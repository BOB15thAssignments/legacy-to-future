"""Generate the recording tap source and export definition.

The tap mirrors the contracted export surface, forwards calls to the renamed
original DLL, and records each boundary crossing. Generated struct layouts use
explicit padding and compile-time size and offset checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import (POINTER_KINDS, SCALAR_KINDS, ArgSpec, Contract,
                    ContractError, FieldSpec, StructSpec, SymbolSpec)

logger = logging.getLogger(__name__)

GENERATOR = "shimforge gen_tap"
CB_SLOTS = 8
MAX_STR_BYTES = 4096

C_SCALAR: dict[str, str] = {
    "void": "void",
    "bool": "unsigned char",        # model says sizeof(bool)==1, not Win32 BOOL
    "i8": "signed char", "u8": "unsigned char",
    "i16": "short", "u16": "unsigned short",
    "i32": "int", "u32": "unsigned int",
    "i64": "long long", "u64": "unsigned long long",
    "f32": "float", "f64": "double",
}

# C keywords plus every identifier the generated thunk bodies rely on. An
# argument named `c` would shadow the tr_call* and silently miscompile.
RESERVED_C = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Static_assert",
    "bool", "true", "false", "near", "far", "this", "new", "delete",
    "interface", "c", "r", "fn", "i",
    # `slot` is the first parameter of every callback dispatcher and
    # `DllMain` is defined by the tap itself; either one reused as an
    # argument or export name is a redefinition, not a shadow.
    "slot", "DllMain",
}

CC_ATTR = {
    "cdecl": "__cdecl", "stdcall": "__stdcall", "fastcall": "__fastcall",
    "thiscall": "__thiscall", "win64": "",
}


# --------------------------------------------------------------------------
# identifiers / small helpers
# --------------------------------------------------------------------------

def _c_ident(name: str) -> str:
    out = []
    for ch in name:
        out.append(ch if (ch.isalnum() and ch.isascii()) or ch == "_" else "_")
    ident = "".join(out) or "_"
    if ident[0].isdigit():
        ident = "_" + ident
    if ident in RESERVED_C or ident.startswith("tf_") or ident.startswith("g_tf"):
        ident += "_a"
    return ident


def _is_plain_ident(name: str) -> bool:
    if not name:
        return False
    if not (name[0].isalpha() and name.isascii()) and name[0] != "_":
        return False
    return all((ch.isalnum() and ch.isascii()) or ch == "_" for ch in name)


def _unique(names: list[str], prefix: str) -> dict[str, str]:
    """Map raw names to unique C identifiers with `prefix`."""
    taken: set[str] = set()
    out: dict[str, str] = {}
    for raw in names:
        base = prefix + _c_ident(raw)
        cand, n = base, 1
        while cand in taken:
            cand = f"{base}_{n}"
            n += 1
        taken.add(cand)
        out[raw] = cand
    return out


def _cstr(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def contract_hash(contract: Contract) -> str:
    """SHA256 over the canonical contract JSON.

    Stamped into both generated files so a tap built from an older contract
    is detectable without re-running the generator.
    """
    return contract.fingerprint()


def _default_real_module(module: str) -> str:
    stem = module[:-4] if module.lower().endswith(".dll") else module
    return f"{stem}_real.dll"


# --------------------------------------------------------------------------
# type mapping
# --------------------------------------------------------------------------

def _cc(contract: Contract, cc: str) -> str:
    """Calling-convention attribute, or "" on x64 where there is only one."""
    if contract.arch == "x64":
        return ""
    return CC_ATTR.get(cc, "__stdcall")


def _cc_space(contract: Contract, cc: str) -> str:
    a = _cc(contract, cc)
    return a + " " if a else ""


def _arg_type(contract: Contract, arg: ArgSpec,
              cb_types: dict[str, str] | None = None) -> str:
    """C type for an argument, honouring direction constness."""
    const = "const " if arg.dir == "in" else ""
    k = arg.kind
    if k == "fnptr":
        if cb_types and arg.callback and arg.callback in cb_types:
            return cb_types[arg.callback]
        return "void *"
    if k == "handle":
        return "void *"
    if k == "str":
        return f"{const}char *"
    if k == "wstr":
        return f"{const}unsigned short *"
    if k == "ptr":
        if arg.struct:
            return f"{const}{_c_ident(arg.struct)} *"
        return f"{const}void *"
    if k == "blob":
        # A by-value aggregate cannot be expressed here; treat it as opaque.
        return f"{const}void *"
    return C_SCALAR[k]


def _ret_type(kind: str) -> str:
    if kind in ("ptr", "handle", "fnptr", "blob"):
        return "void *"
    if kind == "str":
        return "char *"
    if kind == "wstr":
        return "unsigned short *"
    return C_SCALAR[kind]


def _field_type(contract: Contract, f: FieldSpec) -> tuple[str, str]:
    """(type, array-suffix) for a struct member of exactly f.size bytes."""
    if f.kind in POINTER_KINDS and f.size == contract.ptr_size:
        return "void *", ""
    natural = SCALAR_KINDS.get(f.kind)
    if natural is not None and natural == f.size and f.kind != "void":
        return C_SCALAR[f.kind], ""
    # Declared size disagrees with the natural type: keep the bytes, lose
    # the type. Offsets are what the comparison depends on.
    return "unsigned char", f"[{f.size}]"


# --------------------------------------------------------------------------
# export planning
# --------------------------------------------------------------------------

@dataclass
class _Export:
    """One line of the .def, plus how (or whether) it is implemented in C."""

    name: str
    ordinal: int | None
    noname: bool
    forward: str | None = None      # "module.Func" or "module.#42"
    impl: str | None = None         # C function name, None for forwarders

    def def_line(self) -> str:
        parts = [self.name]
        if self.forward:
            parts[0] = f"{self.name}={self.forward}"
        elif self.impl and self.impl != self.name:
            parts[0] = f"{self.name}={self.impl}"
        if self.ordinal is not None:
            parts.append(f"@{self.ordinal}")
        if self.noname:
            parts.append("NONAME")
        return "    " + " ".join(parts)


def _forward_target(forward: str) -> str:
    mod, _, func = forward.rpartition(".")
    if not mod:
        # No module part: the contract only named a function. Not forwardable.
        raise ContractError(f"forward target needs a module: '{forward}'")
    if mod.lower().endswith(".dll"):
        mod = mod[:-4]
    return f"{mod}.{func}"


def _surface_entries(surface: Any) -> dict[int, Any]:
    by_ord = getattr(surface, "by_ordinal", None)
    if isinstance(by_ord, dict) and by_ord:
        return dict(by_ord)
    exports = getattr(surface, "exports", None) or {}
    out: dict[int, Any] = {}
    for entry in exports.values():
        ordinal = getattr(entry, "ordinal", None)
        if ordinal is not None:
            out[int(ordinal)] = entry
    return out


def _plan_exports(contract: Contract, surface: Any,
                  real_module: str) -> tuple[list[_Export], list[SymbolSpec]]:
    """Decide the .def contents after exact surface validation."""
    entries = _surface_entries(surface) if surface is not None else {}
    by_name: dict[str, Any] = {}
    for e in entries.values():
        nm = getattr(e, "name", None)
        if nm:
            by_name[nm] = e

    exports: list[_Export] = []
    thunks: list[SymbolSpec] = []
    covered_ords: set[int] = set()
    covered_names: set[str] = set()

    for name in sorted(contract.symbols):
        sym = contract.symbols[name]
        ordinal, noname = sym.ordinal, sym.noname
        entry = by_name.get(name)
        if entry is not None:
            ent_ord = getattr(entry, "ordinal", None)
            if ordinal is None and ent_ord is not None:
                ordinal = int(ent_ord)
            elif ent_ord is not None and int(ent_ord) != ordinal:
                raise ContractError(
                    f"{name}: contract ordinal {ordinal} disagrees with "
                    f"original surface {ent_ord}")
        if ordinal is not None:
            covered_ords.add(ordinal)
        elif noname:
            # `NONAME` with no ordinal is not a .def the linker will accept,
            # and a nameless export has nothing else to be reached by.
            raise ContractError(
                f"{name}: noname export has no ordinal; the .def would be "
                "rejected by the linker and the export unreachable")
        covered_names.add(name)

        if sym.forward:
            exports.append(_Export(name, ordinal, noname,
                                   _forward_target(sym.forward), None))
            continue

        # Names in a .def are undecorated on both arches; the linker does the
        # x86 stdcall/fastcall mangle search, which also keeps the exported
        # names clean (a bare __declspec(dllexport) would leak `_Name@8`).
        # _c_ident even for plain names: an export called `tf_resolve` or
        # `DllMain` would otherwise redefine the tap's own helper.
        impl = _c_ident(name) if _is_plain_ident(name) \
            else "tf_sym_" + _c_ident(name)
        thunks.append(sym)
        exports.append(_Export(name, ordinal, noname, None, impl))

    # Defense in depth: generate_tap validates the complete contract/surface
    # relation before reaching this planner.  Never restore the old behaviour
    # of silently forwarding uncovered entries: those calls bypassed the
    # recorder yet could still receive an L0 PASS.
    uncovered: list[str] = []
    for ordinal in sorted(entries):
        entry = entries[ordinal]
        nm = getattr(entry, "name", None)
        if nm in covered_names or ordinal in covered_ords:
            continue
        uncovered.append(nm if nm else f"NONAME #{ordinal}")
    if uncovered:
        raise ContractError(
            "original exports absent from contract (untraced forwarding is "
            "forbidden): " + ", ".join(uncovered))
    return exports, thunks


# --------------------------------------------------------------------------
# C emission: structs
# --------------------------------------------------------------------------

def _emit_struct(contract: Contract, st: StructSpec, out: list[str]) -> None:
    name = _c_ident(st.name)
    fields = sorted(st.fields, key=lambda f: f.off)
    pads = {off: size for off, size in st.padding_ranges()}
    idents = _unique([f.name for f in fields], "")
    taken = set(idents.values())

    pad_n = 0

    def _pad_name() -> str:
        # A field literally called `_pad0` must not collide with the padding
        # members this function invents.
        nonlocal pad_n
        while True:
            cand = f"_pad{pad_n}"
            pad_n += 1
            if cand not in taken:
                taken.add(cand)
                return cand

    out.append(f"typedef struct tf_s_{name} {{")
    cursor = 0
    for f in fields:
        while cursor in pads and cursor < f.off:
            size = pads[cursor]
            out.append(f"    unsigned char {_pad_name()}[{size}];")
            cursor += size
        ctype, suffix = _field_type(contract, f)
        out.append(f"    {ctype} {idents[f.name]}{suffix};"
                   f"{'' if not f.volatile else '   /* volatile: masked */'}")
        cursor = f.off + f.size
    while cursor in pads:
        size = pads[cursor]
        out.append(f"    unsigned char {_pad_name()}[{size}];")
        cursor += size
    out.append(f"}} {name};")
    out.append(f'_Static_assert(sizeof({name}) == {st.size},'
               f' "sizeof({st.name}) != {st.size}");')
    for f in fields:
        ident = idents[f.name]
        out.append(f'_Static_assert(offsetof({name}, {ident}) == {f.off},'
                   f' "{st.name}.{f.name} offset != {f.off}");')
        out.append(f'_Static_assert(sizeof((({name} *)0)->{ident}) == {f.size},'
                   f' "{st.name}.{f.name} size != {f.size}");')
    out.append("")


# --------------------------------------------------------------------------
# C emission: extents
# --------------------------------------------------------------------------

def _extent_expr(contract: Contract, owner: str, arg: ArgSpec, phase: str,
                 ident: str, used: set[str], idents: dict[str, str]) -> str:
    """C expression yielding the byte count for a pointer capture.

    `idents` maps contract argument names to the C identifiers actually
    emitted for them; two argument names can sanitise to the same token, so
    re-deriving the count argument's name here would read the wrong local.
    """
    ext = arg.extent
    if ext is not None and ext.is_known:
        if ext.fixed is not None:
            return str(ext.fixed)
        if ext.arg is not None:
            used.add("count")
            cnt = idents.get(ext.arg, _c_ident(ext.arg))
            why = (f"{phase}.{arg.name}: count arg '{ext.arg}' out of range,"
                   " not captured")
            return (f"tf_extent_count({_cstr(owner)}, {_cstr(why)},"
                    f" (long long)({cnt}), {ext.scale})")
        if ext.struct is not None:
            used.add("struct:" + ext.struct)
            sname = _c_ident(ext.struct)
            return f"tf_extent_{sname}((const {sname} *){ident})"
    if arg.struct:
        used.add("struct:" + arg.struct)
        sname = _c_ident(arg.struct)
        cast = "" if arg.kind == "ptr" else f"(const {sname} *)"
        return f"tf_extent_{sname}({cast}{ident})"
    if arg.kind == "str":
        used.add("str")
        return f"tf_extent_str({ident})"
    if arg.kind == "wstr":
        used.add("wstr")
        return f"tf_extent_wstr({ident})"
    return "-1"


def _emit_extent_helpers(contract: Contract, used: set[str],
                         out: list[str]) -> None:
    if "count" in used:
        out.append("/* An element count under attacker/callee control must not")
        out.append(" * turn into an out-of-bounds read inside the recorder. */")
        out.append("static long long tf_extent_count(const char *sym, const char *why,")
        out.append("                                 long long n, long long scale) {")
        out.append("    if (n < 0 || n > 0x7fffffffLL / scale) {")
        out.append("        tr_note(sym, why);")
        out.append("        return -1;")
        out.append("    }")
        out.append("    return n * scale;")
        out.append("}")
        out.append("")
    if "str" in used:
        out.append("static long long tf_extent_str(const char *p) {")
        out.append("    long long i;")
        out.append("    if (!p) return -1;")
        out.append(f"    for (i = 0; i < {MAX_STR_BYTES}; i++)")
        out.append("        if (!p[i]) return i + 1;")
        out.append("    return -1;   /* no terminator in range: refuse to guess */")
        out.append("}")
        out.append("")
    if "wstr" in used:
        out.append("static long long tf_extent_wstr(const unsigned short *p) {")
        out.append("    long long i;")
        out.append("    if (!p) return -1;")
        out.append(f"    for (i = 0; i < {MAX_STR_BYTES // 2}; i++)")
        out.append("        if (!p[i]) return (i + 1) * 2;")
        out.append("    return -1;")
        out.append("}")
        out.append("")
    for key in sorted(k for k in used if k.startswith("struct:")):
        st = contract.structs[key.split(":", 1)[1]]
        name = _c_ident(st.name)
        out.append(f"static long long tf_extent_{name}(const {name} *p) {{")
        out.append("    long long n;")
        out.append("    if (!p) return -1;")
        if st.size_field:
            sf = st.field_by_name(st.size_field)
            if sf is None:
                raise ContractError(
                    f"{st.name}.size_field '{st.size_field}' is not a field")
            # `(long long)p->fld` must read a number. A field whose declared
            # size has no matching scalar type is emitted as unsigned char[N]
            # and would decay to a pointer here: the extent would silently
            # become the struct's address instead of its length.
            ctype, suffix = _field_type(contract, sf)
            if suffix or ctype not in ("unsigned char", "signed char", "short",
                                       "unsigned short", "int", "unsigned int",
                                       "long long", "unsigned long long"):
                raise ContractError(
                    f"{st.name}.{st.size_field}: size_field must be an integer "
                    f"field whose declared size matches its kind (kind "
                    f"'{sf.kind}', size {sf.size} -> C type "
                    f"'{ctype}{suffix}')")
            fld = _c_ident(st.size_field)
            out.append(f"    n = (long long)p->{fld};")
            out.append(f"    if (n < 0 || n > (long long)sizeof({name})) {{")
            out.append(f'        tr_note({_cstr(st.name)}, "size_field '
                       f'{st.size_field} out of [0, {st.size}]; clamped");')
            out.append(f"        return n < 0 ? 0 : (long long)sizeof({name});")
            out.append("    }")
            out.append("    return n;")
        else:
            out.append(f"    n = (long long)sizeof({name});")
            out.append("    return n;")
        out.append("}")
        out.append("")


# --------------------------------------------------------------------------
# C emission: value capture
# --------------------------------------------------------------------------

def _captures_no_bytes(arg: ArgSpec) -> bool:
    """True when `_extent_expr` will emit a literal -1 for this argument."""
    if arg.kind in ("str", "wstr") or arg.struct:
        return False
    return arg.extent is None or not arg.extent.is_known


def _emit_capture(contract: Contract, owner: str, arg: ArgSpec, phase: str,
                  ident: str, used: set[str], indent: str,
                  out: list[str], idents: dict[str, str]) -> None:
    fn_suffix = "in" if phase == "in" else "out"
    label = _cstr(arg.name)
    k = arg.kind
    if k in ("f32", "f64"):
        out.append(f"{indent}tr_{fn_suffix}_f64(c, {label}, (double){ident});")
        return
    if k in ("handle", "fnptr"):
        out.append(f"{indent}tr_{fn_suffix}_i64(c, {label},"
                   f" (long long)(intptr_t){ident}, {_cstr(k)});")
        return
    if k in ("ptr", "blob", "str", "wstr"):
        if k == "str" and phase == "in":
            out.append(f"{indent}tr_in_str(c, {label}, {ident});")
            return
        if k == "wstr" and phase == "in":
            out.append(f"{indent}tr_in_wstr(c, {label}, {ident});")
            return
        ext = _extent_expr(contract, owner, arg, phase, ident, used, idents)
        out.append(f"{indent}tr_{fn_suffix}_ptr(c, {label}, {ident}, {ext});")
        return
    out.append(f"{indent}tr_{fn_suffix}_i64(c, {label},"
               f" (long long){ident}, {_cstr(k)});")


def _emit_ret(kind: str, out: list[str], indent: str) -> None:
    if kind == "void":
        out.append(f"{indent}tr_ret_void(c);")
    elif kind in ("f32", "f64"):
        out.append(f"{indent}tr_ret_f64(c, (double)r);")
    elif kind in POINTER_KINDS or kind == "blob":
        out.append(f"{indent}tr_ret_i64(c, (long long)(intptr_t)r, {_cstr(kind)});")
    else:
        out.append(f"{indent}tr_ret_i64(c, (long long)r, {_cstr(kind)});")


# --------------------------------------------------------------------------
# C emission: callbacks
# --------------------------------------------------------------------------

def _emit_callbacks(contract: Contract, cb_types: dict[str, str],
                    used: set[str], out: list[str]) -> None:
    for name in sorted(contract.callbacks):
        spec = contract.callbacks[name]
        ident = _c_ident(name)
        tname = cb_types[name]
        cc = _cc_space(contract, spec.cc)
        ret = _ret_type(spec.ret)
        idents = _unique([a.name for a in spec.args], "")
        params = ", ".join(
            f"{_arg_type(contract, a)} {idents[a.name]}" for a in spec.args
        ) or "void"
        call_args = ", ".join(idents[a.name] for a in spec.args)

        out.append(f"static {ret} {ident}_dispatch(int slot"
                   f"{', ' + params if spec.args else ''}) {{")
        out.append(f"    {tname} fn = g_tf_cb_{ident}[slot];")
        out.append(f'    tr_call *c = tr_enabled() ? tr_enter({_cstr(name)}, 1) : NULL;')
        if spec.ret != "void":
            out.append(f"    {ret} r;")
        ins = [a for a in spec.args if a.is_in]
        outs = [a for a in spec.args if a.is_out]
        if ins:
            out.append("    if (c) {")
            for a in ins:
                _emit_capture(contract, name, a, "in", idents[a.name], used,
                              "        ", out, idents)
            out.append("    }")
        assign = "" if spec.ret == "void" else "r = "
        out.append(f"    {assign}fn({call_args});")
        out.append("    if (c) {")
        # The DLL is mid-call and may inspect its last error after the
        # callback returns; recording must not be observable.
        out.append("        DWORD tf_le = GetLastError();")
        for a in outs:
            _emit_capture(contract, name, a, "out", idents[a.name], used,
                          "        ", out, idents)
        _emit_ret(spec.ret, out, "        ")
        out.append("        tr_leave(c);")
        out.append("        SetLastError(tf_le);")
        out.append("    }")
        if spec.ret != "void":
            out.append("    return r;")
        out.append("}")
        for i in range(CB_SLOTS):
            tail = (", " + call_args) if spec.args else ""
            body = f"{ident}_dispatch({i}{tail})"
            stmt = f"return {body};" if spec.ret != "void" else f"{body};"
            out.append(f"static {ret} {cc}tf_cb_{ident}_{i}({params}) "
                       f"{{ {stmt} }}")
        thunks = ", ".join(f"tf_cb_{ident}_{i}" for i in range(CB_SLOTS))
        out.append(f"static const {tname} g_tf_cbt_{ident}[TF_CB_SLOTS] = {{ {thunks} }};")
        out.append("")
        out.append("/* One slot per distinct application callback. Re-registering the")
        out.append(" * same function reuses its slot so the traced identity is stable. */")
        out.append(f"static {tname} tf_cb_{ident}_wrap({tname} fn) {{")
        out.append("    int i;")
        out.append("    if (!fn) return fn;")
        out.append("    for (i = 0; i < TF_CB_SLOTS; i++)")
        out.append(f"        if (g_tf_cbt_{ident}[i] == fn) return fn;")
        out.append("    EnterCriticalSection(&g_tf_lock);")
        out.append("    for (i = 0; i < TF_CB_SLOTS; i++) {")
        out.append(f"        if (g_tf_cb_{ident}[i] == fn) break;")
        out.append(f"        if (g_tf_cb_{ident}[i] == NULL) {{")
        out.append(f"            g_tf_cb_{ident}[i] = fn;")
        out.append("            break;")
        out.append("        }")
        out.append("    }")
        out.append("    LeaveCriticalSection(&g_tf_lock);")
        out.append("    if (i == TF_CB_SLOTS) {")
        out.append(f'        tr_note({_cstr(name)}, "callback slots exhausted;'
                   ' this registration is untraced");')
        out.append("        return fn;")
        out.append("    }")
        out.append(f"    return g_tf_cbt_{ident}[i];")
        out.append("}")
        out.append("")


# --------------------------------------------------------------------------
# C emission: thunks
# --------------------------------------------------------------------------

def _emit_thunk(contract: Contract, sym: SymbolSpec, idx_name: str,
                impl: str, cb_types: dict[str, str], used: set[str],
                out: list[str]) -> None:
    cc = _cc_space(contract, sym.cc)
    ret = _ret_type(sym.ret)
    idents = _unique([a.name for a in sym.args], "")
    params = ", ".join(
        f"{_arg_type(contract, a, cb_types)} {idents[a.name]}"
        for a in sym.args) or "void"

    wrapped = [a for a in sym.args
               if a.kind == "fnptr" and a.callback and a.callback in cb_types]
    call_idents = dict(idents)
    for a in wrapped:
        call_idents[a.name] = "tf_w_" + idents[a.name]
    call_args = ", ".join(call_idents[a.name] for a in sym.args)

    # Only when the C name IS the exported name. Otherwise dllexport would
    # publish the internal `tf_sym_...` alias as an extra export, adding
    # ordinals the original never had.
    export = ("__declspec(dllexport) "
              if contract.arch == "x64" and impl == sym.name else "")
    note = "" if contract.arch != "x64" else f"  /* cc: {sym.cc} */"
    out.append(f"{export}{ret} {cc}{impl}({params}){note}")
    out.append("{")
    out.append(f"    PFN_{impl} fn = (PFN_{impl})tf_resolve({idx_name},"
               f" {_cstr(sym.name)});")
    out.append(f"    tr_call *c = tf_begin({_cstr(sym.name)});")
    for a in wrapped:
        out.append(f"    {cb_types[a.callback]} tf_w_{idents[a.name]}"
                   f" = {idents[a.name]};")
    if sym.ret != "void":
        out.append(f"    {ret} r;")

    ins = [a for a in sym.args if a.is_in]
    outs = [a for a in sym.args if a.is_out]
    if ins or wrapped:
        out.append("    if (c) {")
        for a in ins:
            _emit_capture(contract, sym.name, a, "in", idents[a.name], used,
                          "        ", out, idents)
        for a in wrapped:
            out.append(f"        tf_w_{idents[a.name]} ="
                       f" tf_cb_{_c_ident(a.callback)}_wrap({idents[a.name]});")
        out.append("    }")

    assign = "" if sym.ret == "void" else "r = "
    out.append(f"    {assign}fn({call_args});")
    out.append("    if (c) {")
    # GetLastError first: every tr_* call below is free to clobber it, and
    # SetLastError on the way out keeps the tap invisible to the caller.
    out.append("        DWORD tf_le = GetLastError();")
    if sym.lasterr:
        out.append("        tr_lasterr(c, tf_le);")
    for a in outs:
        _emit_capture(contract, sym.name, a, "out", idents[a.name], used,
                      "        ", out, idents)
    _emit_ret(sym.ret, out, "        ")
    out.append("        tr_leave(c);")
    out.append("        SetLastError(tf_le);")
    out.append("    }")
    if sym.ret != "void":
        out.append("    return r;")
    out.append("}")
    out.append("")


# --------------------------------------------------------------------------
# C emission: whole file
# --------------------------------------------------------------------------

def _banner(contract: Contract, real_module: str, chash: str,
            thunks: int, forwards: int, extra: str) -> list[str]:
    return [
        f"/* GENERATED by {GENERATOR} -- do not edit by hand.",
        f" * contract module : {contract.module} ({contract.arch})",
        f" * real module     : {real_module}",
        f" * contract sha256 : {chash}",
        f" * {thunks} traced thunk(s), {forwards} forwarder(s),"
        f" {len(contract.structs)} struct(s), {len(contract.callbacks)} callback(s)",
        f" * {extra}",
        " */",
    ]


def _emit_c(contract: Contract, real_module: str, exports: list[_Export],
            thunk_syms: list[SymbolSpec], chash: str) -> str:
    # Only callbacks some traced thunk actually hands to the real module get
    # a trampoline table: an unreferenced CallbackSpec would emit a wrapper
    # nothing calls, which is a -Wunused-function on an otherwise clean build.
    wanted_cbs = sorted({a.callback for s in thunk_syms for a in s.args
                         if a.kind == "fnptr" and a.callback
                         and a.callback in contract.callbacks})
    cb_types = {n: "PFN_CB_" + _c_ident(n) for n in wanted_cbs}
    used: set[str] = set()

    idx_names = _unique([s.name for s in thunk_syms], "TF_IDX_")
    impls = {e.name: e.impl for e in exports if e.impl and not e.forward}

    # A contract of pure forwarders needs no runtime at all; emitting one
    # would only produce unused-function warnings.
    runtime = bool(thunk_syms)
    callbacks = wanted_cbs if runtime else []

    body: list[str] = []
    for s in thunk_syms:
        _emit_thunk(contract, s, idx_names[s.name], impls[s.name], cb_types,
                    used, body)

    cb_body: list[str] = []
    if callbacks:
        _emit_callbacks(contract, cb_types, used, cb_body)

    head: list[str] = []
    head += _banner(contract, real_module, chash, len(thunk_syms),
                    len(exports) - len(thunk_syms),
                    "regenerate with gen_tap.generate_tap()")
    head.append("")
    head.append("#ifndef _WIN32_WINNT")
    head.append("#define _WIN32_WINNT 0x0601   /* INIT_ONCE */")
    head.append("#endif")
    head.append("#define WIN32_LEAN_AND_MEAN")
    head.append("#include <windows.h>")
    head.append("#include <stddef.h>")
    head.append("#include <stdint.h>")
    if runtime:
        head.append("#include <stdlib.h>")
        head.append('#include "tr_record.h"')
    head.append("")
    head.append(f'#define TF_MODULE {_cstr(contract.module)}')
    head.append(f'#define TF_ARCH {_cstr(contract.arch)}')
    head.append(f'#define TF_CONTRACT_HASH {_cstr(chash)}')
    if runtime:
        head.append("#ifndef TF_REAL_MODULE")
        head.append(f'#define TF_REAL_MODULE {_cstr(real_module)}')
        head.append(f'#define TF_REAL_MODULE_W L{_cstr(real_module)}')
        head.append("#endif")
        head.append("#ifndef TF_DEFAULT_TRACE")
        head.append(f'#define TF_DEFAULT_TRACE {_cstr("tap_trace.jsonl")}')
        head.append("#endif")
        head.append("#define TF_E_UNRESOLVED 0xE0534601UL")
    if callbacks:
        head.append(f"#define TF_CB_SLOTS {CB_SLOTS}")
    head.append("")

    structs: list[str] = []
    if contract.structs:
        structs.append("/* Layouts are packed with explicit padding so the C view matches the")
        structs.append(" * contract byte for byte; the asserts below turn any drift into a")
        structs.append(" * build failure instead of a wrong comparison. */")
        structs.append("#pragma pack(push, 1)")
        for name in sorted(contract.structs):
            _emit_struct(contract, contract.structs[name], structs)
        structs.append("#pragma pack(pop)")
        structs.append("")

    types: list[str] = []
    for name in callbacks:
        spec = contract.callbacks[name]
        cc = _cc_space(contract, spec.cc)
        args = ", ".join(_arg_type(contract, a) for a in spec.args) or "void"
        types.append(f"typedef {_ret_type(spec.ret)} ({cc}*{cb_types[name]})({args});")
    for s in thunk_syms:
        cc = _cc_space(contract, s.cc)
        args = ", ".join(_arg_type(contract, a, cb_types) for a in s.args) or "void"
        types.append(f"typedef {_ret_type(s.ret)} ({cc}*PFN_{impls[s.name]})({args});")
    if types:
        types.append("")

    state: list[str] = []
    if runtime:
        state.append("static HINSTANCE g_tf_self;")
        state.append("typedef struct { const char *diag; const char *by_name;"
                     " unsigned short ord; } tf_binding;")
        state.append("enum {")
        for s in thunk_syms:
            state.append(f"    {idx_names[s.name]},")
        state.append("    TF_IDX__COUNT")
        state.append("};")
        state.append("static const tf_binding g_tf_bind[TF_IDX__COUNT] = {")
        for s in thunk_syms:
            # A NONAME export is not reachable by name in the real module.
            by_name = "NULL" if s.noname else _cstr(s.name)
            state.append(f"    {{ {_cstr(s.name)}, {by_name},"
                         f" {s.ordinal or 0} }},")
        state.append("};")
        state.append("static void *g_tf_fns[TF_IDX__COUNT];")
        state.append("static HMODULE g_tf_real;")
        state.append("static INIT_ONCE g_tf_once = INIT_ONCE_STATIC_INIT;")
    if callbacks:
        state.append("static CRITICAL_SECTION g_tf_lock;")
        for name in callbacks:
            state.append(f"static {cb_types[name]} "
                         f"g_tf_cb_{_c_ident(name)}[TF_CB_SLOTS];")
    state.append("")

    init: list[str] = []
    if not runtime:
        # Pure forwarder contract: the .def carries everything. Keep the
        # struct asserts (they still check the contract) and nothing else.
        tag = ["typedef int tf_forwarder_only_tap;   /* no thunks to emit */",
               ""]
        return "\n".join(head + structs + tag)
    init.append("/* The tap usually sits under the original's file name, so a bare")
    init.append(" * LoadLibrary would find the tap again. Load the renamed original")
    init.append(" * out of the tap's own directory first. */")
    init.append("static HMODULE tf_load_real(void)")
    init.append("{")
    init.append("    WCHAR path[MAX_PATH];")
    init.append("    DWORD n, i, cut = 0, leaf;")
    init.append("    HMODULE h;")
    init.append("    n = GetModuleFileNameW(g_tf_self, path, MAX_PATH);")
    init.append("    if (n > 0 && n < MAX_PATH) {")
    init.append("        for (i = 0; i < n; i++)")
    init.append("            if (path[i] == L'\\\\' || path[i] == L'/') cut = i + 1;")
    init.append("        leaf = (DWORD)lstrlenW(TF_REAL_MODULE_W) + 1;")
    init.append("        if (cut > 0 && leaf <= MAX_PATH - cut) {")
    init.append("            lstrcpynW(path + cut, TF_REAL_MODULE_W,"
                " (int)(MAX_PATH - cut));")
    init.append("            h = LoadLibraryExW(path, NULL,")
    init.append("                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |")
    init.append("                LOAD_LIBRARY_SEARCH_SYSTEM32);")
    init.append("            if (h) return h;")
    init.append("        }")
    init.append("    }")
    init.append("    /* Never fall back to a bare DLL name: that would re-enable the")
    init.append("     * ambient process search path and could bind an unrelated file. */")
    init.append("    return NULL;")
    init.append("}")
    init.append("")
    init.append("static void tf_trace_shutdown(void)")
    init.append("{")
    init.append("    tr_shutdown();")
    init.append("}")
    init.append("")
    init.append("static BOOL CALLBACK tf_init_once(PINIT_ONCE once, PVOID param,"
                " PVOID *ctx)")
    init.append("{")
    init.append("    int i, exit_hook;")
    init.append("    (void)once; (void)param; (void)ctx;")
    if callbacks:
        init.append("    InitializeCriticalSection(&g_tf_lock);")
    init.append("    g_tf_real = tf_load_real();")
    init.append("    if (g_tf_real) {")
    init.append("        for (i = 0; i < TF_IDX__COUNT; i++) {")
    init.append("            const tf_binding *b = &g_tf_bind[i];")
    init.append("            g_tf_fns[i] = b->by_name")
    init.append("                ? (void *)GetProcAddress(g_tf_real, b->by_name)")
    init.append("                : (void *)GetProcAddress(g_tf_real,"
                " (LPCSTR)(ULONG_PTR)b->ord);")
    init.append("        }")
    init.append("    }")
    init.append("    /* tr_record is the sole TAP_* environment parser. Keeping it in")
    init.append("     * one wide-character, length-checked implementation prevents the")
    init.append("     * generated tap from treating a required-size return as content. */")
    init.append("    exit_hook = atexit(tf_trace_shutdown);")
    init.append("    tr_init(TF_DEFAULT_TRACE, TF_MODULE, TF_ARCH, NULL,")
    init.append("               TF_CONTRACT_HASH);")
    init.append("    if (tr_enabled()) {")
    init.append("        if (exit_hook != 0)")
    init.append('            tr_note(TF_MODULE, "failed to register normal-exit trace footer");')
    init.append("        if (!g_tf_real)")
    init.append('            tr_note(TF_MODULE, "failed to load " TF_REAL_MODULE);')
    # Declaring the blind spots once beats a note per call. The test is the
    # extent the thunk actually passes, not ArgSpec.records_bytes: that
    # property is False for every non-`ptr` kind, so a `blob` with a fixed
    # extent would be reported as a blind spot while its bytes are captured.
    for s in thunk_syms:
        for a in s.args:
            if a.kind in ("ptr", "blob") and _captures_no_bytes(a):
                init.append(f'        tr_note({_cstr(s.name)},'
                            f' "unknown-extent arg {a.name}");')
    init.append("    }")
    init.append("    return TRUE;")
    init.append("}")
    init.append("")
    init.append("static void *tf_resolve(int idx, const char *name)")
    init.append("{")
    init.append("    void *fn;")
    init.append("    InitOnceExecuteOnce(&g_tf_once, tf_init_once, NULL, NULL);")
    init.append("    fn = g_tf_fns[idx];")
    init.append("    if (!fn) {")
    init.append('        tr_note(name, "unresolved in " TF_REAL_MODULE);')
    init.append("        /* Returning would call through NULL; a named exception")
    init.append("         * is far easier to read in a crash dump. */")
    init.append("        RaiseException(TF_E_UNRESOLVED, EXCEPTION_NONCONTINUABLE,"
                " 0, NULL);")
    init.append("    }")
    init.append("    return fn;")
    init.append("}")
    init.append("")
    init.append("static tr_call *tf_begin(const char *sym)")
    init.append("{")
    init.append("    return tr_enabled() ? tr_enter(sym, 0) : NULL;")
    init.append("}")
    init.append("")

    helpers: list[str] = []
    _emit_extent_helpers(contract, used, helpers)

    tail: list[str] = []
    tail.append("BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)")
    tail.append("{")
    tail.append("    if (reason == DLL_PROCESS_ATTACH) {")
    tail.append("        /* Only record the handle here. Loading the real module")
    tail.append("         * under the loader lock is how taps deadlock. */")
    tail.append("        g_tf_self = inst;")
    tail.append("        DisableThreadLibraryCalls(inst);")
    tail.append("    } else if (reason == DLL_PROCESS_DETACH && reserved == NULL) {")
    tail.append("        /* reserved != NULL means the process is dying and calling")
    tail.append("         * out is unsafe; the recorder flushes per line anyway. */")
    tail.append("        tr_shutdown();")
    tail.append("    }")
    tail.append("    return TRUE;")
    tail.append("}")
    tail.append("")

    return "\n".join(head + structs + types + state + init + helpers
                     + cb_body + body + tail)


def _emit_def(contract: Contract, real_module: str, exports: list[_Export],
              chash: str) -> str:
    lines = [
        f"; GENERATED by {GENERATOR} -- do not edit by hand.",
        f"; contract module : {contract.module} ({contract.arch})",
        f"; real module     : {real_module}",
        f"; contract sha256 : {chash}",
        f"LIBRARY {contract.module}",
        "EXPORTS",
    ]
    with_ord = [e for e in exports if e.ordinal is not None]
    without = [e for e in exports if e.ordinal is None]
    for e in sorted(with_ord, key=lambda x: x.ordinal or 0):
        lines.append(e.def_line())
    for e in sorted(without, key=lambda x: x.name):
        lines.append(e.def_line())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def generate_tap(contract: Contract, out_dir: str | Path, *,
                 surface: Any = None,
                 real_module: str | None = None) -> dict[str, str]:
    """Write `tap.c` and `tap.def` for `contract` into `out_dir`.

    `surface` is the parsed `pe_surface.Surface` of the original module.  It is
    mandatory: generating from the contract alone cannot prove that a named,
    NONAME, data, or forwarded export was omitted.  Every callable export must
    be represented exactly and receive a recording thunk before any output is
    written.
    """
    problems = contract.validate()
    if problems:
        raise ContractError(
            "cannot generate a tap from an invalid contract:\n  "
            + "\n  ".join(problems))
    if surface is None:
        raise ContractError(
            "cannot generate an approval tap without the original PE surface; "
            "parse the original DLL with pe_surface.read_exports() and pass "
            "surface=...")
    try:
        from .pe_surface import compare_contract_surface
        surface_problems = compare_contract_surface(contract, surface)
    except Exception as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError(
            "cannot validate the contract against the original PE surface: "
            f"{type(exc).__name__}: {exc}") from exc
    if surface_problems:
        raise ContractError(
            "contract does not exactly and traceably cover the original PE "
            "surface:\n  " + "\n  ".join(surface_problems))

    real = real_module or contract.real_module or \
        _default_real_module(contract.module)
    if (not real or real in (".", "..") or
            any(ch in real for ch in ("/", "\\", ":", "\0")) or
            any(ord(ch) < 0x20 for ch in real)):
        raise ContractError(
            f"real module '{real}' must be a plain sibling file name")
    if real.lower() == contract.module.lower():
        raise ContractError(
            f"real module '{real}' equals the tap's own name; the tap would "
            "load itself")

    chash = contract_hash(contract)
    exports, thunk_syms = _plan_exports(contract, surface, real)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    c_path = out / "tap.c"
    def_path = out / "tap.def"
    c_path.write_text(_emit_c(contract, real, exports, thunk_syms, chash),
                      encoding="utf-8", newline="\n")
    def_path.write_text(_emit_def(contract, real, exports, chash),
                        encoding="utf-8", newline="\n")
    logger.info("generated tap for %s: %d thunks, %d exports (%s)",
                contract.module, len(thunk_syms), len(exports), chash[:12])
    return {"tap.c": str(c_path), "tap.def": str(def_path)}
