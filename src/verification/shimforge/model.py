"""Contract types, JSON decoding, and validation."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCALAR_KINDS = {
    "void": 0, "bool": 1,
    "i8": 1, "u8": 1, "i16": 2, "u16": 2,
    "i32": 4, "u32": 4, "i64": 8, "u64": 8,
    "f32": 4, "f64": 8,
}
POINTER_KINDS = {"ptr", "str", "wstr", "handle", "fnptr"}
ALL_KINDS = set(SCALAR_KINDS) | POINTER_KINDS | {"blob"}

CALLING_CONVENTIONS = {"cdecl", "stdcall", "fastcall", "thiscall", "win64"}


class ContractError(ValueError):
    """Raised when a contract is internally inconsistent."""


_MISSING = object()


def _schema_object(value: Any, path: str, *, allowed: set[str],
                   required: set[str] = frozenset()) -> dict[str, Any]:
    """Return an exact JSON object after checking its key schema.

    Contract input is approval input, not a convenience API.  In particular,
    accepting a misspelled key and silently applying a default could make the
    recorder observe less than the author intended.  Keep this deliberately
    stricter than ordinary dataclass decoding.
    """
    if type(value) is not dict:
        raise ContractError(f"{path} must be an object, got "
                            f"{type(value).__name__}")
    for key in value:
        if type(key) is not str:
            raise ContractError(
                f"{path} has a non-string key of type {type(key).__name__}")
    unknown = set(value) - allowed
    if unknown:
        raise ContractError(
            f"{path} has unsupported field(s): {', '.join(sorted(unknown))}")
    missing = required - set(value)
    if missing:
        raise ContractError(
            f"{path} is missing required field(s): "
            f"{', '.join(sorted(missing))}")
    return value


def _schema_value(obj: dict[str, Any], key: str, expected: type,
                  path: str, *, default: Any = _MISSING) -> Any:
    """Read one field without Python's bool/int or other coercions."""
    if key not in obj:
        if default is _MISSING:
            raise ContractError(f"{path}.{key} is required")
        return default
    value = obj[key]
    if type(value) is not expected:
        names = {str: "string", int: "integer", bool: "boolean",
                 list: "array", dict: "object"}
        raise ContractError(
            f"{path}.{key} must be a {names.get(expected, expected.__name__)}, "
            f"got {type(value).__name__}")
    return value


def _schema_named_objects(value: Any, path: str) -> dict[str, Any]:
    obj = _schema_object(value, path, allowed=set(value) if type(value) is dict
                         else set())
    for name in obj:
        if not name:
            raise ContractError(f"{path} contains an empty name")
        if type(obj[name]) is not dict:
            raise ContractError(
                f"{path}.{name} must be an object, got "
                f"{type(obj[name]).__name__}")
    return obj


def _json_object_no_duplicates(
        pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ContractError(f"duplicate JSON object key {key!r}")
        obj[key] = value
    return obj


def _reject_json_constant(token: str) -> Any:
    # Python's JSON decoder otherwise accepts these non-JSON spellings.
    raise ContractError(f"non-finite JSON number {token!r} is not allowed")


@dataclass
class Extent:
    """How many bytes a pointer argument addresses.

    Exactly one resolution strategy must be set. `unknown` is a first-class
    drafting value: it prevents a guessed read, while Contract.validate()
    prevents that blind spot from producing an approval result.
    """

    fixed: int | None = None
    arg: str | None = None          # another argument holds the count
    scale: int = 1                  # bytes = arg_value * scale
    struct: str | None = None       # sizeof(struct), or its size_field
    unknown: bool = False

    def __post_init__(self) -> None:
        set_ = [self.fixed is not None, self.arg is not None,
                self.struct is not None, self.unknown]
        if sum(set_) != 1:
            raise ContractError(
                f"Extent needs exactly one strategy, got {self!r}")
        if self.fixed is not None and self.fixed < 0:
            raise ContractError(f"negative fixed extent: {self.fixed}")
        if self.scale < 1:
            raise ContractError(f"scale must be >= 1: {self.scale}")

    @property
    def is_known(self) -> bool:
        return not self.unknown

    def to_json(self) -> dict[str, Any]:
        if self.fixed is not None:
            return {"fixed": self.fixed}
        if self.arg is not None:
            d: dict[str, Any] = {"arg": self.arg}
            if self.scale != 1:
                d["scale"] = self.scale
            return d
        if self.struct is not None:
            return {"struct": self.struct}
        return {"unknown": True}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Extent":
        d = _schema_object(d, "extent",
                           allowed={"fixed", "arg", "scale", "struct",
                                    "unknown"})
        strategies = [k for k in ("fixed", "arg", "struct", "unknown")
                      if k in d]
        if len(strategies) != 1:
            raise ContractError(
                "extent must contain exactly one of fixed, arg, struct, "
                f"unknown; got {strategies!r}")
        if "scale" in d and "arg" not in d:
            raise ContractError("extent.scale is only valid with extent.arg")
        fixed = (_schema_value(d, "fixed", int, "extent")
                 if "fixed" in d else None)
        arg = (_schema_value(d, "arg", str, "extent")
               if "arg" in d else None)
        struct = (_schema_value(d, "struct", str, "extent")
                  if "struct" in d else None)
        unknown = (_schema_value(d, "unknown", bool, "extent")
                   if "unknown" in d else False)
        if "unknown" in d and not unknown:
            raise ContractError("extent.unknown, when present, must be true")
        scale = _schema_value(d, "scale", int, "extent", default=1)
        return cls(fixed=fixed, arg=arg, scale=scale, struct=struct,
                   unknown=unknown)


@dataclass
class FieldSpec:
    name: str
    off: int
    size: int
    kind: str = "blob"
    volatile: bool = False          # never compared (timestamps, cookies)

    def to_json(self) -> dict[str, Any]:
        d = {"name": self.name, "off": self.off, "size": self.size,
             "kind": self.kind}
        if self.volatile:
            d["volatile"] = True
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "FieldSpec":
        d = _schema_object(
            d, "field", allowed={"name", "off", "size", "kind", "volatile"},
            required={"name", "off", "size"})
        return cls(
            name=_schema_value(d, "name", str, "field"),
            off=_schema_value(d, "off", int, "field"),
            size=_schema_value(d, "size", int, "field"),
            kind=_schema_value(d, "kind", str, "field", default="blob"),
            volatile=_schema_value(
                d, "volatile", bool, "field", default=False))


@dataclass
class StructSpec:
    """A struct layout, ideally harvested from PDB rather than hand written."""

    name: str
    size: int
    fields: list[FieldSpec] = field(default_factory=list)
    size_field: str | None = None   # runtime extent comes from this field

    def field_by_name(self, name: str) -> FieldSpec | None:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def padding_ranges(self) -> list[tuple[int, int]]:
        """Byte ranges not covered by any declared field.

        Strict comparison keeps these bytes visible. They may contain noise,
        but masking them would also hide a real field omitted from a mistaken
        contract. Callers may use this inventory for diagnostics only.
        """
        covered = bytearray(self.size)
        for f in self.fields:
            end = min(f.off + f.size, self.size)
            for i in range(max(f.off, 0), end):
                covered[i] = 1
        return _runs_of_zero(covered)

    def volatile_ranges(self) -> list[tuple[int, int]]:
        out = []
        for f in self.fields:
            if f.volatile:
                out.append((f.off, f.size))
        return out

    def masked_ranges(self) -> list[tuple[int, int]]:
        return _merge_ranges(self.padding_ranges() + self.volatile_ranges())

    def pointer_fields(self) -> list[FieldSpec]:
        """Pointer fields whose identity is comparable, in offset order.

        `volatile` wins over identity tracking: the field author declared
        "do not look at this", and honouring that is not negotiable just
        because the field happens to hold an address.
        """
        return sorted((f for f in self.fields
                       if f.kind == "ptr" and not f.volatile),
                      key=lambda f: f.off)

    def pointer_ranges(self) -> list[tuple[int, int]]:
        """Byte ranges covered by `pointer_fields()`."""
        return [(f.off, f.size) for f in self.pointer_fields()]

    def noncomparable_ranges(self) -> list[tuple[int, int]]:
        """Bytes replaced by an equally strict semantic representation.

        Only embedded pointer bytes qualify: their process-local address is
        replaced by a compared identity token. Padding stays in the raw byte
        comparison. It can be noisy, but ignoring it could hide a contract
        field that was accidentally omitted; fail-closed verification accepts
        that false-negative risk. Volatile fields are rejected by validation.
        """
        return self.pointer_ranges()

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.size <= 0:
            problems.append(f"{self.name}: sizeof must be > 0, got {self.size}")
        seen: dict[int, str] = {}
        seen_names: set[str] = set()
        for f in self.fields:
            if f.name in seen_names:
                problems.append(f"{self.name}: duplicate field '{f.name}'")
            seen_names.add(f.name)
            if f.kind not in ALL_KINDS:
                problems.append(
                    f"{self.name}.{f.name}: unknown kind '{f.kind}'")
            if f.off < 0:
                problems.append(
                    f"{self.name}.{f.name}: negative offset {f.off}")
            if f.size <= 0:
                problems.append(
                    f"{self.name}.{f.name}: size must be > 0, got {f.size}")
            if f.off + f.size > self.size:
                problems.append(
                    f"{self.name}.{f.name} extends past sizeof "
                    f"({f.off}+{f.size} > {self.size})")
            for i in range(f.off, f.off + f.size):
                if i in seen and seen[i] != f.name:
                    problems.append(
                        f"{self.name}: {f.name} overlaps {seen[i]} at byte {i}")
                    break
                seen[i] = f.name
        if self.size_field and not self.field_by_name(self.size_field):
            problems.append(
                f"{self.name}.size_field '{self.size_field}' is not a field")
        return problems

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"size": self.size,
                             "fields": [f.to_json() for f in self.fields]}
        if self.size_field:
            d["size_field"] = self.size_field
        return d

    @classmethod
    def from_json(cls, name: str, d: dict[str, Any]) -> "StructSpec":
        path = f"structs.{name}"
        d = _schema_object(
            d, path, allowed={"size", "fields", "size_field"},
            required={"size"})
        raw_fields = _schema_value(d, "fields", list, path, default=[])
        size_field = (_schema_value(d, "size_field", str, path)
                      if "size_field" in d else None)
        return cls(
            name=name, size=_schema_value(d, "size", int, path),
            fields=[FieldSpec.from_json(x) for x in raw_fields],
            size_field=size_field)


@dataclass
class ArgSpec:
    name: str
    kind: str
    dir: str = "in"                 # in | out | inout
    extent: Extent | None = None
    struct: str | None = None       # struct this pointer addresses
    symbolize: str | None = None    # symbol class: handle, ptr, ...
    creates: str | None = None      # out arg mints a new symbolic object
    releases: str | None = None     # in arg destroys a symbolic object
    callback: str | None = None     # CallbackSpec name for fnptr args

    def __post_init__(self) -> None:
        if self.kind not in ALL_KINDS:
            raise ContractError(f"unknown kind '{self.kind}' for arg {self.name}")
        if self.dir not in ("in", "out", "inout"):
            raise ContractError(f"bad dir '{self.dir}' for arg {self.name}")
        if self.kind in ("ptr", "blob") and self.extent is None \
                and self.struct is None:
            # Preserve the incomplete draft explicitly; Contract.validate()
            # rejects it before generation or approval.
            self.extent = Extent(unknown=True)

    @property
    def records_bytes(self) -> bool:
        if self.kind in ("str", "wstr"):
            return True
        if self.kind not in ("ptr", "blob"):
            return False
        if self.struct is not None:
            return True
        return self.extent is not None and self.extent.is_known

    @property
    def is_out(self) -> bool:
        return self.dir in ("out", "inout")

    @property
    def is_in(self) -> bool:
        return self.dir in ("in", "inout")

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "kind": self.kind,
                             "dir": self.dir}
        if self.extent is not None:
            d["extent"] = self.extent.to_json()
        for k in ("struct", "symbolize", "creates", "releases", "callback"):
            v = getattr(self, k)
            if v:
                d[k] = v
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "ArgSpec":
        d = _schema_object(
            d, "argument",
            allowed={"name", "kind", "dir", "extent", "struct",
                     "symbolize", "creates", "releases", "callback"},
            required={"name", "kind"})
        ext = (Extent.from_json(_schema_value(d, "extent", dict, "argument"))
               if "extent" in d else None)

        def optional_string(key: str) -> str | None:
            return (_schema_value(d, key, str, "argument")
                    if key in d else None)

        return cls(
            name=_schema_value(d, "name", str, "argument"),
            kind=_schema_value(d, "kind", str, "argument"),
            dir=_schema_value(d, "dir", str, "argument", default="in"),
            extent=ext, struct=optional_string("struct"),
            symbolize=optional_string("symbolize"),
            creates=optional_string("creates"),
            releases=optional_string("releases"),
            callback=optional_string("callback"))


@dataclass
class CallbackSpec:
    """A function the DLL calls back into the application with."""

    name: str
    ret: str = "i32"
    cc: str = "stdcall"
    args: list[ArgSpec] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"ret": self.ret, "cc": self.cc,
                "args": [a.to_json() for a in self.args]}

    @classmethod
    def from_json(cls, name: str, d: dict[str, Any]) -> "CallbackSpec":
        path = f"callbacks.{name}"
        d = _schema_object(d, path, allowed={"ret", "cc", "args"})
        raw_args = _schema_value(d, "args", list, path, default=[])
        return cls(
            name=name,
            ret=_schema_value(d, "ret", str, path, default="i32"),
            cc=_schema_value(d, "cc", str, path, default="stdcall"),
            args=[ArgSpec.from_json(a) for a in raw_args])


@dataclass
class SymbolSpec:
    name: str
    ordinal: int | None = None
    noname: bool = False
    cc: str = "stdcall"
    ret: str = "i32"
    args: list[ArgSpec] = field(default_factory=list)
    lasterr: bool = False           # capture GetLastError after the call
    confidence: str = "high"        # high | medium | low  (from contract.py)
    tier: str | None = None         # T0..T4, filled by the classifier
    forward: str | None = None      # "newlib.NewName" for pure forwarders
    ret_symbolize: str | None = None
    ret_creates: str | None = None

    def arg_by_name(self, name: str) -> ArgSpec | None:
        for a in self.args:
            if a.name == name:
                return a
        return None

    @property
    def fully_specified(self) -> bool:
        """True when every pointer argument has a known extent.

        Only fully specified symbols can earn full verification credit,
        because for the others the trace simply did not look at the bytes.
        """
        for a in self.args:
            if a.kind in (POINTER_KINDS | {"blob"}) \
                    and a.kind not in ("handle", "fnptr"):
                if not a.records_bytes:
                    return False
        return True

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"cc": self.cc, "ret": self.ret,
                             "args": [a.to_json() for a in self.args]}
        if self.ordinal is not None:
            d["ordinal"] = self.ordinal
        for k, default in (("noname", False), ("lasterr", False),
                           ("confidence", "high")):
            v = getattr(self, k)
            if v != default:
                d[k] = v
        for k in ("tier", "forward", "ret_symbolize", "ret_creates"):
            v = getattr(self, k)
            if v:
                d[k] = v
        return d

    @classmethod
    def from_json(cls, name: str, d: dict[str, Any]) -> "SymbolSpec":
        path = f"symbols.{name}"
        d = _schema_object(
            d, path,
            allowed={"ordinal", "noname", "cc", "ret", "args", "lasterr",
                     "confidence", "tier", "forward", "ret_symbolize",
                     "ret_creates"})
        raw_args = _schema_value(d, "args", list, path, default=[])

        def optional_string(key: str) -> str | None:
            return (_schema_value(d, key, str, path)
                    if key in d else None)

        return cls(
            name=name,
            ordinal=(_schema_value(d, "ordinal", int, path)
                     if "ordinal" in d else None),
            noname=_schema_value(d, "noname", bool, path, default=False),
            cc=_schema_value(d, "cc", str, path, default="stdcall"),
            ret=_schema_value(d, "ret", str, path, default="i32"),
            args=[ArgSpec.from_json(a) for a in raw_args],
            lasterr=_schema_value(d, "lasterr", bool, path, default=False),
            confidence=_schema_value(
                d, "confidence", str, path, default="high"),
            tier=optional_string("tier"), forward=optional_string("forward"),
            ret_symbolize=optional_string("ret_symbolize"),
            ret_creates=optional_string("ret_creates"))


@dataclass
class Contract:
    module: str                     # "oldlib.dll" -- the ABI being preserved
    arch: str = "x64"               # x64 | x86
    real_module: str = ""           # renamed original the tap forwards to
    symbols: dict[str, SymbolSpec] = field(default_factory=dict)
    structs: dict[str, StructSpec] = field(default_factory=dict)
    callbacks: dict[str, CallbackSpec] = field(default_factory=dict)

    @property
    def ptr_size(self) -> int:
        return 8 if self.arch == "x64" else 4

    def struct_size(self, name: str) -> int:
        s = self.structs.get(name)
        if s is None:
            raise ContractError(f"unknown struct '{name}'")
        return s.size

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.arch not in ("x64", "x86"):
            problems.append(f"bad arch '{self.arch}'")
        for s in self.structs.values():
            problems.extend(s.validate())
            for f in s.fields:
                if f.volatile:
                    problems.append(
                        f"{s.name}.{f.name}: volatile fields erase arbitrary "
                        "value changes; strict verification requires an "
                        "explicit semantic invariant")
                if f.kind in POINTER_KINDS:
                    if f.kind != "ptr":
                        problems.append(
                            f"{s.name}.{f.name}: embedded {f.kind} fields are "
                            "not identity-normalized; declare a ptr field or "
                            "add recorder support")
                    if f.size != self.ptr_size:
                        problems.append(
                            f"{s.name}.{f.name}: pointer field size {f.size} "
                            f"!= {self.arch} pointer size {self.ptr_size}")
                elif f.kind in SCALAR_KINDS:
                    expected = SCALAR_KINDS[f.kind]
                    if expected == 0 or f.size != expected:
                        problems.append(
                            f"{s.name}.{f.name}: {f.kind} field size {f.size} "
                            f"!= {expected}")
                    if f.kind in ("f32", "f64"):
                        problems.append(
                            f"{s.name}.{f.name}: floating-point contract "
                            "fields are not approval-safe until the complete "
                            "wire/normalizer/replay path preserves raw IEEE "
                            "bits")
            if s.size_field:
                size_field = s.field_by_name(s.size_field)
                if size_field and size_field.kind not in {
                        "u8", "u16", "u32", "u64"}:
                    problems.append(
                        f"{s.name}.{s.size_field}: size_field must be an "
                        "unsigned integer")
        seen_ord: dict[int, str] = {}
        for sym in self.symbols.values():
            if sym.cc not in CALLING_CONVENTIONS:
                problems.append(f"{sym.name}: bad cc '{sym.cc}'")
            if sym.ret not in ALL_KINDS:
                problems.append(f"{sym.name}: bad ret kind '{sym.ret}'")
            elif sym.ret in ("f32", "f64"):
                problems.append(
                    f"{sym.name}: floating-point returns are not "
                    "approval-safe until the complete wire/normalizer/replay "
                    "path preserves raw IEEE bits")
            if (sym.ret_symbolize or sym.ret_creates) and \
                    sym.ret not in (POINTER_KINDS | {"blob"}):
                problems.append(
                    f"{sym.name}: return identity annotations require a "
                    "pointer-like return kind")
            if sym.ordinal is not None:
                if not 1 <= int(sym.ordinal) <= 0xFFFF:
                    problems.append(
                        f"{sym.name}: ordinal out of range: {sym.ordinal}")
                if sym.ordinal in seen_ord:
                    problems.append(
                        f"ordinal {sym.ordinal} used by both "
                        f"{seen_ord[sym.ordinal]} and {sym.name}")
                seen_ord[sym.ordinal] = sym.name
            if sym.noname and sym.ordinal is None:
                problems.append(f"{sym.name}: NONAME export requires an ordinal")
            if sym.confidence not in ("high", "medium", "low"):
                problems.append(
                    f"{sym.name}: bad confidence '{sym.confidence}'")
            elif sym.confidence != "high":
                problems.append(
                    f"{sym.name}: confidence is {sym.confidence}; strict "
                    "verification requires high")
            problems.extend(self._validate_args(sym.name, sym.args,
                                                sym.arg_by_name))

        for cb in self.callbacks.values():
            if cb.cc not in CALLING_CONVENTIONS:
                problems.append(f"{cb.name}: bad callback cc '{cb.cc}'")
            if cb.ret not in ALL_KINDS:
                problems.append(
                    f"{cb.name}: bad callback ret kind '{cb.ret}'")
            elif cb.ret in ("f32", "f64"):
                problems.append(
                    f"{cb.name}: floating-point callback returns are not "
                    "approval-safe until the complete wire/normalizer/replay "
                    "path preserves raw IEEE bits")
            by_name = {a.name: a for a in cb.args}
            problems.extend(self._validate_args(
                cb.name, cb.args, lambda name, d=by_name: d.get(name)))
        return problems

    def _validate_args(self, owner: str, args: list[ArgSpec],
                       lookup: Any) -> list[str]:
        problems: list[str] = []
        names: set[str] = set()
        for a in args:
            if a.name in names:
                problems.append(f"{owner}: duplicate arg '{a.name}'")
            names.add(a.name)
            if a.kind in ("f32", "f64"):
                problems.append(
                    f"{owner}.{a.name}: floating-point arguments are not "
                    "approval-safe until the complete wire/normalizer/replay "
                    "path preserves raw IEEE bits")
            if a.struct and a.kind != "ptr":
                problems.append(
                    f"{owner}.{a.name}: struct is only valid on ptr arguments")
            if a.struct and a.struct not in self.structs:
                problems.append(
                    f"{owner}.{a.name}: unknown struct '{a.struct}'")
            if a.callback and a.kind != "fnptr":
                problems.append(
                    f"{owner}.{a.name}: callback is only valid on fnptr arguments")
            if a.callback and a.callback not in self.callbacks:
                problems.append(
                    f"{owner}.{a.name}: unknown callback '{a.callback}'")
            if a.is_out and a.kind not in {"ptr", "blob", "str", "wstr"}:
                problems.append(
                    f"{owner}.{a.name}: {a.dir} {a.kind} is passed by value; "
                    "post-call output cannot be observed")
            if a.extent and a.kind not in ("ptr", "blob"):
                problems.append(
                    f"{owner}.{a.name}: extent is only supported for ptr/blob")
            if a.kind == "fnptr" and not a.callback:
                problems.append(
                    f"{owner}.{a.name}: fnptr has no callback contract; "
                    "callback effects would be unverified")
            if a.kind in ("ptr", "blob") and not a.records_bytes:
                problems.append(
                    f"{owner}.{a.name}: pointer extent is unknown; strict "
                    "verification cannot observe its bytes")
            if a.kind in ("ptr", "blob") and a.extent \
                    and a.extent.fixed == 0:
                problems.append(
                    f"{owner}.{a.name}: zero-byte fixed extent is vacuous")
            if a.struct and a.extent and a.extent.struct and \
                    a.struct != a.extent.struct:
                problems.append(
                    f"{owner}.{a.name}: struct '{a.struct}' disagrees with "
                    f"extent struct '{a.extent.struct}'")
            if a.creates and not a.is_out:
                problems.append(
                    f"{owner}.{a.name}: creates requires out or inout direction")
            if a.releases and not a.is_in:
                problems.append(
                    f"{owner}.{a.name}: releases requires in or inout direction")
            if (a.symbolize or a.creates or a.releases) and \
                    a.kind not in (POINTER_KINDS | {"blob"}):
                problems.append(
                    f"{owner}.{a.name}: identity annotations require a "
                    "pointer-like kind")
            if a.extent and a.extent.arg:
                length_arg = lookup(a.extent.arg)
                if length_arg is None:
                    problems.append(
                        f"{owner}.{a.name}: extent references missing arg "
                        f"'{a.extent.arg}'")
                elif length_arg.kind not in SCALAR_KINDS or \
                        length_arg.kind in ("void", "bool", "f32", "f64"):
                    problems.append(
                        f"{owner}.{a.name}: extent arg '{a.extent.arg}' "
                        "must be an integer scalar")
            if a.extent and a.extent.struct and \
                    a.extent.struct not in self.structs:
                problems.append(
                    f"{owner}.{a.name}: extent references unknown struct "
                    f"'{a.extent.struct}'")
        return problems

    def to_json(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "arch": self.arch,
            "real_module": self.real_module,
            "structs": {k: v.to_json() for k, v in sorted(self.structs.items())},
            "callbacks": {k: v.to_json() for k, v in sorted(self.callbacks.items())},
            "symbols": {k: v.to_json() for k, v in sorted(self.symbols.items())},
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_json(), indent=2, ensure_ascii=False),
            encoding="utf-8")

    def fingerprint(self) -> str:
        """Stable SHA-256 binding traces and generated taps to this contract."""
        payload = json.dumps(
            self.to_json(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Contract":
        d = _schema_object(
            d, "contract",
            allowed={"module", "arch", "real_module", "symbols", "structs",
                     "callbacks"},
            required={"module"})
        raw_structs = _schema_named_objects(
            _schema_value(d, "structs", dict, "contract", default={}),
            "contract.structs")
        raw_callbacks = _schema_named_objects(
            _schema_value(d, "callbacks", dict, "contract", default={}),
            "contract.callbacks")
        raw_symbols = _schema_named_objects(
            _schema_value(d, "symbols", dict, "contract", default={}),
            "contract.symbols")
        c = cls(
            module=_schema_value(d, "module", str, "contract"),
            arch=_schema_value(d, "arch", str, "contract", default="x64"),
            real_module=_schema_value(
                d, "real_module", str, "contract", default=""))
        for name, sd in raw_structs.items():
            c.structs[name] = StructSpec.from_json(name, sd)
        for name, cd in raw_callbacks.items():
            c.callbacks[name] = CallbackSpec.from_json(name, cd)
        for name, yd in raw_symbols.items():
            c.symbols[name] = SymbolSpec.from_json(name, yd)
        return c

    @classmethod
    def load(cls, path: str | Path) -> "Contract":
        try:
            text = Path(path).read_text(encoding="utf-8")
            decoded = json.loads(
                text, object_pairs_hook=_json_object_no_duplicates,
                parse_constant=_reject_json_constant)
        except ContractError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContractError(f"cannot load strict contract JSON: {exc}") \
                from exc
        c = cls.from_json(decoded)
        problems = c.validate()
        if problems:
            raise ContractError(
                "contract validation failed:\n  " + "\n  ".join(problems))
        return c


def _runs_of_zero(flags: bytearray) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    start: int | None = None
    for i, v in enumerate(flags):
        if v == 0 and start is None:
            start = i
        elif v != 0 and start is not None:
            out.append((start, i - start))
            start = None
    if start is not None:
        out.append((start, len(flags) - start))
    return out


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ordered = sorted(ranges)
    merged = [list(ordered[0])]
    for off, size in ordered[1:]:
        last = merged[-1]
        if off <= last[0] + last[1]:
            last[1] = max(last[0] + last[1], off + size) - last[0]
        else:
            merged.append([off, size])
    return [(o, s) for o, s in merged]
