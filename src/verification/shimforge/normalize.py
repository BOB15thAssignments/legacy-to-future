"""Normalize raw traces for deterministic comparison.

Pointer-like values are symbolized, policy-approved byte ranges are masked,
and thread identifiers are remapped by first appearance. Embedded pointer
fields retain symbolic identity while their process-specific address bytes
are masked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .model import ArgSpec, CallbackSpec, Contract, SymbolSpec
# Frozen module: reuse its range merger rather than growing a second one
# that could drift from the semantics StructSpec.masked_ranges() relies on.
from .model import _merge_ranges
from .policy import MaskRule, Policy, match_pattern
from .trace import (TRACE_TAP_VERSION, Rec, Trace, Val,
                    validate_trace_contract)

logger = logging.getLogger(__name__)

NULL_TOKEN = "@null"
ERASED_TOKEN = "@ptr"
FREED_SUFFIX = "!freed"
EXT_CLASS = "ext"
_EXT_PREFIX = f"@{EXT_CLASS}#"

# Kinds whose payload is bytes the recorder may or may not have captured.
# Deliberately the same set model.ArgSpec.records_bytes uses, so "no bytes
# here" means one thing across the toolkit; "blob" is excluded for that
# reason even though the name suggests otherwise.
BYTE_KINDS = ("ptr", "str", "wstr")
# Kinds that are a pointer value even when the recorder logged them as a
# scalar (the tap passes handles through tr_in_i64 with kind "handle").
PTR_VALUE_KINDS = ("ptr", "handle", "fnptr")

# Header keys handled outside ordinary header equality. pid/run are run-local;
# subject is separately bound to each binary and must differ for CLI L2.
_RUN_LOCAL_HEADER_KEYS = ("t", "pid", "run", "subject")


@dataclass
class NormVal:
    k: str
    v: Any = None             # scalar, or "@h#3" for symbolized, or None if masked out
    b: str | None = None      # hex with masked ranges replaced by ".." per byte
    captured: bool = True
    # Embedded pointer field -> its token, e.g. {"data": "@ext#2"}. The bytes
    # these were read from are masked out of `b` (a raw address is run-local),
    # so this dict is the ONLY place their identity is compared. Keyed
    # "data[0]", "data[1]", ... across a struct array; None when the value is
    # not a declared struct, has no comparable pointer field, or is fully
    # masked.
    fields: dict[str, str] | None = None


@dataclass
class NormRec:
    seq: int
    tid: int
    sym: str
    depth: int
    parent_sym: str | None
    inn: dict[str, NormVal]
    out: dict[str, NormVal]
    ret: NormVal | None
    lasterr: int | None
    origin: Rec               # back-pointer for reporting


@dataclass
class NormTrace:
    header: dict[str, Any]
    threads: dict[int, list[NormRec]]
    records: list[NormRec]
    # raw hex -> "@h#1". Reporting aid only: when an allocator reuses an
    # address the entry holds the LAST binding, so the authoritative token
    # for a given occurrence is the one on its NormVal.
    symbol_table: dict[str, str]
    # (sym, path) of every value the recorder did not capture, deduped --
    # the coverage scorer docks credit per path, not per occurrence.
    unknown_extent: list[tuple[str, str]]
    # Provenance/validity is carried through normalization so no caller can
    # accidentally turn a malformed or interrupted raw trace into an ordinary
    # empty normalized trace.  Defaults keep hand-built unit fixtures valid.
    run_id: str = ""
    # Bound to the actual original/candidate binary by the L2 CLI. It is kept
    # out of the comparable header because A-vs-B subjects must differ.
    subject_hash: str = ""
    complete: bool = True
    validation_errors: list[str] = field(default_factory=list)
    source: str = ""


class _Symbolizer:
    """Raw value -> stable token, shared across all symbols and fields."""

    def __init__(self, erase: bool) -> None:
        self.erase = erase
        self.table: dict[str, str] = {}
        self.freed: set[str] = set()
        self._counters: dict[str, int] = {}

    def token(self, raw: str, creates: str | None = None) -> str:
        if _is_zero(raw):
            # NULL is never numbered: it is the same object in every run and
            # in every process, and numbering it would shift every later n.
            return NULL_TOKEN
        prior = self.table.get(raw)
        # An "@ext#n" binding only records that the address was seen before
        # anything owned it. A create there is still a create, and it MUST
        # re-mint: otherwise whether the object reads "@h#1" or "@ext#2"
        # depends on whether this run's allocator happened to hand back an
        # address the app had already passed in -- exactly the run-to-run
        # noise normalization exists to erase.
        stale_ext = (prior is not None and creates != EXT_CLASS
                     and prior.startswith(_EXT_PREFIX))
        if creates and (prior is None or raw in self.freed or stale_ext):
            # Allocators reuse addresses. A create at a raw value we already
            # released is a NEW object and must not inherit the old token,
            # otherwise a use-after-free and a legitimate realloc look alike.
            self.freed.discard(raw)
            self.table[raw] = self._mint(creates)
        elif raw not in self.table:
            self.table[raw] = self._mint(EXT_CLASS)
        tok = ERASED_TOKEN if self.erase else self.table[raw]
        if raw in self.freed:
            # Kept even in erased mode: the suffix carries no address, and
            # dropping it would let a use-after-close match silently.
            tok += FREED_SUFFIX
        return tok

    def release(self, raw: str) -> None:
        # Deliberately does not mint. A release normally follows the token()
        # call for the same value in the same record, so the binding exists;
        # when it does not (the releasing arg was masked whole) minting here
        # would put an uncompared value into the numbering and desynchronise
        # every later token. Marking it freed is enough -- a later real use
        # mints then, identically in both runs.
        if not _is_zero(raw):
            self.freed.add(raw)

    def _mint(self, cls: str) -> str:
        n = self._counters.get(cls, 0) + 1
        self._counters[cls] = n
        return f"@{cls}#{n}"


@dataclass
class _Ctx:
    contract: Contract
    policy: Policy
    syms: _Symbolizer
    unknown: list[tuple[str, str]] = field(default_factory=list)
    _unknown_seen: set[tuple[str, str]] = field(default_factory=set)
    validation_errors: list[str] = field(default_factory=list)
    _validation_seen: set[str] = field(default_factory=set)
    # (sym, path, nbytes) -> (whole_value, ranges). Mask resolution walks every
    # rule in the policy, and a real trace hits the same few paths millions of
    # times.
    _mask_cache: dict[tuple[str, str, int],
                      tuple[bool, list[tuple[int, int]]]] = \
        field(default_factory=dict)

    def note_unknown(self, sym: str, path: str) -> None:
        key = (sym, path)
        if key not in self._unknown_seen:
            self._unknown_seen.add(key)
            self.unknown.append(key)

    def note_invalid(self, message: str) -> None:
        if message not in self._validation_seen:
            self._validation_seen.add(message)
            self.validation_errors.append(message)

    def mask_for(self, sym: str, path: str,
                 nbytes: int) -> tuple[bool, list[tuple[int, int]]]:
        """(whole_value, byte ranges) for one field, tiled and merged."""
        key = (sym, path, nbytes)
        hit = self._mask_cache.get(key)
        if hit is None:
            hit = self._resolve_mask(sym, path, nbytes)
            self._mask_cache[key] = hit
        return hit

    def _resolve_mask(self, sym: str, path: str,
                      nbytes: int) -> tuple[bool, list[tuple[int, int]]]:
        rules = self.policy.masks_for(sym, path)
        if not rules:
            return False, []
        ranges: list[tuple[int, int]] = []
        for rule in rules:
            if rule.byte_ranges is None:
                return True, []
            ranges.extend(_tile(self.contract, sym, path, rule, nbytes))
        return False, _merge_ranges(ranges)


def normalize(trace: Trace, contract: Contract, policy: Policy) -> NormTrace:
    """Symbolize, mask and per-thread split a raw trace."""
    ctx = _Ctx(contract=contract, policy=policy,
               syms=_Symbolizer(erase=not policy.symbolize_pointers))

    # Parent is recorded as a seq, but seqs are an artefact of how many calls
    # happened to precede this one and are not comparable across runs. Resolve
    # to the parent's SYMBOL up front, from the whole trace, because a
    # streaming resolve would miss out-of-order lines from concurrent threads.
    sym_by_seq = {r.seq: r.sym for r in trace.records if r.is_call}

    tid_map: dict[int, int] = {}
    records: list[NormRec] = []
    for rec in sorted(trace.records, key=lambda r: r.seq):
        if not rec.is_call:
            continue
        tid = tid_map.setdefault(rec.tid, len(tid_map))
        nrec = _norm_record(rec, tid, sym_by_seq, ctx)
        # Ignored symbols are still normalized so the symbol table and the
        # per-class counters advance identically in both runs; only the
        # output record is dropped.
        if any(match_pattern(p, rec.sym) for p in policy.ignore_symbols):
            continue
        records.append(nrec)

    threads: dict[int, list[NormRec]] = {}
    if policy.thread_mode == "global":
        # One comparable sequence: callers that opt out of per-thread split
        # still read threads[], so give them a single bucket rather than
        # something they have to special-case.
        if records:
            threads[0] = list(records)
    else:
        for r in records:
            threads.setdefault(r.tid, []).append(r)

    header = {k: v for k, v in trace.header.items()
              if k not in _RUN_LOCAL_HEADER_KEYS}
    logger.debug("normalized %d records, %d threads, %d symbols, %d unknown",
                 len(records), len(threads), len(ctx.syms.table),
                 len(ctx.unknown))
    evidence_errors = list(getattr(trace, "validation_errors", ()) or ())
    evidence_errors.extend(validate_trace_contract(trace, contract))
    for note in getattr(trace, "notes", ()) or ():
        marker = f"runtime note q={note.seq} {note.sym}: {note.msg}"
        if not any(marker in problem for problem in evidence_errors):
            evidence_errors.append(
                f"{trace.source + ': ' if trace.source else ''}{marker}")
    evidence_errors.extend(ctx.validation_errors)
    # Keep diagnostics stable if both the parser and this defensive in-memory
    # check observed the same defect.
    evidence_errors = list(dict.fromkeys(evidence_errors))

    return NormTrace(header=header, threads=threads, records=records,
                     symbol_table=dict(ctx.syms.table),
                     unknown_extent=list(ctx.unknown),
                     run_id=(str(trace.header.get("run", "")).strip()
                             if isinstance(trace.header.get("run", ""), str)
                             else ""),
                     subject_hash=(str(trace.header.get("subject", "")).strip()
                                   if isinstance(
                                       trace.header.get("subject", ""), str)
                                   else ""),
                     complete=bool(getattr(trace, "complete", True)),
                     validation_errors=evidence_errors,
                     source=str(getattr(trace, "source", "") or ""))


def _norm_record(rec: Rec, tid: int, sym_by_seq: dict[int, str],
                 ctx: _Ctx) -> NormRec:
    spec = _spec_for(ctx.contract, rec.sym)
    released: list[str] = []

    inn: dict[str, NormVal] = {}
    for name, val in rec.inn.items():
        arg = _arg_of(spec, name)
        inn[name] = _norm_value(val, arg, spec, rec.sym, f"in.{name}", ctx)
        if arg is not None and arg.releases:
            raw = _raw_of(val, arg, spec, f"in.{name}",
                          ctx.contract.ptr_size)
            if raw is not None:
                released.append(raw)

    # Applied between the sections, not after the record: the `in` values were
    # captured before the call, so the releasing call still shows a live token,
    # while `out` and `ret` were captured after it and must see the release.
    # A realloc-shaped symbol (releases `old`, creates `new`) that the allocator
    # satisfies in place would otherwise re-bind the SAME raw value while it is
    # still marked live, so the new object inherits the dead token and every
    # later use reads "!freed" -- and only in the runs where the allocator
    # happened to reuse the block, which is precisely the run-to-run noise this
    # module exists to erase.
    for raw in released:
        ctx.syms.release(raw)

    out: dict[str, NormVal] = {}
    for name, val in rec.out.items():
        arg = _arg_of(spec, name)
        out[name] = _norm_value(val, arg, spec, rec.sym, f"out.{name}", ctx)

    ret = None
    if rec.ret is not None:
        ret = _norm_value(rec.ret, None, spec, rec.sym, "ret", ctx)

    lasterr = rec.lasterr
    if lasterr is not None and ctx.policy.masks_for(rec.sym, "lasterr"):
        # lasterr is a bare int with no byte layout, so any matching rule can
        # only mean "drop it"; byte_ranges on this path are ignored.
        lasterr = None

    return NormRec(seq=rec.seq, tid=tid, sym=rec.sym, depth=rec.depth,
                   parent_sym=sym_by_seq.get(rec.parent)
                   if rec.parent is not None else None,
                   inn=inn, out=out, ret=ret, lasterr=lasterr, origin=rec)


def _norm_value(val: Val, arg: ArgSpec | None,
                spec: SymbolSpec | CallbackSpec | None,
                sym: str, path: str, ctx: _Ctx) -> NormVal:
    nbytes = len(val.b) // 2 if val.b is not None else 0
    if isinstance(val.n, int) and not isinstance(val.n, bool):
        if val.b is None and val.n > 0:
            ctx.note_invalid(
                f"{sym}.{path}: partial capture declares n={val.n} but b is absent")
        elif val.b is not None and nbytes != val.n:
            ctx.note_invalid(
                f"{sym}.{path}: partial capture has {nbytes} byte(s), n={val.n}")
    whole, ranges = ctx.mask_for(sym, path, nbytes)

    captured = _is_captured(val)
    if not captured and _expects_bytes(val, arg):
        ctx.note_unknown(sym, path)

    b = val.b
    if b is not None:
        b = ".." * nbytes if whole else _mask_hex(b, ranges)

    if whole:
        # A fully masked value is out of the comparison entirely, so it must
        # not mint a token either -- doing so would put an uncompared address
        # into the identity graph and shift every later token number. That
        # applies to its embedded pointers too: nothing here is extracted.
        return NormVal(k=val.k, v=None, b=b, captured=captured)

    # Order matters: the value's own pointer is minted before the pointers
    # found inside it, in both runs, so token numbers line up.
    v = _norm_scalar(val, arg, spec, path, ctx)
    return NormVal(k=val.k, v=v, b=b, captured=captured,
                   fields=_norm_fields(val, sym, path, nbytes, ctx))


def _norm_fields(val: Val, sym: str, path: str, nbytes: int,
                 ctx: _Ctx) -> dict[str, str] | None:
    """Symbolize the pointer fields embedded in a captured struct.

    Read from the raw capture so pointer identity remains available after
    process-specific address bytes are masked.
    """
    if val.b is None or nbytes <= 0:
        return None
    name = _struct_name(ctx.contract, sym, path)
    if name is None:
        return None
    struct = ctx.contract.structs.get(name)
    if struct is None:
        # An undeclared struct has no known layout, so any offset we picked
        # would be a guess -- and a guessed token pollutes the identity graph
        # for every later value. Contract.validate() reports this separately.
        return None
    pointers = struct.pointer_fields()
    if not pointers:
        return None

    stride = struct.size
    count = 1 if stride <= 0 or nbytes <= stride \
        else (nbytes + stride - 1) // stride
    ptr_size = ctx.contract.ptr_size
    out: dict[str, str] = {}
    for index in range(count):
        base = index * stride
        for f in pointers:
            key = f.name if count == 1 else f"{f.name}[{index}]"
            # Read exactly the bytes `pointer_ranges()` masks, not
            # `ptr_size` of them. A 32-bit pointer field inside an x64
            # contract is a real shape (WOW64 structs, on-disk formats), and
            # reading 8 bytes there swallows the NEXT field -- which is a
            # normal compared field, so the token becomes a function of data
            # that has nothing to do with the pointer. The damage is not just
            # noise: the contaminated value no longer matches the top-level
            # token for the same object, so the identity link the extraction
            # exists to create is silently absent and a shim writing a wrong
            # pointer there diffs clean again.
            width = f.size if 1 <= f.size <= 8 else ptr_size
            off = base + f.off
            if off + width > nbytes:
                # Truncated capture (a runtime size_field smaller than the
                # declared struct). Reporting it as absent would read as
                # agreement between two runs that both stopped short; the
                # coverage scorer is the right place for it.
                ctx.note_unknown(sym, f"{path}.{key}")
                continue
            chunk = val.b[2 * off:2 * (off + width)]
            try:
                raw = _canon(int.from_bytes(bytes.fromhex(chunk), "little"),
                             ptr_size)
            except ValueError:
                logger.warning("unparsable embedded pointer %r at %s.%s",
                               chunk, path, key)
                ctx.note_unknown(sym, f"{path}.{key}")
                continue
            # Same table as every top-level pointer: that is what makes
            # "the buffer the app passed in" and "the pointer the callee
            # left in the struct" comparable at all.
            out[key] = ctx.syms.token(raw)
    return out or None


def _norm_scalar(val: Val, arg: ArgSpec | None,
                 spec: SymbolSpec | CallbackSpec | None,
                 path: str, ctx: _Ctx) -> Any:
    if val.k in ("str", "wstr"):
        # For strings the content is the comparable value and the address is
        # pure noise, so the pointer is dropped rather than symbolized. NULL
        # still has to be distinguishable from an empty string.
        return NULL_TOKEN if _is_null(val) else val.v
    raw = _raw_of(val, arg, spec, path, ctx.contract.ptr_size)
    if raw is None:
        return val.v
    return ctx.syms.token(raw, creates=_creates_of(arg, spec, path))


def _raw_of(val: Val, arg: ArgSpec | None,
            spec: SymbolSpec | CallbackSpec | None, path: str,
            ptr_size: int = 8) -> str | None:
    """Canonical hex of the symbolizable raw value, or None."""
    if val.k in ("str", "wstr"):
        return None
    if val.p is not None:
        try:
            return _canon(int(val.p, 16), ptr_size)
        except ValueError:
            logger.warning("unparsable pointer %r at %s", val.p, path)
            return None
    if not isinstance(val.v, int) or isinstance(val.v, bool):
        return None
    declared = None
    if arg is not None:
        declared = arg.symbolize or arg.creates or arg.releases
    elif path == "ret" and isinstance(spec, SymbolSpec):
        declared = spec.ret_symbolize or spec.ret_creates
    if val.k in PTR_VALUE_KINDS or declared:
        return _canon(val.v, ptr_size)
    return None


def _creates_of(arg: ArgSpec | None, spec: SymbolSpec | CallbackSpec | None,
                path: str) -> str | None:
    if arg is not None:
        return arg.creates
    if path == "ret" and isinstance(spec, SymbolSpec):
        return spec.ret_creates
    return None


def _tile(contract: Contract, sym: str, path: str, rule: MaskRule,
          nbytes: int) -> list[tuple[int, int]]:
    """Repeat a per-element mask across an array of structs.

    Only a derived rule that still exactly equals one of the struct's own
    derived range sets is treated as element-relative:
    `noncomparable_ranges()` (what `Policy.derive` emits now) or
    `masked_ranges()` (what a policy saved before pointer fields were
    tracked holds). Everything else keeps absolute offsets, so a mask
    narrowed to a specific differing byte by the determinism check is never
    widened into a periodic one.
    """
    assert rule.byte_ranges is not None
    ranges = [(int(o), int(s)) for o, s in rule.byte_ranges]
    if not rule.auto or nbytes <= 0:
        return ranges
    stride = _element_stride(contract, sym, path)
    if stride is None or stride <= 0 or nbytes <= stride:
        return ranges
    struct = contract.structs.get(_struct_name(contract, sym, path) or "")
    if struct is None or ranges not in (struct.noncomparable_ranges(),
                                        struct.masked_ranges()):
        return ranges
    tiled: list[tuple[int, int]] = []
    for base in range(0, nbytes, stride):
        tiled.extend((base + o, s) for o, s in ranges)
    return tiled


def _element_stride(contract: Contract, sym: str, path: str) -> int | None:
    name = _struct_name(contract, sym, path)
    if name is None:
        return None
    struct = contract.structs.get(name)
    return struct.size if struct is not None else None


def _struct_name(contract: Contract, sym: str, path: str) -> str | None:
    arg = _arg_of(_spec_for(contract, sym), path.partition(".")[2])
    if arg is None:
        return None
    return arg.struct or (arg.extent.struct if arg.extent else None)


def _spec_for(contract: Contract,
              sym: str) -> SymbolSpec | CallbackSpec | None:
    spec = contract.symbols.get(sym)
    return spec if spec is not None else contract.callbacks.get(sym)


def _arg_of(spec: SymbolSpec | CallbackSpec | None,
            name: str) -> ArgSpec | None:
    if spec is None or not name:
        return None
    for a in spec.args:
        if a.name == name:
            return a
    return None


def _is_null(val: Val) -> bool:
    """`Val.is_null` that degrades instead of raising.

    `trace.py` is frozen and its `is_null` calls `int(p, 16)` unguarded, so a
    trace carrying a malformed pointer -- "", "(null)", a torn field -- kills
    the whole normalization run. `_raw_of` already downgrades that case to a
    warning; the capture and coverage paths must agree, otherwise one bad
    field in a hundred-megabyte trace throws away the entire comparison.
    """
    if val.p is None:
        return False
    try:
        return int(val.p, 16) == 0
    except ValueError:
        return False


def _is_captured(val: Val) -> bool:
    if val.k in ("str", "wstr"):
        return val.v is not None or _is_null(val)
    if val.k in BYTE_KINDS:
        return val.b is not None or _is_null(val)
    return True


def _expects_bytes(val: Val, arg: ArgSpec | None) -> bool:
    """Whether a missing payload here costs verification credit."""
    if _is_null(val):
        return False
    if arg is not None and arg.kind not in BYTE_KINDS:
        return False
    return val.k in BYTE_KINDS


def _mask_hex(hexstr: str, ranges: list[tuple[int, int]]) -> str:
    if not ranges or not hexstr:
        return hexstr
    nbytes = len(hexstr) // 2
    chars = list(hexstr)
    for off, size in ranges:
        for i in range(max(off, 0), min(off + size, nbytes)):
            chars[2 * i] = "."
            chars[2 * i + 1] = "."
    return "".join(chars)


def _canon(value: int, ptr_size: int = 8) -> str:
    """Raw value -> table key, at the traced process's pointer width.

    The recorder renders pointer-shaped arguments as a SIGNED integer
    (`tr_in_i64(c, "h", (long long)(intptr_t)h, "handle")`), so an address
    with the top bit set comes back sign extended: on x86 the handle
    0x80001234 is logged as -0x7FFFEDCC. Truncating at the pointer width
    undoes exactly that, and it has to be the CONTRACT's width rather than a
    fixed 64 bits -- otherwise the same x86 address reaches the table as
    "ffffffff80001234" from an argument and as "80001234" from a 4-byte
    struct field, i.e. as two objects, which is the one thing the shared
    table exists to prevent. On x64 this is the old behaviour unchanged.
    """
    return format(value & ((1 << (8 * ptr_size)) - 1), "x")


def _is_zero(raw: str) -> bool:
    return int(raw, 16) == 0


if __name__ == "__main__":
    import struct as _struct

    from .model import Extent, FieldSpec, StructSpec
    from .trace import REC_CALL, REC_CALLBACK, make_header

    logging.basicConfig(level=logging.INFO)

    def build_contract() -> Contract:
        con = Contract(module="oldlib.dll", arch="x64")
        con.structs["OLD_BUF"] = StructSpec(
            name="OLD_BUF", size=24,
            fields=[FieldSpec("size", 0, 4, "u32"),
                    # Raw bytes are masked, but identity remains compared as
                    # a token. Volatile fields are forbidden in strict mode.
                    FieldSpec("data", 8, 8, "ptr"),
                    FieldSpec("len", 16, 4, "u32")])
        con.callbacks["cb_progress"] = CallbackSpec(
            name="cb_progress", ret="i32",
            args=[ArgSpec("ctx", "ptr"), ArgSpec("pct", "i32")])
        con.symbols["Open"] = SymbolSpec(
            name="Open", ret="i32",
            args=[ArgSpec("name", "str"),
                  ArgSpec("h", "handle", dir="out", creates="h")],
            lasterr=True)
        con.symbols["Attach"] = SymbolSpec(
            name="Attach", ret="i32",
            args=[ArgSpec("h", "handle", symbolize="h"),
                  ArgSpec("opt", "ptr")])
        con.symbols["Process"] = SymbolSpec(
            name="Process", ret="i32",
            args=[ArgSpec("h", "handle", symbolize="h"),
                  ArgSpec("buf", "ptr", dir="inout", struct="OLD_BUF"),
                  ArgSpec("cb", "fnptr", callback="cb_progress")])
        con.symbols["ProcessMany"] = SymbolSpec(
            name="ProcessMany", ret="i32",
            args=[ArgSpec("count", "u32"),
                  ArgSpec("items", "ptr", struct="OLD_BUF",
                          extent=Extent(arg="count", scale=24))])
        con.symbols["Close"] = SymbolSpec(
            name="Close", ret="i32",
            args=[ArgSpec("h", "handle", releases="h")])
        con.symbols["Tick"] = SymbolSpec(name="Tick", ret="u32", args=[])
        problems = con.validate()
        # This fixture intentionally contains two unknown extents to exercise
        # unknown_extent bookkeeping below.  Production contract validation
        # rejects them fail-closed; only those deliberate fixture diagnostics
        # are admissible here.
        expected = {
            "Open.h: out handle is passed by value; post-call output cannot be observed",
            "Attach.opt: pointer extent is unknown; strict verification cannot observe its bytes",
            "cb_progress.ctx: pointer extent is unknown; strict verification cannot observe its bytes",
        }
        assert set(problems) == expected, problems
        return con

    def buf_bytes(size: int, data_ptr: int, ln: int, pad: int) -> str:
        return (_struct.pack("<I", size) + bytes([pad]) * 4
                + _struct.pack("<Q", data_ptr) + _struct.pack("<I", ln)
                + bytes([pad]) * 4).hex()

    def build_trace(*, base_seq: int, h: int, buf_p: int, data_p: int,
                    items_p: int, ctx_p: int, ext_h: int, tid_a: int,
                    tid_b: int, pad: int, pid: int) -> Trace:
        """Same behaviour, different addresses / tids / seqs / pid."""
        q = iter(range(base_seq, base_seq + 100))
        recs: list[Rec] = []

        recs.append(Rec(t=REC_CALL, seq=next(q), sym="Open", tid=tid_a,
                        inn={"name": Val(k="str", p=format(data_p, "x"),
                                         v="data.bin")},
                        out={"h": Val(k="handle", v=h)},
                        ret=Val(k="i32", v=0), lasterr=0))
        recs.append(Rec(t=REC_CALL, seq=next(q), sym="Attach", tid=tid_a,
                        inn={"h": Val(k="handle", v=ext_h),
                             "opt": Val(k="ptr", p="0")},
                        ret=Val(k="i32", v=0)))
        proc_seq = next(q)
        recs.append(Rec(
            t=REC_CALL, seq=proc_seq, sym="Process", tid=tid_a,
            inn={"h": Val(k="handle", v=h),
                 "buf": Val(k="ptr", p=format(buf_p, "x"), n=24,
                            b=buf_bytes(24, data_p, 7, pad)),
                 "cb": Val(k="fnptr", p=format(data_p + 0x40, "x"))},
            out={"buf": Val(k="ptr", p=format(buf_p, "x"), n=24,
                            b=buf_bytes(24, data_p, 12, pad))},
            ret=Val(k="i32", v=1)))
        recs.append(Rec(
            t=REC_CALLBACK, seq=next(q), sym="cb_progress", tid=tid_a,
            depth=1, parent=proc_seq,
            # n=0 with no "b": the recorder deliberately did not look.
            inn={"ctx": Val(k="ptr", p=format(ctx_p, "x"), n=0),
                 "pct": Val(k="i32", v=50)},
            ret=Val(k="i32", v=0)))
        recs.append(Rec(
            t=REC_CALL, seq=next(q), sym="ProcessMany", tid=tid_b,
            inn={"count": Val(k="u32", v=2),
                 "items": Val(k="ptr", p=format(items_p, "x"), n=48,
                              b=buf_bytes(24, data_p, 1, pad)
                              + buf_bytes(24, data_p + 0x100, 2, pad))},
            ret=Val(k="i32", v=0)))
        recs.append(Rec(t=REC_CALL, seq=next(q), sym="Tick", tid=tid_b,
                        ret=Val(k="u32", v=pid * 3 + 11)))
        recs.append(Rec(t=REC_CALL, seq=next(q), sym="Close", tid=tid_a,
                        inn={"h": Val(k="handle", v=h)},
                        ret=Val(k="i32", v=0)))
        recs.append(Rec(t=REC_CALL, seq=next(q), sym="Attach", tid=tid_a,
                        inn={"h": Val(k="handle", v=h),
                             "opt": Val(k="ptr", p="0")},
                        ret=Val(k="i32", v=-1)))
        return Trace(header=make_header("oldlib.dll", "x64", label="sc1",
                                        pid=pid, run=f"r{pid:x}"),
                     records=recs, source=f"synthetic-{pid}")

    def val_sig(v: NormVal | None):
        return None if v is None else (v.k, v.v, v.b, v.captured)

    def fingerprint(nt: NormTrace):
        # seq is deliberately excluded: two runs may differ in how many
        # internal calls precede a given one, which is what parent_sym exists
        # to work around.
        return [(r.tid, r.sym, r.depth, r.parent_sym,
                 tuple((k, val_sig(v)) for k, v in sorted(r.inn.items())),
                 tuple((k, val_sig(v)) for k, v in sorted(r.out.items())),
                 val_sig(r.ret), r.lasterr) for r in nt.records]

    con = build_contract()
    # Tick returns a per-process counter; mask it whole, like a real policy
    # would after the determinism check flagged it.
    pol = Policy.derive(con, extra=[MaskRule(sym="Tick", path="ret",
                                             why="free running counter"),
                                    MaskRule(sym="Open", path="lasterr",
                                             why="OS noise")])
    # Exercise the legacy per-thread normalizer explicitly even though strict
    # production policy now requires global ordering.
    pol.thread_mode = "per-thread"

    run_a = build_trace(base_seq=1, h=0x1111, buf_p=0x2000, data_p=0x30000,
                        items_p=0x40000, ctx_p=0x50000, ext_h=0x7777,
                        tid_a=4242, tid_b=777, pad=0xAA, pid=1000)
    run_b = build_trace(base_seq=9001, h=0x9999, buf_p=0x8000, data_p=0x90000,
                        items_p=0xA0000, ctx_p=0xB0000, ext_h=0xDDDD,
                        tid_a=99, tid_b=12345, pad=0xAA, pid=2000)

    na = normalize(run_a, con, pol)
    nb = normalize(run_b, con, pol)

    fa, fb = fingerprint(na), fingerprint(nb)
    if fa != fb:
        for x, y in zip(fa, fb):
            if x != y:
                raise AssertionError(f"diverged:\n  A={x}\n  B={y}")
        raise AssertionError(f"length {len(fa)} != {len(fb)}")
    print(f"identity: {len(fa)} records normalize identically across runs")

    assert na.header == nb.header == {"v": 1, "module": "oldlib.dll",
                                      "arch": "x64", "maxcap": 65536,
                                      "contract": "0" * 64,
                                      "tap": TRACE_TAP_VERSION,
                                      "label": "sc1"}, na.header
    print(f"header: run-local keys dropped -> {na.header}")

    # Symbolization.
    assert na.symbol_table["1111"] == "@h#1", na.symbol_table
    assert nb.symbol_table["9999"] == "@h#1", nb.symbol_table
    assert na.symbol_table["7777"] == "@ext#1", na.symbol_table
    assert list(na.symbol_table.values()) == list(nb.symbol_table.values())
    by_sym = {}
    for r in na.records:
        by_sym.setdefault(r.sym, []).append(r)
    assert by_sym["Open"][0].out["h"].v == "@h#1"
    assert by_sym["Process"][0].inn["h"].v == "@h#1"
    assert by_sym["Attach"][0].inn["h"].v == "@ext#1"
    assert by_sym["Attach"][0].inn["opt"].v == NULL_TOKEN
    assert by_sym["Close"][0].inn["h"].v == "@h#1", "release call stays live"
    assert by_sym["Attach"][1].inn["h"].v == "@h#1!freed", "use after close"
    assert by_sym["Open"][0].inn["name"].v == "data.bin", "string content kept"
    # The buffer pointer is itself an identity: same token in and out. The
    # embedded data pointer is minted next, before cb.
    assert by_sym["Process"][0].inn["buf"].v == "@ext#2"
    assert by_sym["Process"][0].out["buf"].v == "@ext#2"
    assert by_sym["Process"][0].inn["buf"].fields == {"data": "@ext#3"}
    assert by_sym["Process"][0].inn["cb"].v == "@ext#4", "fnptr symbolized"
    print("symbolize: @h#1 / @ext#n / @null / !freed all correct")

    # Masking: pointer bytes 8..16 only. Padding is compared fail-closed.
    hexed = by_sym["Process"][0].inn["buf"].b
    assert len(hexed) == 48
    assert hexed[0:8] == "18000000", hexed
    assert hexed[8:16] == "aa" * 4, hexed
    assert hexed[16:32] == "." * 16, hexed
    assert hexed[32:40] == "07000000", hexed
    assert hexed[40:48] == "aa" * 4, hexed
    assert by_sym["Process"][0].out["buf"].b[32:40] == "0c000000"
    print(f"mask: {hexed}")

    # Tiling across a 2-element array; second element masked at +24.
    items = by_sym["ProcessMany"][0].inn["items"].b
    assert len(items) == 96
    assert items[8:16] == "aa" * 4 and items[16:32] == "." * 16, items
    assert items[40:48] == "aa" * 4, items
    assert items[48:56] == "18000000", items
    assert items[56:64] == "aa" * 4 and items[64:80] == "." * 16, items
    assert items[80:88] == "02000000", items
    assert items[88:96] == "aa" * 4, items
    print(f"tile: {items}")

    # Whole-value masks.
    assert by_sym["Tick"][0].ret.v is None, "whole-value mask clears v"
    assert by_sym["Open"][0].lasterr is None, "lasterr mask drops the field"
    assert by_sym["Process"][0].lasterr is None, "not recorded at all"

    # Coverage bookkeeping: the uncaptured callback ctx, and nothing else.
    assert na.unknown_extent == [("cb_progress", "in.ctx")], na.unknown_extent
    assert na.unknown_extent == nb.unknown_extent
    assert by_sym["cb_progress"][0].inn["ctx"].captured is False
    assert by_sym["Process"][0].inn["buf"].captured is True
    print(f"coverage: unknown_extent={na.unknown_extent}")

    # Callback parenting by symbol name, not seq (run B's seqs are +9000).
    cb_a = by_sym["cb_progress"][0]
    cb_b = [r for r in nb.records if r.sym == "cb_progress"][0]
    assert cb_a.parent_sym == cb_b.parent_sym == "Process"
    assert cb_a.seq != cb_b.seq, "seqs deliberately differ between runs"
    assert by_sym["Open"][0].parent_sym is None
    print(f"callback: parent_sym={cb_a.parent_sym} "
          f"(seq {cb_a.seq} vs {cb_b.seq})")

    # Thread remap: raw ids 4242/777 and 99/12345 both become 0/1.
    assert sorted(na.threads) == sorted(nb.threads) == [0, 1]
    assert [r.sym for r in na.threads[0]] == [r.sym for r in nb.threads[0]]
    assert [r.sym for r in na.threads[1]] == ["ProcessMany", "Tick"]
    print("threads: remapped to first-appearance order 0,1")

    # thread_mode=global collapses to one comparable sequence.
    from dataclasses import replace as _replace
    g = normalize(run_a, con, _replace(pol, thread_mode="global"))
    assert list(g.threads) == [0] and len(g.threads[0]) == len(g.records)

    # ignore_symbols drops records but not symbolizer state.
    ign = normalize(run_a, con, _replace(pol, ignore_symbols=["Tick", "Proc*"]))
    assert [r.sym for r in ign.records] == ["Open", "Attach", "cb_progress",
                                            "Close", "Attach"], \
        [r.sym for r in ign.records]
    assert ign.symbol_table == na.symbol_table, "token numbering unchanged"

    # symbolize_pointers=False erases identity but keeps the freed signal.
    er = normalize(run_a, con, _replace(pol, symbolize_pointers=False))
    er_attach = [r for r in er.records if r.sym == "Attach"]
    assert er_attach[0].inn["h"].v == ERASED_TOKEN
    assert er_attach[1].inn["h"].v == ERASED_TOKEN + FREED_SUFFIX
    assert er_attach[0].inn["opt"].v == NULL_TOKEN
    print("modes: global / ignore_symbols / symbolize_pointers=False ok")

    # Different objects must not normalize to the same shared token.
    bad = build_trace(base_seq=1, h=0x1111, buf_p=0x2000, data_p=0x30000,
                      items_p=0x40000, ctx_p=0x50000, ext_h=0x7777,
                      tid_a=4242, tid_b=777, pad=0xAA, pid=1000)
    bad.records[2].inn["h"] = Val(k="handle", v=0x2222)   # Process(h) aliased
    assert fingerprint(normalize(bad, con, pol)) != fa, \
        "identity break must show up as a diff"
    print("negative: broken handle identity does diverge")

    # A malformed pointer degrades to a warning; trace.Val.is_null would raise.
    torn = normalize(
        Trace(header=make_header("oldlib.dll"),
              records=[Rec(t=REC_CALL, seq=1, sym="Attach",
                           inn={"h": Val(k="ptr", p="")})]), con, pol)
    assert len(torn.records) == 1
    assert torn.records[0].inn["h"].captured is False

    # Whether the allocator reuses an address is run-local, so neither a create
    # over an "@ext" binding nor an in-place realloc may change the tokens.
    rc = Contract(module="oldlib.dll", arch="x64")
    rc.symbols["Alloc"] = SymbolSpec(
        name="Alloc", ret="i32",
        args=[ArgSpec("p", "ptr", dir="out", creates="mem")])
    rc.symbols["Realloc"] = SymbolSpec(
        name="Realloc", ret="i32",
        args=[ArgSpec("old", "ptr", releases="mem"),
              ArgSpec("new", "ptr", dir="out", creates="mem")])
    rc.symbols["Touch"] = SymbolSpec(
        name="Touch", ret="i32", args=[ArgSpec("p", "ptr", symbolize="mem")])
    rpol = Policy.derive(rc)

    def realloc_run(new_p: str) -> list[tuple]:
        recs = [Rec(t=REC_CALL, seq=1, sym="Touch",
                    inn={"p": Val(k="ptr", p="1000")}),
                Rec(t=REC_CALL, seq=2, sym="Alloc",
                    out={"p": Val(k="ptr", p="1000")}),
                Rec(t=REC_CALL, seq=3, sym="Realloc",
                    inn={"old": Val(k="ptr", p="1000")},
                    out={"new": Val(k="ptr", p=new_p)}),
                Rec(t=REC_CALL, seq=4, sym="Touch",
                    inn={"p": Val(k="ptr", p=new_p)})]
        nt = normalize(Trace(header=make_header("oldlib.dll"), records=recs),
                       rc, rpol)
        return [tuple(v.v for _, v in sorted({**r.inn, **r.out}.items()))
                for r in nt.records]

    in_place, moved = realloc_run("1000"), realloc_run("5000")
    assert in_place == moved, (in_place, moved)
    assert in_place == [("@ext#1",), ("@mem#1",), ("@mem#2", "@mem#1"),
                        ("@mem#2",)], in_place
    print(f"reuse: allocator address reuse is invisible -> {in_place}")

    # ---- embedded pointer fields ----------------------------------------
    # BUF.data below also flows through the SAME symbol table as every
    # top-level pointer.
    ec = Contract(module="oldlib.dll", arch="x64")
    ec.structs["BUF"] = StructSpec(
        name="BUF", size=24,
        fields=[FieldSpec("size", 0, 4, "u32"),
                FieldSpec("data", 8, 8, "ptr"),
                FieldSpec("len", 16, 4, "u32")])
    ec.symbols["Alloc"] = SymbolSpec(
        name="Alloc", ret="i32",
        args=[ArgSpec("p", "ptr", dir="out", creates="mem",
                      extent=Extent(unknown=True))])
    ec.symbols["Process"] = SymbolSpec(
        name="Process", ret="i32",
        args=[ArgSpec("buf", "ptr", dir="inout", struct="BUF",
                      extent=Extent(struct="BUF"))])
    ec.symbols["Many"] = SymbolSpec(
        name="Many", ret="i32",
        args=[ArgSpec("items", "ptr", struct="BUF",
                      extent=Extent(arg="n", scale=24)),
              ArgSpec("n", "u32")])
    assert ec.validate() == [
        "Alloc.p: pointer extent is unknown; strict verification cannot observe its bytes"
    ], ec.validate()
    epol = Policy.derive(ec)

    def ebuf(size: int, data_ptr: int, ln: int, pad: int = 0xEE) -> str:
        return (_struct.pack("<I", size) + bytes([pad]) * 4
                + _struct.pack("<Q", data_ptr) + _struct.pack("<I", ln)
                + bytes([pad]) * 4).hex()

    def erecs(mem: int, out_data: int | None = None) -> list[Rec]:
        return [
            Rec(t=REC_CALL, seq=1, sym="Alloc",
                out={"p": Val(k="ptr", p=format(mem, "x"))},
                ret=Val(k="i32", v=0)),
            Rec(t=REC_CALL, seq=2, sym="Process",
                inn={"buf": Val(k="ptr", p=format(mem + 0x9000, "x"), n=24,
                                b=ebuf(24, mem, 5))},
                out={"buf": Val(k="ptr", p=format(mem + 0x9000, "x"), n=24,
                                b=ebuf(24, mem if out_data is None
                                       else out_data, 5))},
                ret=Val(k="i32", v=0)),
            # Two-element array; the second element's pointer is NULL.
            Rec(t=REC_CALL, seq=3, sym="Many",
                inn={"items": Val(k="ptr", p=format(mem + 0xA000, "x"), n=48,
                                  b=ebuf(24, mem, 5) + ebuf(24, 0, 0)),
                     "n": Val(k="u32", v=2)},
                ret=Val(k="i32", v=0)),
            # size_field says 8, so the capture stops before `data`.
            Rec(t=REC_CALL, seq=4, sym="Process",
                inn={"buf": Val(k="ptr", p=format(mem + 0xB000, "x"), n=8,
                                b=ebuf(24, mem, 5)[:16])},
                ret=Val(k="i32", v=-1)),
        ]

    def enorm(mem: int, out_data: int | None = None,
              policy: Policy | None = None) -> NormTrace:
        return normalize(Trace(header=make_header("oldlib.dll"),
                               records=erecs(mem, out_data)),
                         ec, policy or epol)

    ea, eb = enorm(0x30000), enorm(0x770000)
    assert fingerprint(ea) == fingerprint(eb), "addresses must not leak"
    e_by = {}
    for r in ea.records:
        e_by.setdefault(r.sym, []).append(r)

    # THE point of the shared table: the address minted by a top-level out
    # argument is recognised as the same object when it turns up inside a
    # struct, in and out.
    assert e_by["Alloc"][0].out["p"].v == "@mem#1"
    assert e_by["Process"][0].inn["buf"].fields == {"data": "@mem#1"}
    assert e_by["Process"][0].out["buf"].fields == {"data": "@mem#1"}
    assert e_by["Process"][0].inn["buf"].v == "@ext#1", "the struct itself"
    print(f"fields: top-level {e_by['Alloc'][0].out['p'].v} == embedded "
          f"{e_by['Process'][0].inn['buf'].fields['data']}")

    # The bytes those tokens came from are masked, so byte comparison alone
    # can never see the pointer -- which is exactly why the tokens exist.
    hexed = e_by["Process"][0].inn["buf"].b
    assert hexed[16:32] == "." * 16, hexed
    assert hexed[0:8] == "18000000" and hexed[32:40] == "05000000", hexed

    # Tiling: one key per element, NULL stays @null.
    assert e_by["Many"][0].inn["items"].fields == {"data[0]": "@mem#1",
                                                   "data[1]": NULL_TOKEN}
    tiled = e_by["Many"][0].inn["items"].b
    assert tiled[16:32] == "." * 16 and tiled[64:80] == "." * 16, tiled
    print(f"fields: array -> {e_by['Many'][0].inn['items'].fields}")

    # Truncated capture: no silent absence, a coverage debit instead.
    assert e_by["Process"][1].inn["buf"].fields is None
    assert ("Process", "in.buf.data") in ea.unknown_extent, ea.unknown_extent
    assert ea.unknown_extent == eb.unknown_extent
    print(f"fields: truncated capture -> unknown_extent {ea.unknown_extent}")

    # A wrong-but-readable pointer in the out struct: identical bytes after
    # masking, different token. Byte comparison cannot see this; the field can.
    wrong = enorm(0x30000, out_data=0x30000 + 0x4000)
    w_proc = [r for r in wrong.records if r.sym == "Process"][0]
    ok_proc = e_by["Process"][0]
    assert w_proc.out["buf"].b == ok_proc.out["buf"].b, "bytes agree"
    assert w_proc.out["buf"].fields != ok_proc.out["buf"].fields
    print(f"fields: wrong pointer, same bytes -> "
          f"{ok_proc.out['buf'].fields} vs {w_proc.out['buf'].fields}")

    # A fully masked value mints nothing, embedded pointers included.
    masked = enorm(0x30000, policy=epol.merged_with(
        [MaskRule(sym="Process", path="in.buf", why="whole value")]))
    m_proc = [r for r in masked.records if r.sym == "Process"][0]
    assert m_proc.inn["buf"].v is None and m_proc.inn["buf"].fields is None

    # An undeclared struct is never guessed at: no fields, no tokens minted.
    gc = Contract(module="oldlib.dll", arch="x64")
    gc.symbols["Process"] = SymbolSpec(
        name="Process", ret="i32",
        args=[ArgSpec("buf", "ptr", dir="in", struct="GHOST")])
    ghost = normalize(
        Trace(header=make_header("oldlib.dll"),
              records=[Rec(t=REC_CALL, seq=1, sym="Process",
                           inn={"buf": Val(k="ptr", p="7000", n=24,
                                           b=ebuf(24, 0x30000, 5))})]),
        gc, Policy.derive(gc))
    assert ghost.records[0].inn["buf"].fields is None
    assert list(ghost.symbol_table) == ["7000"], ghost.symbol_table
    print("fields: undeclared struct mints nothing")

    # ---- pointer WIDTH, both directions ---------------------------------
    # The read has to be the field's declared size, not Contract.ptr_size. A
    # 32-bit pointer field in an x64 struct is a real shape, and reading 8
    # bytes there folds the next (compared) field into the token, which both
    # invents divergences and -- the expensive half -- breaks the link to the
    # top-level token, silently switching the check back off.
    wc = Contract(module="oldlib.dll", arch="x64")
    wc.structs["W"] = StructSpec(
        name="W", size=16,
        fields=[FieldSpec("p32", 0, 4, "ptr"),
                FieldSpec("seqno", 4, 4, "u32"),
                FieldSpec("n", 8, 8, "u64")])
    wc.symbols["Alloc"] = SymbolSpec(
        name="Alloc", ret="i32",
        args=[ArgSpec("p", "ptr", dir="out", creates="mem",
                      extent=Extent(unknown=True))])
    wc.symbols["Use"] = SymbolSpec(
        name="Use", ret="i32",
        args=[ArgSpec("s", "ptr", struct="W", extent=Extent(struct="W"))])
    assert set(wc.validate()) == {
        "W.p32: pointer field size 4 != x64 pointer size 8",
        "Alloc.p: pointer extent is unknown; strict verification cannot observe its bytes",
    }, wc.validate()
    wpol = Policy.derive(wc)
    assert wpol.masks_for("Use", "in.s")[0].byte_ranges == [(0, 4)]

    def wrun(ptr: int, seqno: int) -> NormTrace:
        body = (_struct.pack("<I", ptr) + _struct.pack("<I", seqno)
                + _struct.pack("<Q", 1)).hex()
        return normalize(
            Trace(header=make_header("oldlib.dll"),
                  records=[Rec(t=REC_CALL, seq=1, sym="Alloc",
                               out={"p": Val(k="ptr", p="401000")}),
                           Rec(t=REC_CALL, seq=2, sym="Use",
                               inn={"s": Val(k="ptr", p="7000", n=16,
                                             b=body)})]),
            wc, wpol)

    assert wrun(0x401000, 7).records[1].inn["s"].fields == {"p32": "@mem#1"}, \
        wrun(0x401000, 7).records[1].inn["s"].fields
    # The neighbour must not reach the token, and a wrong pointer must still
    # break the identity link rather than reading as another external object.
    assert wrun(0x401000, 7).records[1].inn["s"].fields == \
        wrun(0x401000, 99).records[1].inn["s"].fields
    assert wrun(0x405000, 7).records[1].inn["s"].fields == {"p32": "@ext#2"}
    print("fields: 32-bit pointer field in an x64 struct stays linked")

    # x86: the recorder sign extends pointer-shaped scalars, the struct field
    # is 4 unsigned bytes. Both have to land on ONE table entry.
    xc = Contract(module="oldlib.dll", arch="x86")
    xc.structs["X"] = StructSpec(
        name="X", size=12,
        fields=[FieldSpec("size", 0, 4, "u32"),
                FieldSpec("data", 4, 4, "ptr"),
                FieldSpec("len", 8, 4, "u32")])
    xc.symbols["Touch"] = SymbolSpec(
        name="Touch", ret="i32", args=[ArgSpec("h", "handle", symbolize="mem")])
    xc.symbols["Use"] = SymbolSpec(
        name="Use", ret="i32",
        args=[ArgSpec("s", "ptr", struct="X", extent=Extent(struct="X"))])
    assert xc.validate() == [], xc.validate()
    xbody = (_struct.pack("<I", 12) + _struct.pack("<I", 0x80001234)
             + _struct.pack("<I", 5)).hex()
    xnt = normalize(
        Trace(header=make_header("oldlib.dll", "x86"),
              records=[Rec(t=REC_CALL, seq=1, sym="Touch",
                           inn={"h": Val(k="handle", v=-0x7FFFEDCC)}),
                       Rec(t=REC_CALL, seq=2, sym="Use",
                           inn={"s": Val(k="ptr", p="7000", n=12, b=xbody)})]),
        xc, Policy.derive(xc))
    assert xnt.records[0].inn["h"].v == "@ext#1", xnt.symbol_table
    assert xnt.records[1].inn["s"].fields == {"data": "@ext#1"}, \
        (xnt.records[1].inn["s"].fields, xnt.symbol_table)
    print(f"fields: x86 sign-extended arg == embedded field "
          f"({xnt.records[0].inn['h'].v})")

    print("normalize.py self-test PASS")
