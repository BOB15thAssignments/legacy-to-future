"""Generate a deterministic replay driver from a contract and trace.

The generated header contains recorded inputs and typed call thunks. Runtime
values created by the target are stored in slots and substituted into later
calls, so replay does not depend on process-specific handle values.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .model import POINTER_KINDS, ArgSpec, CallbackSpec, Contract, SymbolSpec
from .gen_tap import contract_hash
from .trace import (REC_CALLBACK, Rec, Trace, Val,
                    validate_trace_contract)

logger = logging.getLogger(__name__)

# Past this many bytes the blob goes to a companion file instead of a C
# literal; multi-megabyte initialisers make clang crawl for no benefit.
EMBED_LIMIT = 64 * 1024

# Mirrors the stack arrays in replay_main.c.
MAX_ARGS = 32
MAX_REPLAY_BUFFER = 256 * 1024 * 1024

GEN_HEADER = "replay_gen.h"
BLOB_FILE = "replay_blob.bin"
ENGINE_FILE = "replay_main.c"

# Symbolic names, not integers: gen_replay and replay_main disagreeing about
# an enum ordering then fails to compile instead of mis-decoding a table.
_KIND_ENUM = {
    "void": "RP_K_VOID", "bool": "RP_K_BOOL",
    "i8": "RP_K_I8", "u8": "RP_K_U8", "i16": "RP_K_I16", "u16": "RP_K_U16",
    "i32": "RP_K_I32", "u32": "RP_K_U32", "i64": "RP_K_I64", "u64": "RP_K_U64",
    "f32": "RP_K_F32", "f64": "RP_K_F64",
    "ptr": "RP_K_PTR", "str": "RP_K_STR", "wstr": "RP_K_WSTR",
    "handle": "RP_K_HANDLE", "fnptr": "RP_K_FNPTR", "blob": "RP_K_BLOB",
}
_DIR_ENUM = {"in": "RP_D_IN", "out": "RP_D_OUT", "inout": "RP_D_INOUT"}

# Passing class: how the engine materialises the recorded value into the
# actual argument slot.
PASS_SCALAR = "RP_P_SCALAR"
PASS_FLOAT = "RP_P_FLOAT"
PASS_PTRVAL = "RP_P_PTRVAL"
PASS_BUFFER = "RP_P_BUFFER"
PASS_REF = "RP_P_REF"
PASS_CB = "RP_P_CB"

_C_SCALAR = {
    "bool": "int", "i8": "signed char", "u8": "unsigned char",
    "i16": "short", "u16": "unsigned short",
    "i32": "int", "u32": "unsigned int",
    "i64": "long long", "u64": "unsigned long long",
    "f32": "float", "f64": "double",
}
_C_CC = {"cdecl": "__cdecl", "stdcall": "__stdcall", "fastcall": "__fastcall",
         "thiscall": "__thiscall", "win64": ""}

_BUFFER_KINDS = ("ptr", "str", "wstr", "blob")


class ReplayError(ValueError):
    """Raised when a trace cannot be turned into a driver at all."""


@dataclass
class ReplayArg:
    """One argument of one recorded call, resolved for re-execution."""

    name: str
    kind: str
    dir: str
    pcls: str = PASS_SCALAR
    ival: int = 0
    fval: float = 0.0
    is_null: bool = False
    slot: int = -1              # substitute the live value of this slot
    creates: int = -1           # bind this slot from the live value
    cb: int = -1                # index into the callback table
    in_len: int = -1
    in_off: int = 0
    in_captured: bool = False
    out_len: int = -1


@dataclass
class ReplayRec:
    seq: int
    tid: int
    sym: str
    symi: int
    is_cb: bool
    parent: int
    args: list[ReplayArg] = field(default_factory=list)
    kids: list[int] = field(default_factory=list)
    has_ret: bool = False
    ret_kind: str = "void"
    ret_i: int = 0
    ret_f: float = 0.0
    ret_slot: int = -1
    has_lasterr: bool = False
    lasterr: int = 0
    skip: str = ""


@dataclass
class ReplayPlan:
    contract: Contract
    tid: int
    label: str
    syms: list[SymbolSpec] = field(default_factory=list)
    cbs: list[CallbackSpec] = field(default_factory=list)
    recs: list[ReplayRec] = field(default_factory=list)
    blob: bytearray = field(default_factory=bytearray)
    nslots: int = 0
    skipped_tids: list[int] = field(default_factory=list)
    plan_incomplete: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def calls(self) -> list[ReplayRec]:
        return [r for r in self.recs if not r.is_cb]

    @property
    def skipped(self) -> list[ReplayRec]:
        return [r for r in self.recs if r.skip]


def generate_replay(contract: Contract, trace: Trace,
                    out_dir: str | Path) -> dict[str, str]:
    """Emit a replay driver for `trace` under `out_dir`.

    Returns {logical name: written path}, matching gen_tap's convention.
    `replay_main.c` is copied next to the generated header so the output
    directory builds on its own (it still needs `-I` at the tap runtime for
    `tr_record.h`).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    plan = plan_replay(contract, trace)

    external = len(plan.blob) > EMBED_LIMIT
    written: dict[str, str] = {}

    header = out / GEN_HEADER
    header.write_text(render_header(plan, external=external),
                      encoding="ascii", newline="\n")
    written[GEN_HEADER] = str(header)

    if external:
        blob = out / BLOB_FILE
        blob.write_bytes(bytes(plan.blob))
        written[BLOB_FILE] = str(blob)

    engine_src = Path(__file__).parent / "runtime" / ENGINE_FILE
    if engine_src.is_file():
        engine_dst = out / ENGINE_FILE
        shutil.copyfile(engine_src, engine_dst)
        written[ENGINE_FILE] = str(engine_dst)
    else:  # a source tree missing its own runtime is a packaging bug
        logger.error("runtime/%s not found at %s", ENGINE_FILE, engine_src)

    logger.info("replay driver: %d calls (%d skipped), %d callbacks, "
                "%d slots, %d blob bytes%s",
                len(plan.calls), len(plan.skipped),
                sum(1 for r in plan.recs if r.is_cb), plan.nslots,
                len(plan.blob), " (external)" if external else "")
    for note in plan.notes:
        logger.warning("%s", note)
    return written


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------

class _Slots:
    """Mint/resolve symbol slots in recorded seq order."""

    def __init__(self) -> None:
        self._mints: dict[int, list[tuple[int, int]]] = {}
        self.classes: list[str] = []

    @property
    def n(self) -> int:
        return len(self.classes)

    def mint(self, raw: int | None, seq: int, cls: str | None) -> int:
        # NULL is not an object; minting it would bind every later NULL to a
        # live handle. Mirrors normalize.py's @null rule.
        if not raw:
            return -1
        idx = len(self.classes)
        self.classes.append(cls or "obj")
        self._mints.setdefault(raw, []).append((seq, idx))
        return idx

    def resolve(self, raw: int | None, seq: int) -> int:
        if not raw:
            return -1
        found = -1
        for mint_seq, idx in self._mints.get(raw, ()):
            if mint_seq >= seq:
                break
            found = idx
        return found


def _raw_of(val: Val | None) -> int | None:
    """The value's identity as an integer, or None if it has none."""
    if val is None:
        return None
    if val.p is not None:
        try:
            return int(val.p, 16)
        except ValueError:
            return None
    if isinstance(val.v, bool) or not isinstance(val.v, int):
        return None
    return val.v


def _is_opaque(a: ArgSpec) -> bool:
    """True when the argument is a token, not a buffer.

    A `ptr` that carries a symbol class but no recordable extent is an opaque
    cookie the DLL handed out, so it takes slot substitution rather than
    byte reconstruction.

    An `in` pointer whose extent the contract declares `unknown` is a token
    for the same reason even without a symbol class: the tap records its
    value and deliberately no bytes (SPEC: "Symbols with Extent(unknown=True)
    still get a thunk but pass nbytes<0"), so there is nothing to reconstruct
    and the recorded value is all anyone ever had. Treating it as a buffer
    instead drops the whole record, which for an `Init(tag, reserved)` shaped
    symbol leaves every later call running against an uninitialised library.
    Only `in` qualifies: an out/inout cell is written by the callee and still
    needs storage.
    """
    if a.kind in ("handle", "fnptr"):
        return True
    if a.kind != "ptr" or a.records_bytes:
        return False
    return bool(a.symbolize or a.releases
                or (a.dir == "in" and a.extent is not None and a.extent.unknown))


def _pass_class(a: ArgSpec) -> str:
    if a.callback:
        return PASS_CB
    opaque = _is_opaque(a)
    if a.kind in _BUFFER_KINDS and not opaque:
        return PASS_BUFFER
    if a.dir in ("out", "inout"):
        return PASS_REF          # scalar/token out params are T*, not T
    if a.kind in ("f32", "f64"):
        return PASS_FLOAT
    return PASS_PTRVAL if opaque else PASS_SCALAR


def _encode_text(kind: str, s: str) -> bytes:
    return (s.encode("utf-16-le") + b"\0\0" if kind == "wstr"
            else s.encode("utf-8", "surrogatepass") + b"\0")


def _is_null(val: Val | None) -> bool:
    """`Val.is_null` without the ValueError a malformed pointer raises."""
    if val is None or val.p is None:
        return False
    try:
        return int(val.p, 16) == 0
    except ValueError:
        return False


def _decode(val: Val) -> bytes | None:
    """Captured bytes, or None when the hex is unusable.

    A torn or hand-edited trace can carry an odd-length or non-hex `b`.
    `Val.raw_bytes()` raises on it, which would abort the whole generation
    with a message naming no record; the caller turns None into a skip.
    """
    if val.b is None or len(val.b) % 2:
        return None
    try:
        return val.raw_bytes()
    except ValueError:
        return None


def _val_len(val: Val | None) -> int:
    """Bytes the recorder actually kept, or -1 when it did not look."""
    if val is None or _is_null(val):
        return -1
    if val.b is not None:
        return -1 if len(val.b) % 2 else len(val.b) // 2
    if val.n is not None and val.n > 0:
        return val.n
    return -1


def _extent_len(val: Val | None) -> int:
    """Bytes the callee is entitled to touch.

    `Val.n` is what the recorder ATTEMPTED (trace.py), which exceeds what it
    kept whenever TAP_MAXCAP clamped the capture or the tail was unreadable.
    The callee still writes the whole extent, so the replay buffer has to be
    sized from `n`; sizing it from the surviving bytes lets a correct shim
    run off the end of the driver's allocation.
    """
    if val is None or _is_null(val):
        return -1
    n = val.n if val.n is not None and val.n > 0 else -1
    return max(_val_len(val), n)


class _Planner:
    def __init__(self, contract: Contract) -> None:
        self.contract = contract
        self.slots = _Slots()
        self.blob = bytearray()
        self._blob_index: dict[bytes, int] = {}
        self.syms: list[SymbolSpec] = []
        self._sym_index: dict[str, int] = {}
        self.cbs: list[CallbackSpec] = []
        self._cb_index: dict[str, int] = {}
        self.notes: list[str] = []

    # -- tables ------------------------------------------------------------

    def blob_add(self, data: bytes) -> int:
        hit = self._blob_index.get(data)
        if hit is not None:
            return hit
        off = len(self.blob)
        self.blob += data
        self._blob_index[data] = off
        return off

    def sym_index(self, name: str) -> int:
        if name in self._sym_index:
            return self._sym_index[name]
        spec = self.contract.symbols.get(name)
        if spec is None:
            return -1
        if len(spec.args) > MAX_ARGS:
            raise ReplayError(
                f"{name} has {len(spec.args)} args, driver cap is {MAX_ARGS}")
        self._sym_index[name] = len(self.syms)
        self.syms.append(spec)
        return self._sym_index[name]

    def cb_index(self, name: str) -> int:
        if name in self._cb_index:
            return self._cb_index[name]
        spec = self.contract.callbacks.get(name)
        if spec is None:
            return -1
        if len(spec.args) > MAX_ARGS:
            raise ReplayError(
                f"callback {name} has {len(spec.args)} args, cap is {MAX_ARGS}")
        self._cb_index[name] = len(self.cbs)
        self.cbs.append(spec)
        return self._cb_index[name]

    # -- per argument ------------------------------------------------------

    def plan_arg(self, rec: Rec, a: ArgSpec, skips: list[str]) -> ReplayArg:
        pa = ReplayArg(name=a.name, kind=a.kind, dir=a.dir, pcls=_pass_class(a))
        in_val = rec.inn.get(a.name)
        out_val = rec.out.get(a.name)

        if pa.pcls == PASS_CB:
            pa.cb = self.cb_index(a.callback or "")
            if pa.cb < 0:
                skips.append(f"callback '{a.callback}' missing from contract")
            return pa

        if pa.pcls == PASS_BUFFER:
            self._plan_buffer(rec, a, pa, in_val, out_val, skips)
            return pa

        # Token or scalar. The recorded input decides what we pass in; the
        # recorded output only matters for slot binding.
        ref = in_val if a.is_in else out_val
        raw = _raw_of(ref)
        if a.kind in ("f32", "f64"):
            pa.fval = float(ref.v) if ref is not None and ref.v is not None else 0.0
        else:
            pa.ival = raw if raw is not None else 0
        if a.is_in and in_val is None:
            skips.append(f"no recorded input for '{a.name}'")
        # Identity is a property of the contract, not of the C type:
        # normalize.py symbolizes every arg declaring symbolize/creates/
        # releases whatever its kind, so a u64 that carries a handle has to be
        # substituted too. Passing the recorded integer through hands the shim
        # a token it never issued, and the resulting rejection reads as the
        # shim's fault.
        identity = bool(a.symbolize or a.creates or a.releases)
        if a.is_in and (pa.pcls in (PASS_PTRVAL, PASS_REF)
                        or (pa.pcls == PASS_SCALAR and identity)):
            pa.slot = self.slots.resolve(raw, rec.seq)
        if pa.pcls == PASS_REF and _is_null(out_val):
            pa.is_null = True
        return pa

    def _plan_buffer(self, rec: Rec, a: ArgSpec, pa: ReplayArg,
                     in_val: Val | None, out_val: Val | None,
                     skips: list[str]) -> None:
        ref = in_val if in_val is not None else out_val
        if _is_null(ref):
            pa.is_null = True
            return

        if a.is_in:
            data = None if in_val is None else _decode(in_val)
            if in_val is None:
                skips.append(f"no recorded input for '{a.name}'")
            elif a.kind in ("str", "wstr") and isinstance(in_val.v, str):
                data = _encode_text(a.kind, in_val.v)
                pa.in_len = len(data)
                pa.in_captured = True
                if len(data) > MAX_REPLAY_BUFFER:
                    skips.append(
                        f"'{a.name}' input is {len(data)} bytes, above the "
                        f"{MAX_REPLAY_BUFFER}-byte replay safety cap")
                else:
                    pa.in_off = self.blob_add(data)
            elif in_val.b is not None and data is None:
                skips.append(
                    f"'{a.name}' has {len(in_val.b)} hex digits the recorder "
                    f"cannot have written; the trace is corrupt here")
            elif data is not None:
                pa.in_len = len(data)
                pa.in_captured = True
                if len(data) > MAX_REPLAY_BUFFER:
                    skips.append(
                        f"'{a.name}' input is {len(data)} bytes, above the "
                        f"{MAX_REPLAY_BUFFER}-byte replay safety cap")
                else:
                    pa.in_off = self.blob_add(data)
                    stale = self._dangling_field(a, data)
                    if stale:
                        skips.append(
                            f"'{a.name}' holds struct field "
                            f"'{a.struct}.{stale}', a pointer into the "
                            "recorded process that nothing in the trace "
                            "describes")
                    elif in_val.n is not None and in_val.n > len(data):
                        # The tap notes this as a TAP_MAXCAP truncation or an
                        # unreadable tail. Either way the input is incomplete
                        # and calling with the surviving prefix asks a question
                        # the recording never asked.
                        skips.append(
                            f"'{a.name}' capture is short: {in_val.n} bytes "
                            f"attempted, {len(data)} recorded")
            else:
                # No bytes and no way to derive them. Fabricating input would
                # make the shim answer a question nobody asked, so the whole
                # record is dropped and the driver says so at runtime.
                why = ("contract marks extent unknown"
                       if a.extent is not None and a.extent.unknown
                       else "recorder captured no bytes")
                skips.append(f"unknown-extent input '{a.name}' ({why})")

        if a.is_out:
            # The attempted extent, not the surviving bytes: the buffer has to
            # hold everything the callee writes.
            pa.out_len = _extent_len(out_val)
            if pa.out_len < 0 and pa.in_len > 0:
                pa.out_len = pa.in_len
            if pa.out_len < 0 and a.creates:
                # A creating out param is a cell holding one pointer; that
                # size comes from the contract, not from guessed content.
                pa.out_len = self.contract.ptr_size
            if pa.out_len < 0:
                skips.append(f"unknown-extent output '{a.name}'")
            elif pa.out_len > MAX_REPLAY_BUFFER:
                skips.append(
                    f"'{a.name}' output is {pa.out_len} bytes, above the "
                    f"{MAX_REPLAY_BUFFER}-byte replay safety cap")

    # -- per record --------------------------------------------------------

    def plan_call(self, rec: Rec) -> ReplayRec:
        spec = self.contract.symbols.get(rec.sym)
        out = ReplayRec(seq=rec.seq, tid=rec.tid, sym=rec.sym,
                        symi=self.sym_index(rec.sym), is_cb=False,
                        parent=-1)
        if spec is None or out.symi < 0:
            out.skip = "symbol not declared in the contract"
            return out

        skips: list[str] = []
        out.args = [self.plan_arg(rec, a, skips) for a in spec.args]
        if spec.ret != "void":
            out.ret_kind = spec.ret
            if rec.ret is None:
                skips.append(
                    f"contract returns {spec.ret} but the trace has no "
                    "return value")
            else:
                out.has_ret = True
                if spec.ret in ("f32", "f64"):
                    out.ret_f = float(rec.ret.v or 0.0)
                else:
                    out.ret_i = _raw_of(rec.ret) or 0
        if rec.lasterr is not None:
            out.has_lasterr = True
            out.lasterr = int(rec.lasterr)
        if skips:
            out.skip = "; ".join(skips)
        return out

    def bind_creates(self, rec: Rec, planned: ReplayRec) -> None:
        """Mint slots for whatever this record produced.

        Runs after the record's callbacks are planned, matching the runtime
        order: a handle only exists once the creating call has returned.
        """
        spec = self.contract.symbols.get(rec.sym)
        if spec is None:
            return
        for a, pa in zip(spec.args, planned.args):
            if not a.creates:
                continue
            out_val = rec.out.get(a.name)
            # A creating buffer arg is a cell: the new object is what the
            # cell holds, not the address of the cell itself.
            raw = (self._raw_from_bytes(out_val) if pa.pcls == PASS_BUFFER
                   else _raw_of(out_val))
            pa.creates = self.slots.mint(raw, rec.seq, a.creates)
            if pa.creates < 0 and not planned.skip:
                planned.skip = (
                    f"creates='{a.creates}' output '{a.name}' has no usable "
                    "recorded value")
        if spec.ret_creates and planned.has_ret:
            planned.ret_slot = self.slots.mint(
                planned.ret_i, rec.seq, spec.ret_creates)

    def _dangling_field(self, a: ArgSpec, data: bytes) -> str | None:
        """Name of a recorded struct field replay must not hand to the shim.

        Captured struct bytes carry raw addresses from the process that was
        recorded, and nothing in the trace says what they pointed at. Passing
        one on is passing a pointer from a dead address space: the callee
        dereferences it and the driver dies, taking every later record with
        it. A field that was NULL is harmless and stays.

        Checked at every struct-sized stride so an array of structs is
        covered, and only inside the bytes the recorder actually captured.
        """
        st = self.contract.structs.get(a.struct or "")
        if st is None or st.size <= 0:
            return None
        psize = self.contract.ptr_size
        for base in range(0, len(data), st.size):
            for f in st.fields:
                if f.kind not in POINTER_KINDS or f.size != psize:
                    continue
                lo = base + f.off
                if lo + psize <= len(data) and int.from_bytes(
                        data[lo:lo + psize], "little"):
                    return f.name
        return None

    def _raw_from_bytes(self, val: Val | None) -> int | None:
        """A creating out param logged as bytes holds the pointer inline."""
        if val is None:
            return None
        raw = _decode(val)
        if raw is None:
            return None
        data = raw[:self.contract.ptr_size]
        return int.from_bytes(data, "little") if data else None

    def plan_callback(self, rec: Rec, parent_seq: int) -> ReplayRec:
        idx = self.cb_index(rec.sym)
        out = ReplayRec(seq=rec.seq, tid=rec.tid, sym=rec.sym, symi=idx,
                        is_cb=True, parent=parent_seq)
        spec = self.contract.callbacks.get(rec.sym)
        if spec is None:
            out.skip = "callback not declared in the contract"
            self.notes.append(
                f"seq {rec.seq}: callback '{rec.sym}' is not in the contract, "
                f"its invocation cannot be checked")
            return out

        # Expected values only -- nothing is passed in, the DLL supplies the
        # arguments and the engine compares them. An unreconstructible value
        # makes validation incomplete, so retain the record for diagnostics
        # but mark the plan non-passing.
        unreconstructible: list[str] = []
        for a in spec.args:
            out.args.append(self.plan_arg(rec, a, unreconstructible))
        if unreconstructible:
            out.skip = "; ".join(unreconstructible)
        if spec.ret != "void":
            out.ret_kind = spec.ret
            out.has_ret = True
            if rec.ret is not None:
                if spec.ret in ("f32", "f64"):
                    out.ret_f = float(rec.ret.v or 0.0)
                else:
                    out.ret_i = _raw_of(rec.ret) or 0
        return out


def plan_replay(contract: Contract, trace: Trace) -> ReplayPlan:
    """Resolve complete, contract-conformant evidence for one thread.

    Replay is downstream of verification input parsing, so it must not try to
    make a useful best-effort driver from a damaged prefix.  Doing so makes a
    crash, recorder note, or partial capture look like a smaller passing test.
    """
    contract_problems = contract.validate()
    if contract_problems:
        raise ReplayError(
            "contract is not approval-safe:\n  "
            + "\n  ".join(contract_problems))

    if not trace.valid:
        reasons = list(trace.validation_errors)
        if not trace.complete:
            reasons.append("normal-completion footer was not observed")
        raise ReplayError(
            "trace is invalid or incomplete:\n  "
            + "\n  ".join(dict.fromkeys(reasons or ["unknown trace defect"])))

    conformance = validate_trace_contract(trace, contract)
    if conformance:
        raise ReplayError(
            "trace is not complete evidence for this contract:\n  "
            + "\n  ".join(conformance))

    calls = [r for r in trace.records if r.is_call]
    if not calls:
        raise ReplayError("trace has no call records")

    tops = [r for r in calls if r.t != REC_CALLBACK]
    if not tops:
        raise ReplayError("trace has only callback records")
    tid = tops[0].tid
    skipped_tids = sorted({r.tid for r in tops if r.tid != tid})

    kids_by_parent: dict[int, list[Rec]] = {}
    for r in calls:
        if r.t == REC_CALLBACK and r.parent is not None:
            kids_by_parent.setdefault(r.parent, []).append(r)
    for lst in kids_by_parent.values():
        lst.sort(key=lambda r: r.seq)

    pl = _Planner(contract)
    plan = ReplayPlan(contract=contract, tid=tid,
                      label=str(trace.header.get("label", "") or "replay"),
                      skipped_tids=skipped_tids)

    for rec in sorted((r for r in tops if r.tid == tid), key=lambda r: r.seq):
        planned = pl.plan_call(rec)
        plan.recs.append(planned)
        for kid in kids_by_parent.get(rec.seq, ()):
            planned.kids.append(len(plan.recs))
            plan.recs.append(pl.plan_callback(kid, rec.seq))
        pl.bind_creates(rec, planned)

    plan.syms = pl.syms
    plan.cbs = pl.cbs
    plan.blob = pl.blob
    plan.nslots = pl.slots.n
    plan.notes = pl.notes

    planned_seqs = {r.seq for r in plan.recs}
    unplanned_callbacks = sorted(
        r.seq for r in calls
        if r.t == REC_CALLBACK and r.tid == tid and r.seq not in planned_seqs)
    if unplanned_callbacks:
        msg = (f"{len(unplanned_callbacks)} callback record(s) on replayed "
               f"thread are orphaned or nested beyond the replay plan: "
               f"{unplanned_callbacks}")
        plan.plan_incomplete.append(msg)
        plan.notes.append(msg)

    if skipped_tids:
        plan.notes.append(
            f"dropped {len(skipped_tids)} non-replayed thread(s): "
            f"{skipped_tids}")
    return plan


# --------------------------------------------------------------------------
# C rendering
# --------------------------------------------------------------------------

def _cs(s: str | None) -> str:
    # Octal, not hex: a C hex escape has no length limit, so "\xc3\xa9" + "1"
    # parses as \xa91 and the header fails to compile. Octal stops at three
    # digits, which makes every escape self terminating.
    if s is None:
        return "NULL"
    out = ['"']
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            out.append("".join(f"\\{b:03o}" for b in ch.encode("utf-8")))
    out.append('"')
    return "".join(out)


def _comment(s: str) -> str:
    """Text safe inside the generated header's banner comment.

    The header is written as ASCII, and a stray `*/` would close the comment
    early and spill the rest of the line into the translation unit.
    """
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?"
                   for c in s).replace("*/", "*_/")


def _cf(x: float) -> str:
    if x != x or x in (float("inf"), float("-inf")):
        # No portable literal; the differ sees the recorded value anyway.
        return "0.0"
    return repr(float(x))


def _ci(x: int) -> str:
    # Recorded pointers on x64 exceed the signed range; keep the bit pattern
    # and let the LL cast wrap it.
    if x >= 1 << 63:
        x -= 1 << 64
    return f"{x}LL"


def _c_type(kind: str) -> str:
    return _C_SCALAR.get(kind, "void *")


def _ptr_to(t: str) -> str:
    return t + "*" if t.endswith("*") else t + " *"


def _param_type(pa: ReplayArg) -> str:
    if pa.pcls in (PASS_BUFFER, PASS_CB, PASS_PTRVAL):
        return "void *"
    if pa.pcls == PASS_REF:
        return _ptr_to(_c_type(pa.kind))
    return _c_type(pa.kind)


def _ret_type(kind: str) -> str:
    if kind == "void":
        return "void"
    return _c_type(kind)


def _arg_expr(pa: ReplayArg, i: int) -> str:
    t = _param_type(pa)
    if pa.pcls in (PASS_BUFFER, PASS_CB, PASS_PTRVAL, PASS_REF):
        return f"({t})a[{i}].p"
    if pa.pcls == PASS_FLOAT:
        return f"({t})a[{i}].f"
    return f"({t})a[{i}].i"


def _spec_args_as_replay(args: list[ArgSpec]) -> list[ReplayArg]:
    """Type-only view of a signature, for prototypes and thunks."""
    return [ReplayArg(name=a.name, kind=a.kind, dir=a.dir, pcls=_pass_class(a))
            for a in args]


def _arg_init(pa: ReplayArg) -> str:
    return ("{ .name = %s, .kindname = %s, .kind = %s, .dir = %s, .pass = %s, "
            ".is_null = %d, .slot = %d, .creates = %d, .cb = %d, "
            ".ival = %s, .fval = %s, .in_len = %s, .out_len = %s, "
            ".in_off = %du, .in_captured = %d }" % (
                _cs(pa.name), _cs(pa.kind), _KIND_ENUM[pa.kind],
                _DIR_ENUM[pa.dir], pa.pcls, int(pa.is_null), pa.slot,
                pa.creates, pa.cb, _ci(pa.ival), _cf(pa.fval),
                _ci(pa.in_len), _ci(pa.out_len), pa.in_off,
                int(pa.in_captured)))


def _invoke_thunk(idx: int, spec: SymbolSpec) -> list[str]:
    view = _spec_args_as_replay(spec.args)
    cc = _C_CC.get(spec.cc, "")
    ptypes = [_param_type(p) for p in view] or ["void"]
    ret = _ret_type(spec.ret)
    call = (f"((rp_pfn_{idx})fn)("
            + ", ".join(_arg_expr(p, i) for i, p in enumerate(view)) + ")")
    lines = [
        f"typedef {ret} ({cc} *rp_pfn_{idx})({', '.join(ptypes)});",
        f"static void rp_invoke_{idx}(void *fn, rp_val *a, rp_val *r)",
        "{",
    ]
    if not spec.args:
        lines.append("    (void)a;")
    if spec.ret == "void":
        lines.append(f"    {call};")
        lines.append("    r->i = 0;")
    elif spec.ret in ("f32", "f64"):
        lines.append(f"    r->f = (double){call};")
    elif spec.ret in _C_SCALAR:
        lines.append(f"    r->i = (long long){call};")
    else:
        lines.append(f"    r->i = (long long)(intptr_t){call};")
    lines += ["}", ""]
    return lines


def _trampoline(idx: int, spec: CallbackSpec) -> list[str]:
    view = _spec_args_as_replay(spec.args)
    cc = _C_CC.get(spec.cc, "")
    ret = _ret_type(spec.ret)
    params = ", ".join(f"{_param_type(p)} p{i}" for i, p in enumerate(view))
    lines = [
        f"static {ret} {cc} rp_tramp_{idx}({params or 'void'})",
        "{",
        f"    rp_val a[{max(len(view), 1)}], r;",
    ]
    for i, p in enumerate(view):
        if p.pcls in (PASS_BUFFER, PASS_CB, PASS_PTRVAL, PASS_REF):
            lines.append(f"    a[{i}].p = (void *)p{i};")
        elif p.pcls == PASS_FLOAT:
            lines.append(f"    a[{i}].f = (double)p{i};")
        else:
            lines.append(f"    a[{i}].i = (long long)p{i};")
    if not view:
        lines.append("    a[0].i = 0;")
    lines.append(f"    rp_callback_hit({idx}, a, {len(view)}, &r);")
    if spec.ret == "void":
        lines.append("    (void)r;")
    elif spec.ret in ("f32", "f64"):
        lines.append(f"    return ({ret})r.f;")
    elif spec.ret in _C_SCALAR:
        lines.append(f"    return ({ret})r.i;")
    else:
        lines.append(f"    return ({ret})(intptr_t)r.i;")
    lines += ["}", ""]
    return lines


def _blob_lines(blob: bytes) -> list[str]:
    if not blob:
        # A zero length array is not C; one padding byte keeps RP_BLOB_SIZE
        # honest and the declaration legal.
        return ["static const unsigned char RP_BLOB_DATA[1] = { 0x00 };"]
    out = ["static const unsigned char RP_BLOB_DATA[%d] = {" % len(blob)]
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        out.append("    " + " ".join(f"0x{b:02x}," for b in chunk))
    out.append("};")
    return out


def render_header(plan: ReplayPlan, *, external: bool = False) -> str:
    c = plan.contract
    L: list[str] = [
        "/* generated by shimforge gen_replay.py -- do not edit */",
        f"/* module {_comment(c.module)} ({_comment(c.arch)}), "
        f"thread {plan.tid}, {len(plan.calls)} calls */",
        "",
        f"#define RP_MODULE {_cs(c.module)}",
        f"#define RP_ARCH {_cs(c.arch)}",
        f"#define RP_LABEL {_cs('replay:' + plan.label)}",
        f"#define RP_CONTRACT_HASH {_cs(contract_hash(c))}",
        f"#define RP_TID {plan.tid}",
        f"#define RP_DROPPED_THREADS {len(plan.skipped_tids)}",
        f"#define RP_PLAN_INCOMPLETE {len(plan.plan_incomplete)}",
        f"#define RP_PLANNED_SKIPS {len(plan.skipped)}",
        f"#define RP_EXPECTED_CALLS {len(plan.calls)}",
        f"#define RP_EXPECTED_CALLBACKS "
        f"{sum(1 for r in plan.recs if r.is_cb)}",
        f"#define RP_NSLOTS {plan.nslots}",
        f"#define RP_BLOB_EXTERNAL {1 if external else 0}",
        f"#define RP_BLOB_FILE {_cs(BLOB_FILE)}",
        f"#define RP_BLOB_SIZE {len(plan.blob)}",
        "",
    ]
    if not external:
        L += _blob_lines(bytes(plan.blob)) + [""]

    for i, spec in enumerate(plan.syms):
        L += _invoke_thunk(i, spec)
    for i, spec in enumerate(plan.cbs):
        L += _trampoline(i, spec)

    L.append("static rp_sym RP_SYMS[] = {")
    for i, spec in enumerate(plan.syms):
        L.append("    { .name = %s, .ordinal = %d, .noname = %d, "
                 ".invoke = rp_invoke_%d }," % (
                     _cs(spec.name), spec.ordinal or 0, int(spec.noname), i))
    L += ["    { .name = NULL }", "};",
          f"#define RP_NSYMS {len(plan.syms)}", ""]

    # Callback prototypes carry names and kinds so a callback the recording
    # never saw can still be logged when the shim fires it.
    for i, spec in enumerate(plan.cbs):
        view = _spec_args_as_replay(spec.args)
        L.append(f"static const rp_arg rp_cbproto_{i}[] = {{")
        for pa in view or [ReplayArg(name="", kind="void", dir="in")]:
            L.append("    " + _arg_init(pa) + ",")
        L += ["};"]
    L.append("static const rp_cb RP_CBS[] = {")
    for i, spec in enumerate(plan.cbs):
        L.append("    { .name = %s, .fn = (void *)rp_tramp_%d, "
                 ".proto = rp_cbproto_%d, .nargs = %d, .ret_kind = %s, "
                 ".ret_kindname = %s }," % (
                     _cs(spec.name), i, i, len(spec.args),
                     _KIND_ENUM[spec.ret], _cs(spec.ret)))
    L += ["    { .name = NULL }", "};", f"#define RP_NCB {len(plan.cbs)}", ""]

    L.append("static const rp_arg rp_noargs[1] = { "
             + _arg_init(ReplayArg(name="", kind="void", dir="in")) + " };")
    L.append("")
    for i, rec in enumerate(plan.recs):
        if not rec.args:
            continue
        L.append(f"static const rp_arg rp_a{i}[] = {{")
        for pa in rec.args:
            L.append("    " + _arg_init(pa) + ",")
        L.append("};")
    L.append("")

    kids: list[int] = []
    kid0: list[int] = []
    for rec in plan.recs:
        kid0.append(len(kids))
        kids.extend(rec.kids)
    L.append("static const int RP_KIDS[] = { "
             + "".join(f"{k}, " for k in kids) + "0 };")
    L.append("")

    L.append("static const rp_rec RP_RECS[] = {")
    for i, rec in enumerate(plan.recs):
        L.append("    { .seq = %d, .tid = %d, .sym = %s, .symi = %d, "
                 ".is_cb = %d, .parent = %d, .args = %s, .nargs = %d, "
                 ".kid0 = %d, .nkids = %d, .has_ret = %d, .ret_kind = %s, "
                 ".ret_kindname = %s, .ret_i = %s, .ret_f = %s, "
                 ".ret_slot = %d, .has_lasterr = %d, .lasterr = %dul, "
                 ".skip = %s }," % (
                     rec.seq, rec.tid, _cs(rec.sym), rec.symi, int(rec.is_cb),
                     rec.parent, f"rp_a{i}" if rec.args else "rp_noargs",
                     len(rec.args), kid0[i], len(rec.kids), int(rec.has_ret),
                     _KIND_ENUM[rec.ret_kind], _cs(rec.ret_kind),
                     _ci(rec.ret_i), _cf(rec.ret_f), rec.ret_slot,
                     int(rec.has_lasterr), rec.lasterr,
                     _cs(rec.skip) if rec.skip else "NULL"))
    L += ["};", f"#define RP_NRECS {len(plan.recs)}", ""]
    return "\n".join(L) + "\n"
