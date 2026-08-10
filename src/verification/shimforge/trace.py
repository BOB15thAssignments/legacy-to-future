"""shimforge trace format: streaming JSONL emitted by the tap runtime.

Wire format, one JSON object per line. Keys are short because real traces
reach hundreds of megabytes.

  header    {"t":"hdr","v":1,"module":"oldlib.dll","arch":"x64","pid":123,
             "run":"a1b2","tap":"0.3","label":"scenario-1",
             "maxcap":65536,"contract":"<64 lowercase hex>",
             "subject":"<SHA-256 of the exercised DLL>"}
  call      {"t":"c","q":7,"d":3,"dp":0,"s":"Open","p":null,
             "in":{...},"out":{...},"r":{...},"e":0}
  callback  {"t":"k","q":8,"d":3,"dp":1,"s":"cb_progress","p":7,
             "in":{...},"out":{},"r":{...}}
  note      {"t":"n","q":9,"s":"Process","msg":"unknown-extent arg buf"}
  footer    {"t":"end","records":17,"bytes":4096,
             "sha256":"<64 lowercase hex>"}

The footer is written only after a normal, quiescent shutdown. ``records``
counts every preceding ``c``/``k``/``n`` payload line (the header is not a
record), while ``bytes`` and ``sha256`` cover the exact raw bytes before the
footer, including every original JSONL newline.  This turns a missing,
deleted, reordered, or modified prefix into invalid evidence.

Value objects:
  scalar    {"k":"i32","v":-1}
  pointer   {"k":"ptr","p":"7ff6a1c0","n":24,"b":"18000000..."}
  null ptr  {"k":"ptr","p":"0"}
  string    {"k":"str","p":"7ff6a1c0","v":"data.bin"}
  uncaptured{"k":"ptr","p":"7ff6a1c0","n":0}          -- b omitted on purpose

`b` omitted means "the recorder deliberately did not look", which the
scoring layer treats as missing verification credit rather than as a match.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator

if TYPE_CHECKING:
    from .model import Contract

logger = logging.getLogger(__name__)

TRACE_VERSION = 1
TRACE_TAP_VERSION = "0.3"
TRACE_DEFAULT_MAX_CAPTURE = 64 * 1024

REC_CALL = "c"
REC_CALLBACK = "k"
REC_HEADER = "hdr"
REC_NOTE = "n"
REC_FOOTER = "end"

_VALUE_KINDS = {
    "void", "bool", "i8", "u8", "i16", "u16", "i32", "u32",
    "i64", "u64", "f32", "f64", "ptr", "str", "wstr", "handle",
    "fnptr", "blob",
}
_HEX = frozenset("0123456789abcdefABCDEF")
_SIGNED_RANGES = {
    "i8": (-(1 << 7), (1 << 7) - 1),
    "i16": (-(1 << 15), (1 << 15) - 1),
    "i32": (-(1 << 31), (1 << 31) - 1),
    "i64": (-(1 << 63), (1 << 63) - 1),
}
_UNSIGNED_RANGES = {
    "bool": (0, 1), "u8": (0, (1 << 8) - 1),
    "u16": (0, (1 << 16) - 1), "u32": (0, (1 << 32) - 1),
    "u64": (0, (1 << 64) - 1),
}


@dataclass
class Val:
    """One logged value crossing the boundary."""

    k: str                       # kind, see model.ALL_KINDS
    v: Any = None                # scalar value or decoded string
    p: str | None = None         # raw pointer, lowercase hex, no 0x
    n: int | None = None         # bytes the recorder attempted to capture
    b: str | None = None         # captured bytes, lowercase hex

    @property
    def is_null(self) -> bool:
        return self.p is not None and int(self.p, 16) == 0

    @property
    def captured(self) -> bool:
        return self.b is not None

    def raw_bytes(self) -> bytes:
        return bytes.fromhex(self.b) if self.b else b""

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"k": self.k}
        if self.v is not None:
            d["v"] = self.v
        if self.p is not None:
            d["p"] = self.p
        if self.n is not None:
            d["n"] = self.n
        if self.b is not None:
            d["b"] = self.b
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Val":
        return cls(k=d.get("k", "blob"), v=d.get("v"), p=d.get("p"),
                   n=d.get("n"), b=d.get("b"))


@dataclass
class Rec:
    """One boundary crossing."""

    t: str                                  # REC_CALL | REC_CALLBACK | REC_NOTE
    seq: int
    sym: str = ""
    tid: int = 0
    depth: int = 0
    parent: int | None = None
    inn: dict[str, Val] = field(default_factory=dict)
    out: dict[str, Val] = field(default_factory=dict)
    ret: Val | None = None
    lasterr: int | None = None
    msg: str = ""

    @property
    def is_call(self) -> bool:
        return self.t in (REC_CALL, REC_CALLBACK)

    def field_paths(self) -> list[str]:
        """Canonical comparable paths, in a stable order."""
        paths = [f"in.{k}" for k in sorted(self.inn)]
        paths += [f"out.{k}" for k in sorted(self.out)]
        if self.ret is not None:
            paths.append("ret")
        if self.lasterr is not None:
            paths.append("lasterr")
        return paths

    def get_path(self, path: str) -> Val | int | None:
        if path == "ret":
            return self.ret
        if path == "lasterr":
            return self.lasterr
        section, _, name = path.partition(".")
        if section == "in":
            return self.inn.get(name)
        if section == "out":
            return self.out.get(name)
        return None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"t": self.t, "q": self.seq}
        if self.t == REC_NOTE:
            d["s"] = self.sym
            d["msg"] = self.msg
            return d
        d["d"] = self.tid
        d["dp"] = self.depth
        d["s"] = self.sym
        if self.parent is not None:
            d["p"] = self.parent
        if self.inn:
            d["in"] = {k: v.to_json() for k, v in self.inn.items()}
        if self.out:
            d["out"] = {k: v.to_json() for k, v in self.out.items()}
        if self.ret is not None:
            d["r"] = self.ret.to_json()
        if self.lasterr is not None:
            d["e"] = self.lasterr
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Rec":
        t = d.get("t", REC_CALL)
        if t == REC_NOTE:
            return cls(t=t, seq=int(d.get("q", -1)), sym=d.get("s", ""),
                       msg=d.get("msg", ""))
        return cls(
            t=t, seq=int(d["q"]), sym=d.get("s", ""), tid=int(d.get("d", 0)),
            depth=int(d.get("dp", 0)), parent=d.get("p"),
            inn={k: Val.from_json(v) for k, v in d.get("in", {}).items()},
            out={k: Val.from_json(v) for k, v in d.get("out", {}).items()},
            ret=Val.from_json(d["r"]) if "r" in d else None,
            lasterr=d.get("e"))


@dataclass
class Trace:
    header: dict[str, Any] = field(default_factory=dict)
    records: list[Rec] = field(default_factory=list)
    notes: list[Rec] = field(default_factory=list)
    source: str = ""
    # `read_trace` is deliberately non-throwing for format defects so callers
    # can render every useful diagnostic.  A trace is admissible for a diff
    # only when this list is empty and a normal-completion footer was seen.
    validation_errors: list[str] = field(default_factory=list)
    complete: bool = True
    footer: dict[str, Any] = field(default_factory=lambda: {
        "t": REC_FOOTER,
        "records": 0,
        "bytes": 0,
        "sha256": "0" * 64,
    })

    @property
    def valid(self) -> bool:
        return self.complete and not self.validation_errors

    @property
    def module(self) -> str:
        return self.header.get("module", "")

    @property
    def arch(self) -> str:
        return self.header.get("arch", "x64")

    @property
    def calls(self) -> list[Rec]:
        return [r for r in self.records if r.is_call]

    def by_seq(self) -> dict[int, Rec]:
        return {r.seq: r for r in self.records}

    def by_thread(self) -> dict[int, list[Rec]]:
        """Per thread subsequences.

        Global interleaving is not comparable across runs; per thread order
        is. Callbacks stay in their invoking thread, which keeps the
        parent/child relationship inside one subsequence.
        """
        out: dict[int, list[Rec]] = {}
        for r in self.records:
            if r.is_call:
                out.setdefault(r.tid, []).append(r)
        for recs in out.values():
            recs.sort(key=lambda r: r.seq)
        return out

    def children_of(self, seq: int) -> list[Rec]:
        return [r for r in self.records if r.parent == seq]

    def symbol_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.records:
            if r.is_call:
                counts[r.sym] = counts.get(r.sym, 0) + 1
        return counts


def read_trace(path: str | Path) -> Trace:
    """Read a trace while retaining format diagnostics.

    Verification is fail-closed: a syntactically valid prefix of a crashed
    run is evidence for debugging, not evidence of equivalence.  Consequently
    the reader requires a unique header and a unique, integrity-protected
    final footer.  It records defects on the returned object instead of
    raising at the first one so ``tracediff`` and the CLI can explain the
    refusal.
    """
    tr = Trace(source=str(path), complete=False)
    saw_header = False
    saw_footer = False
    saw_payload = False
    seq_lines: dict[int, int] = {}
    prefix_digest = hashlib.sha256()
    prefix_bytes = 0
    payload_lines = 0

    with open(path, "rb") as fh:
        for lineno, raw_line in enumerate(fh, 1):
            # The footer must be the final JSONL line.  Even a blank line after
            # it is additional, unauthenticated data and therefore fatal.
            if saw_footer:
                _trace_error(tr, lineno,
                             "bytes appear after completion footer")
                continue
            if raw_line and not raw_line.endswith(b"\n"):
                _trace_error(tr, lineno, "unterminated final line")
            try:
                line = raw_line.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError as exc:
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
                _trace_error(tr, lineno, f"invalid UTF-8: {exc.reason}")
                continue
            if not line:
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
                _trace_error(tr, lineno,
                             "blank JSONL line is not permitted")
                continue
            try:
                d = json.loads(line, object_pairs_hook=_object_no_dupes,
                               parse_constant=_reject_json_constant)
            except json.JSONDecodeError as exc:
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
                _trace_error(tr, lineno,
                             f"invalid/truncated JSON at column {exc.colno}: "
                             f"{exc.msg}")
                continue
            except ValueError as exc:
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
                _trace_error(tr, lineno, str(exc))
                continue
            if not isinstance(d, dict):
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
                _trace_error(tr, lineno, "line must be a JSON object")
                continue

            t = d.get("t")
            if t != REC_FOOTER:
                prefix_digest.update(raw_line)
                prefix_bytes += len(raw_line)
            if t in (REC_CALL, REC_CALLBACK, REC_NOTE):
                payload_lines += 1
            if t == REC_HEADER:
                if saw_header:
                    _trace_error(tr, lineno, "duplicate trace header")
                    continue
                if saw_payload:
                    _trace_error(tr, lineno,
                                 "trace header must be the first object")
                saw_header = True
                tr.header = d
                for problem in _validate_header(d):
                    _trace_error(tr, lineno, problem)
                continue
            if t == REC_FOOTER:
                if not saw_header:
                    _trace_error(tr, lineno, "completion footer precedes header")
                saw_footer = True
                tr.footer = d
                for problem in _validate_footer(
                        d, expected_records=payload_lines,
                        expected_bytes=prefix_bytes,
                        expected_sha256=prefix_digest.hexdigest()):
                    _trace_error(tr, lineno, problem)
                continue

            saw_payload = True
            if not saw_header:
                _trace_error(tr, lineno, "record appears before trace header")
            try:
                if t == REC_NOTE:
                    problems = _validate_note(d)
                    rec = Rec.from_json(d) if not problems else None
                elif t in (REC_CALL, REC_CALLBACK):
                    problems = _validate_record(d, tr.arch)
                    rec = Rec.from_json(d) if not problems else None
                else:
                    problems = [f"unknown record type {t!r}"]
                    rec = None
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                problems = [f"record cannot be decoded: {exc}"]
                rec = None
            for problem in problems:
                _trace_error(tr, lineno, problem)
            if rec is None:
                continue
            prior = seq_lines.get(rec.seq)
            if prior is not None:
                _trace_error(tr, lineno,
                             f"duplicate sequence {rec.seq} (first at line "
                             f"{prior})")
            else:
                seq_lines[rec.seq] = lineno
            if t == REC_NOTE:
                tr.notes.append(rec)
                _trace_error(tr, lineno,
                             f"runtime note q={rec.seq} {rec.sym}: {rec.msg}")
            else:
                tr.records.append(rec)

    if not saw_header:
        _trace_error(tr, None, "missing trace header")
    if not saw_footer:
        _trace_error(tr, None,
                     "missing normal-completion footer (trace is incomplete)")
    tr.complete = saw_footer
    _validate_relationships(tr)
    tr.records.sort(key=lambda r: r.seq)
    return tr


def write_trace(path: str | Path, trace: Trace) -> None:
    if not trace.valid:
        raise ValueError("refusing to write invalid/incomplete trace: "
                         + "; ".join(trace.validation_errors))
    hdr = dict(trace.header)
    hdr.setdefault("t", REC_HEADER)
    hdr.setdefault("v", TRACE_VERSION)
    prefix_digest = hashlib.sha256()
    prefix_bytes = 0
    payload_lines = 0

    with open(path, "wb") as fh:
        raw = _canonical_jsonl(hdr)
        fh.write(raw)
        prefix_digest.update(raw)
        prefix_bytes += len(raw)

        for r in (*trace.records, *trace.notes):
            obj = r.to_json()
            raw = _canonical_jsonl(obj)
            fh.write(raw)
            prefix_digest.update(raw)
            prefix_bytes += len(raw)
            if obj.get("t") in (REC_CALL, REC_CALLBACK, REC_NOTE):
                payload_lines += 1

        # Never preserve caller-supplied trailer metadata.  It describes the
        # exact bytes just emitted and cannot safely be copied from elsewhere.
        footer = {
            "t": REC_FOOTER,
            "records": payload_lines,
            "bytes": prefix_bytes,
            "sha256": prefix_digest.hexdigest(),
        }
        fh.write(_canonical_jsonl(footer))
        trace.footer = footer


def iter_records(path: str | Path) -> Iterator[Rec]:
    """Yield records only from a complete, valid trace.

    This intentionally validates before yielding.  A one-pass streaming
    consumer cannot retract records if the footer is later missing, which is
    incompatible with fail-closed verification.
    """
    tr = read_trace(path)
    if not tr.valid:
        raise ValueError("invalid/incomplete trace: "
                         + "; ".join(tr.validation_errors))
    yield from tr.records


def make_header(module: str, arch: str = "x64", label: str = "",
                **extra: Any) -> dict[str, Any]:
    h = {"t": REC_HEADER, "v": TRACE_VERSION, "module": module, "arch": arch,
         "maxcap": TRACE_DEFAULT_MAX_CAPTURE, "contract": "0" * 64,
         "subject": "0" * 64, "tap": TRACE_TAP_VERSION}
    if label:
        h["label"] = label
    h.update(extra)
    return h


def validate_trace_contract(trace: Trace, contract: "Contract") -> list[str]:
    """Return every reason ``trace`` is not complete contract evidence.

    Equality between A and B is insufficient: two recorders can omit the same
    field and compare clean.  This gate therefore checks the raw wire shape
    against the loaded contract before normalization has a chance to erase
    run-local data.
    """
    problems = list(getattr(trace, "validation_errors", ()) or ())
    if not bool(getattr(trace, "complete", True)):
        problems.append("normal-completion footer was not observed")
    problems.extend(f"footer: {p}" for p in _validate_footer(trace.footer))
    for problem in _validate_header(trace.header):
        problems.append(f"header: {problem}")

    expected_hash = contract.fingerprint()
    if trace.header.get("contract") != expected_hash:
        problems.append(
            f"header.contract {trace.header.get('contract')!r} does not match "
            f"loaded contract {expected_hash}")
    if trace.header.get("module") != contract.module:
        problems.append(
            f"header.module {trace.header.get('module')!r} does not match "
            f"contract module {contract.module!r}")
    if trace.header.get("arch") != contract.arch:
        problems.append(
            f"header.arch {trace.header.get('arch')!r} does not match "
            f"contract arch {contract.arch!r}")

    for note in trace.notes:
        marker = f"runtime note q={note.seq} {note.sym}: {note.msg}"
        if not any(marker in problem for problem in problems):
            problems.append(marker)
    if not trace.records:
        problems.append("trace contains zero call/callback records")

    by_seq: dict[int, Rec] = {}
    for rec in trace.records:
        if rec.seq in by_seq:
            problems.append(f"duplicate record sequence q={rec.seq}")
        else:
            by_seq[rec.seq] = rec

        if rec.t == REC_CALL:
            spec = contract.symbols.get(rec.sym)
            opposite = contract.callbacks.get(rec.sym)
            expected_type = "call"
        elif rec.t == REC_CALLBACK:
            spec = contract.callbacks.get(rec.sym)
            opposite = contract.symbols.get(rec.sym)
            expected_type = "callback"
        else:
            problems.append(
                f"q={rec.seq} {rec.sym}: unsupported record type {rec.t!r}")
            continue
        if spec is None:
            if opposite is not None:
                problems.append(
                    f"q={rec.seq} {rec.sym}: recorded as {expected_type} but "
                    f"contract declares the opposite record type")
            else:
                problems.append(
                    f"q={rec.seq} {rec.sym}: symbol is absent from contract "
                    f"{expected_type}s")
            continue

        args = {arg.name: arg for arg in spec.args}
        expected_in = {arg.name for arg in spec.args if arg.is_in}
        expected_out = {arg.name for arg in spec.args if arg.is_out}
        _validate_section_contract(problems, rec, "in", rec.inn,
                                   expected_in, args, contract)
        _validate_section_contract(problems, rec, "out", rec.out,
                                   expected_out, args, contract)

        if rec.ret is None:
            problems.append(
                f"q={rec.seq} {rec.sym}: missing required return value "
                f"of kind {spec.ret}")
        elif rec.ret.k != spec.ret:
            problems.append(
                f"q={rec.seq} {rec.sym}.ret: recorded kind {rec.ret.k!r}, "
                f"contract requires {spec.ret!r}")
        else:
            problems.extend(
                f"q={rec.seq} {rec.sym}.ret: {p}"
                for p in _capture_completeness(rec.ret))

        expects_lasterr = (rec.t == REC_CALL
                           and bool(getattr(spec, "lasterr", False)))
        has_lasterr = rec.lasterr is not None
        if expects_lasterr != has_lasterr:
            problems.append(
                f"q={rec.seq} {rec.sym}.lasterr: "
                f"{'missing' if expects_lasterr else 'recorded unexpectedly'}")

    return list(dict.fromkeys(problems))


def _validate_section_contract(problems: list[str], rec: Rec, section: str,
                               actual: dict[str, Val], expected: set[str],
                               args: dict[str, Any], contract: "Contract") -> None:
    actual_names = set(actual)
    for name in sorted(expected - actual_names):
        problems.append(f"q={rec.seq} {rec.sym}.{section}: missing field {name!r}")
    for name in sorted(actual_names - expected):
        problems.append(
            f"q={rec.seq} {rec.sym}.{section}: unexpected field {name!r}")
    for name in sorted(expected & actual_names):
        val = actual[name]
        wanted = args[name].kind
        if val.k != wanted:
            problems.append(
                f"q={rec.seq} {rec.sym}.{section}.{name}: recorded kind "
                f"{val.k!r}, contract requires {wanted!r}")
            continue
        problems.extend(
            f"q={rec.seq} {rec.sym}.{section}.{name}: {p}"
            for p in _capture_completeness(val))
        problems.extend(
            f"q={rec.seq} {rec.sym}.{section}.{name}: {p}"
            for p in _validate_extent_contract(
                contract, rec, args[name], val, section))


def _capture_completeness(val: Val) -> list[str]:
    if val.n is None:
        return []
    if not _is_int(val.n) or val.n < 0:
        return [f"invalid capture extent n={val.n!r}"]
    if val.b is None:
        return ([f"partial capture declares n={val.n} but b is absent"]
                if val.n > 0 else [])
    try:
        captured = len(bytes.fromhex(val.b))
    except (TypeError, ValueError):
        return ["captured bytes are not valid hexadecimal"]
    if captured != val.n:
        return [f"partial capture has {captured} byte(s), n={val.n}"]
    return []


def _validate_extent_contract(contract: "Contract", rec: Rec, arg: Any,
                              val: Val, section: str) -> list[str]:
    """Prove a pointer/blob capture covered the contract-declared extent."""
    if arg.kind not in ("ptr", "blob"):
        return []
    if val.p is None:
        return ["pointer argument was not recorded with p"]
    try:
        if int(val.p, 16) == 0:
            return []
    except (TypeError, ValueError):
        return ["pointer p is not hexadecimal"]

    ext = arg.extent
    expected: int | None = None
    if ext is not None and ext.is_known:
        if ext.fixed is not None:
            expected = ext.fixed
        elif ext.arg is not None:
            count_val = rec.inn.get(ext.arg) or rec.out.get(ext.arg)
            if (count_val is None or not _is_int(count_val.v)
                    or count_val.v < 0):
                return [f"cannot resolve extent from count argument {ext.arg!r}"]
            expected = count_val.v * ext.scale
        elif ext.struct is not None:
            struct = contract.structs.get(ext.struct)
            if struct is None:
                return [f"extent names unknown struct {ext.struct!r}"]
            expected = struct.size
    elif arg.struct:
        struct = contract.structs.get(arg.struct)
        if struct is None:
            return [f"argument names unknown struct {arg.struct!r}"]
        expected = struct.size
    else:
        return ["pointer/blob extent is unknown"]

    if val.n is None:
        return [f"missing n for required {expected}-byte capture"]
    if val.n != expected:
        return [f"captured extent n={val.n} does not match contract extent "
                f"{expected} in {section}"]
    return []


def _trace_error(tr: Trace, lineno: int | None, message: str) -> None:
    where = f"{tr.source}:{lineno}" if lineno is not None else tr.source
    text = f"{where}: {message}" if where else message
    tr.validation_errors.append(text)
    logger.warning("%s", text)


def _object_no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_json_constant(token: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant {token!r}")


def _canonical_jsonl(obj: dict[str, Any]) -> bytes:
    """Encode one compact UTF-8 JSON object with its authenticated newline."""
    return (json.dumps(obj, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_header(d: dict[str, Any]) -> list[str]:
    out: list[str] = []
    allowed = {"t", "v", "module", "arch", "pid", "run", "tap",
               "maxcap", "contract", "subject", "label"}
    extra = set(d) - allowed
    if extra:
        out.append("header has unsupported field(s): "
                   + ", ".join(sorted(extra)))
    version = d.get("v")
    if not _is_int(version):
        out.append("header.v must be an integer")
    elif version != TRACE_VERSION:
        out.append(f"unsupported trace version {version!r}; expected "
                   f"{TRACE_VERSION}")
    if not isinstance(d.get("module"), str) or not d.get("module"):
        out.append("header.module must be a nonempty string")
    if d.get("arch") not in ("x86", "x64"):
        out.append("header.arch must be 'x86' or 'x64'")
    if not _is_int(d.get("maxcap")) or d["maxcap"] <= 0:
        out.append("header.maxcap must be a positive integer")
    contract = d.get("contract")
    if (not isinstance(contract, str) or len(contract) != 64
            or any(ch not in "0123456789abcdef" for ch in contract)):
        out.append("header.contract must be 64 lowercase hexadecimal characters")
    subject = d.get("subject")
    if (not isinstance(subject, str) or len(subject) != 64
            or any(ch not in "0123456789abcdef" for ch in subject)):
        out.append("header.subject must be 64 lowercase hexadecimal characters")
    if not _is_int(d.get("pid")) or d["pid"] <= 0:
        out.append("header.pid must be a positive integer")
    if not isinstance(d.get("run"), str) or not d["run"]:
        out.append("header.run must be a nonempty string")
    if d.get("tap") != TRACE_TAP_VERSION:
        out.append(f"header.tap must be supported recorder version "
                   f"{TRACE_TAP_VERSION!r}")
    if "label" in d and not isinstance(d["label"], str):
        out.append("header.label must be a string when present")
    return out


def _validate_footer(
        d: Any, *, expected_records: int | None = None,
        expected_bytes: int | None = None,
        expected_sha256: str | None = None) -> list[str]:
    """Validate the 0.3 completion trailer and optional prefix measurements."""
    if not isinstance(d, dict):
        return ["footer must be a JSON object"]

    out: list[str] = []
    required = {"t", "records", "bytes", "sha256"}
    if set(d) != required:
        missing = sorted(required - set(d))
        extra = sorted(set(d) - required)
        detail: list[str] = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unsupported " + ", ".join(extra))
        out.append("footer fields must be exactly t, records, bytes, sha256"
                   + (" (" + "; ".join(detail) + ")" if detail else ""))
    if d.get("t") != REC_FOOTER:
        out.append(f"footer.t must be {REC_FOOTER!r}")

    records = d.get("records")
    if not _is_int(records) or records < 0:
        out.append("footer.records must be a nonnegative integer")
    elif expected_records is not None and records != expected_records:
        out.append(f"footer.records is {records}, calculated payload count is "
                   f"{expected_records}")

    byte_count = d.get("bytes")
    if not _is_int(byte_count) or byte_count < 0:
        out.append("footer.bytes must be a nonnegative integer")
    elif expected_bytes is not None and byte_count != expected_bytes:
        out.append(f"footer.bytes is {byte_count}, calculated prefix size is "
                   f"{expected_bytes}")

    digest = d.get("sha256")
    if (not isinstance(digest, str) or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)):
        out.append("footer.sha256 must be 64 lowercase hexadecimal characters")
    elif expected_sha256 is not None and digest != expected_sha256:
        out.append(f"footer.sha256 is {digest}, calculated prefix digest is "
                   f"{expected_sha256}")
    return out


def _validate_note(d: dict[str, Any]) -> list[str]:
    out: list[str] = []
    extra = set(d) - {"t", "q", "s", "msg"}
    if extra:
        out.append("note has unsupported field(s): " + ", ".join(sorted(extra)))
    if not _is_int(d.get("q")) or d["q"] < 0:
        out.append("note.q must be a nonnegative integer")
    if not isinstance(d.get("s"), str):
        out.append("note.s must be a string")
    if not isinstance(d.get("msg"), str):
        out.append("note.msg must be a string")
    return out


def _validate_record(d: dict[str, Any], arch: str) -> list[str]:
    out: list[str] = []
    extra = set(d) - {"t", "q", "d", "dp", "s", "p",
                      "in", "out", "r", "e"}
    if extra:
        out.append("record has unsupported field(s): " + ", ".join(sorted(extra)))
    t = d.get("t")
    if not _is_int(d.get("q")) or d["q"] < 0:
        out.append("record.q must be a nonnegative integer")
    if not _is_int(d.get("d")) or d["d"] < 0:
        out.append("record.d (thread id) must be a nonnegative integer")
    if not _is_int(d.get("dp")) or d["dp"] < 0:
        out.append("record.dp (depth) must be a nonnegative integer")
    if not isinstance(d.get("s"), str) or not d.get("s"):
        out.append("record.s must be a nonempty string")
    parent = d.get("p")
    if parent is not None and (not _is_int(parent) or parent < 0):
        out.append("record.p must be null or a nonnegative integer")
    if _is_int(d.get("q")) and parent == d.get("q"):
        out.append("record cannot be its own parent")
    if t == REC_CALLBACK:
        if parent is None:
            out.append("callback record requires a parent sequence")
        if d.get("dp") == 0:
            out.append("callback record depth must be greater than zero")
    elif d.get("dp") == 0 and parent is not None:
        out.append("depth-zero call must not name a parent")

    for section in ("in", "out"):
        raw = d.get(section, {})
        if not isinstance(raw, dict):
            out.append(f"record.{section} must be an object")
            continue
        for name, value in raw.items():
            if not isinstance(name, str) or not name:
                out.append(f"record.{section} field names must be nonempty strings")
                continue
            out.extend(f"{section}.{name}: {p}" for p in
                       _validate_value(value, arch))
    if "r" in d:
        out.extend(f"ret: {p}" for p in _validate_value(d["r"], arch))
    if "e" in d:
        if not _is_int(d["e"]):
            out.append("record.e (last error) must be an integer")
        elif not 0 <= d["e"] <= 0xFFFFFFFF:
            out.append("record.e (last error) is outside DWORD range")
    return out


def _validate_value(value: Any, arch: str) -> list[str]:
    if not isinstance(value, dict):
        return ["value must be an object"]
    out: list[str] = []
    extra = set(value) - {"k", "v", "p", "n", "b"}
    if extra:
        out.append("value has unsupported field(s): " + ", ".join(sorted(extra)))
    kind = value.get("k")
    if kind not in _VALUE_KINDS:
        out.append(f"unsupported or missing kind {kind!r}")
    scalar = value.get("v")
    if kind in _SIGNED_RANGES or kind in _UNSIGNED_RANGES:
        if not _is_int(scalar):
            out.append(f"{kind} requires an integer v")
        else:
            lo, hi = (_SIGNED_RANGES[kind] if kind in _SIGNED_RANGES
                      else _UNSIGNED_RANGES[kind])
            if not lo <= scalar <= hi:
                out.append(f"{kind} v={scalar} is outside [{lo}, {hi}]")
        if any(k in value for k in ("p", "n", "b")):
            out.append(f"{kind} scalar must not carry pointer/byte fields")
    elif kind in ("f32", "f64"):
        if (not isinstance(scalar, (int, float))
                or isinstance(scalar, bool)):
            out.append(f"{kind} requires a numeric v")
        if any(k in value for k in ("p", "n", "b")):
            out.append(f"{kind} scalar must not carry pointer/byte fields")
    elif kind in ("str", "wstr"):
        if scalar is not None and not isinstance(scalar, str):
            out.append(f"{kind} v must be a string when captured")
        if "p" not in value:
            out.append(f"{kind} requires a pointer p")
        if any(k in value for k in ("n", "b")):
            out.append(f"{kind} must not carry raw byte fields")
    elif kind in ("ptr", "blob", "handle", "fnptr"):
        # Pointer arguments use p; pointer/handle returns use signed integer v.
        if "p" not in value and not _is_int(scalar):
            out.append(f"{kind} requires hexadecimal p or integer v")
        if "p" in value and "v" in value:
            out.append(f"{kind} must not carry both p and v")
        if scalar is not None and not _is_int(scalar):
            out.append(f"{kind} v must be an integer")
        if _is_int(scalar) and not -(1 << 63) <= scalar <= (1 << 63) - 1:
            out.append(f"{kind} integer v is outside signed 64-bit range")
        if kind in ("handle", "fnptr") and any(k in value for k in ("n", "b")):
            out.append(f"{kind} must not carry raw byte fields")
        if _is_int(scalar) and any(k in value for k in ("n", "b")):
            out.append(f"{kind} integer value must not carry raw byte fields")
    elif kind == "void" and any(k in value for k in ("v", "p", "n", "b")):
        out.append("void value must not carry a payload")

    pointer = value.get("p")
    if "p" in value:
        if (not isinstance(pointer, str) or not pointer
                or any(ch not in _HEX for ch in pointer)):
            out.append("p must be a nonempty hexadecimal string")
        elif len(pointer) > (8 if arch == "x86" else 16):
            out.append(f"p exceeds {arch} pointer width")
    extent = value.get("n")
    if extent is not None and (not _is_int(extent) or extent < 0):
        out.append("n must be a nonnegative integer")
    if ("n" in value or "b" in value) and "p" not in value:
        out.append("n/b capture fields require a pointer p")
    captured = value.get("b")
    if captured is not None:
        if (not isinstance(captured, str) or len(captured) % 2
                or any(ch not in _HEX for ch in captured)):
            out.append("b must be an even-length hexadecimal string")
        elif not _is_int(extent):
            out.append("captured bytes require an integer n extent")
        elif len(captured) // 2 != extent:
            out.append(f"partial capture: b has {len(captured) // 2} byte(s) "
                       f"but n declares {extent}")
    elif _is_int(extent) and extent > 0:
        out.append(f"partial capture: n declares {extent} byte(s) but b is "
                   "absent")
    return out


def _validate_relationships(tr: Trace) -> None:
    by_seq = {r.seq: r for r in tr.records}
    for rec in tr.records:
        if rec.parent is None:
            if rec.depth > 0:
                _trace_error(tr, None,
                             f"record q={rec.seq} depth={rec.depth} has no parent")
            continue
        parent = by_seq.get(rec.parent)
        if parent is None:
            _trace_error(tr, None,
                         f"record q={rec.seq} names missing parent q={rec.parent}")
            continue
        if rec.tid != parent.tid:
            _trace_error(tr, None,
                         f"record q={rec.seq} parent q={rec.parent} is on a "
                         "different thread")
        if rec.depth != parent.depth + 1:
            _trace_error(tr, None,
                         f"record q={rec.seq} depth {rec.depth} is not parent "
                         f"depth {parent.depth} + 1")


def _selftest() -> None:  # pragma: no cover - run with python -m
    import tempfile

    from .model import ArgSpec, Contract, Extent, SymbolSpec

    rec = Rec(t=REC_CALL, seq=1, sym="Ping", tid=7, depth=0,
              inn={"x": Val(k="i32", v=3)}, ret=Val(k="i32", v=3))
    rec2 = Rec(t=REC_CALL, seq=2, sym="Ping", tid=7, depth=0,
               inn={"x": Val(k="i32", v=4)}, ret=Val(k="i32", v=4))

    def seal(prefix: bytes, records: int) -> bytes:
        return prefix + _canonical_jsonl({
            "t": REC_FOOTER,
            "records": records,
            "bytes": len(prefix),
            "sha256": hashlib.sha256(prefix).hexdigest(),
        })

    def replace_footer(blob: bytes, **changes: Any) -> bytes:
        lines = blob.splitlines(keepends=True)
        footer = json.loads(lines[-1])
        footer.update(changes)
        return b"".join(lines[:-1]) + _canonical_jsonl(footer)

    def assert_invalid(path: Path, *needles: str) -> Trace:
        parsed_trace = read_trace(path)
        assert not parsed_trace.valid, path
        for needle in needles:
            assert any(needle in error for error in
                       parsed_trace.validation_errors), (
                           needle, parsed_trace.validation_errors)
        return parsed_trace

    with tempfile.TemporaryDirectory(prefix="shimforge-trace-") as td:
        root = Path(td)
        good = root / "good.jsonl"
        write_trace(good, Trace(header=make_header(
            "oldlib.dll", "x64", label="selftest", pid=1,
            run="run-a", tap=TRACE_TAP_VERSION),
            records=[rec, rec2]))
        good_bytes = good.read_bytes()
        good_lines = good_bytes.splitlines(keepends=True)
        prefix = b"".join(good_lines[:-1])
        parsed = read_trace(good)
        assert parsed.valid and parsed.complete, parsed.validation_errors
        assert parsed.footer == {
            "t": REC_FOOTER,
            "records": 2,
            "bytes": len(prefix),
            "sha256": hashlib.sha256(prefix).hexdigest(),
        }, parsed.footer
        assert len(parsed.records) == 2
        print("[ok] 0.3 footer authenticates count, byte length, and prefix")

        no_end = root / "no-end.jsonl"
        no_end.write_bytes(prefix)
        parsed = read_trace(no_end)
        assert not parsed.valid and not parsed.complete
        assert any("missing normal-completion footer" in e
                   for e in parsed.validation_errors), parsed.validation_errors
        print("[ok] missing footer -> invalid/incomplete")

        bad_end = root / "bad-end.jsonl"
        # Deliberately omit sha256: an almost-correct trailer is not accepted.
        bad_end.write_bytes(prefix + _canonical_jsonl({
            "t": REC_FOOTER, "records": 2, "bytes": len(prefix)}))
        assert_invalid(bad_end, "footer fields must be exactly",
                       "footer.sha256 must be")
        print("[ok] footer schema omission -> invalid")

        torn = root / "torn.jsonl"
        torn.write_bytes(good_bytes + b'{"t":"c","q":')
        assert_invalid(torn, "bytes appear after completion footer")
        print("[ok] torn trailing line -> invalid")

        tampered = root / "tampered.jsonl"
        changed = json.loads(good_lines[1])
        changed["in"]["x"]["v"] = 9
        tampered.write_bytes(good_lines[0] + _canonical_jsonl(changed)
                             + b"".join(good_lines[2:]))
        assert_invalid(tampered, "calculated prefix digest")
        print("[ok] payload byte tamper -> invalid")

        reordered = root / "reordered.jsonl"
        reordered.write_bytes(good_lines[0] + good_lines[2] + good_lines[1]
                              + good_lines[3])
        assert_invalid(reordered, "calculated prefix digest")
        print("[ok] payload line reorder -> invalid")

        last_deleted = root / "last-record-deleted.jsonl"
        last_deleted.write_bytes(good_lines[0] + good_lines[1] + good_lines[3])
        assert_invalid(last_deleted, "calculated payload count",
                       "calculated prefix size", "calculated prefix digest")
        print("[ok] last payload record deletion -> invalid")

        wrong_count = root / "wrong-count.jsonl"
        wrong_count.write_bytes(replace_footer(good_bytes, records=3))
        assert_invalid(wrong_count, "calculated payload count")

        wrong_bytes = root / "wrong-bytes.jsonl"
        wrong_bytes.write_bytes(replace_footer(good_bytes,
                                               bytes=len(prefix) + 1))
        assert_invalid(wrong_bytes, "calculated prefix size")

        wrong_hash = root / "wrong-hash.jsonl"
        actual_hash = hashlib.sha256(prefix).hexdigest()
        bad_hash = ("0" if actual_hash[0] != "0" else "1") + actual_hash[1:]
        wrong_hash.write_bytes(replace_footer(good_bytes, sha256=bad_hash))
        assert_invalid(wrong_hash, "calculated prefix digest")

        wrong_type = root / "wrong-type.jsonl"
        wrong_type.write_bytes(replace_footer(good_bytes, records="2"))
        assert_invalid(wrong_type,
                       "footer.records must be a nonnegative integer")
        print("[ok] count/bytes/hash/type trailer mismatches -> invalid")

        malformed = root / "malformed.jsonl"
        malformed_prefix = (
            _canonical_jsonl(make_header("oldlib.dll", pid=1, run="bad-a"))
            + b'{"t":"c","q":1,"d":7,"dp":0,"s":"Ping",'
              b'"r":{"k":"not-a-kind","v":3}}\n')
        malformed.write_bytes(seal(malformed_prefix, 1))
        parsed = read_trace(malformed)
        assert not parsed.valid
        assert any("unsupported or missing kind" in e
                   for e in parsed.validation_errors), parsed.validation_errors
        print("[ok] malformed value -> invalid")

        same_seq = root / "same-seq.jsonl"
        line = _canonical_jsonl(rec.to_json())
        same_seq_prefix = (_canonical_jsonl(make_header(
            "oldlib.dll", pid=1, run="same-seq-a")) + line + line)
        same_seq.write_bytes(seal(same_seq_prefix, 2))
        parsed = read_trace(same_seq)
        assert not parsed.valid
        assert any("duplicate sequence" in e
                   for e in parsed.validation_errors), parsed.validation_errors
        print("[ok] duplicate sequence -> invalid")

        try:
            list(iter_records(no_end))
        except ValueError as exc:
            assert "invalid/incomplete trace" in str(exc)
        else:
            raise AssertionError("iter_records accepted an incomplete trace")

        contract = Contract(module="oldlib.dll", arch="x64")
        contract.symbols["Ping"] = SymbolSpec(
            name="Ping", ret="i32", args=[ArgSpec("x", "i32")])
        contract.symbols["Copy"] = SymbolSpec(
            name="Copy", ret="i32",
            args=[ArgSpec("p", "ptr", extent=Extent(fixed=4))])
        bound = Trace(header=make_header(
            "oldlib.dll", contract=contract.fingerprint(), run="contract-a",
            tap=TRACE_TAP_VERSION, pid=1), records=[rec])
        assert validate_trace_contract(bound, contract) == []
        wrong_binding = Trace(header={**bound.header, "contract": "f" * 64},
                              records=[rec])
        assert any("does not match loaded contract" in p
                   for p in validate_trace_contract(wrong_binding, contract))
        assert any("supported recorder version" in p
                   for p in _validate_header({**bound.header, "tap": "999"}))
        assert any("unsupported field" in p for p in
                   _validate_header({**bound.header, "surprise": 1}))

        missing = Rec(t=REC_CALL, seq=1, sym="Ping", tid=7, depth=0,
                      inn={}, ret=None)
        bad_contract = Trace(header=dict(bound.header), records=[missing])
        conformance = validate_trace_contract(bad_contract, contract)
        assert any("missing field 'x'" in p for p in conformance), conformance
        assert any("missing required return" in p for p in conformance), conformance
        print("[ok] contract gate rejects symmetric field/return omissions")

        short = Rec(t=REC_CALL, seq=2, sym="Copy", tid=7, depth=0,
                    inn={"p": Val(k="ptr", p="1000", n=2, b="aabb")},
                    ret=Val(k="i32", v=0))
        short_trace = Trace(header=dict(bound.header), records=[short])
        conformance = validate_trace_contract(short_trace, contract)
        assert any("does not match contract extent 4" in p
                   for p in conformance), conformance
        print("[ok] contract extent beats a self-consistent short prefix")
        print("all trace self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.ERROR)
    _selftest()
