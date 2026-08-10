"""Compare normalized traces and report the first divergence by default.

Call insertion and deletion use bounded lookahead for resynchronization.
Capture asymmetry is reported as a mismatch rather than skipped.
"""

from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from .model import Contract
from .normalize import NormRec, NormTrace, NormVal
from .policy import MaskRule, Policy
from .trace import TRACE_TAP_VERSION

logger = logging.getLogger(__name__)

# How far ahead to look for a resynchronization point. Small on purpose: a
# large window turns "the shim reordered the whole call sequence" into a
# plausible-looking chain of single insertions.
RESYNC_WINDOW = 8
CONTEXT_RECORDS = 3
MAX_CALLBACK_NESTING = 8

KIND_MISSING_CALL = "missing-call"
KIND_EXTRA_CALL = "extra-call"
KIND_SYMBOL_MISMATCH = "symbol-mismatch"
KIND_VALUE_MISMATCH = "value-mismatch"
KIND_CALLBACK_MISMATCH = "callback-mismatch"
KIND_THREAD_COUNT = "thread-count"
KIND_THREAD_MISMATCH = "thread-mismatch"
KIND_UNCAPTURED = "uncaptured-vs-captured"
KIND_TRACE_INVALID = "trace-invalid"
KIND_HEADER_MISMATCH = "header-mismatch"
KIND_SAME_RUN = "same-run"
KIND_SAME_SUBJECT = "same-subject"
KIND_COMPARE_LIMIT = "comparison-limit"
KIND_POLICY_UNSAFE = "unsafe-policy"

KINDS = (KIND_MISSING_CALL, KIND_EXTRA_CALL, KIND_SYMBOL_MISMATCH,
         KIND_VALUE_MISMATCH, KIND_CALLBACK_MISMATCH, KIND_THREAD_COUNT,
         KIND_THREAD_MISMATCH, KIND_UNCAPTURED, KIND_TRACE_INVALID,
         KIND_HEADER_MISMATCH,
         KIND_SAME_RUN, KIND_SAME_SUBJECT, KIND_COMPARE_LIMIT,
         KIND_POLICY_UNSAFE)

_HEX_CHARS = set("0123456789abcdefABCDEF.")
_MAX_JSON_VALUE = 512

# Notes that identify a value-mismatch a mask can NOT repair: normalization
# blanks `v` and dots `b`, but it never invents a missing field and never
# rewrites a kind, so `suggest_masks` has to refuse these rather than emit a
# rule that can never close the determinism loop.
_NOTE_ONE_SIDED_FIELD = "field recorded on one side only"
_NOTE_KIND_DIFFERS = "kind differs"
_NOTE_EMBEDDED_IDENTITY = "embedded pointer identity differs"
_NOTE_EMBEDDED_ONE_SIDED = "embedded pointer field present on one side only"


@dataclass
class Divergence:
    kind: str
    seq_a: int | None
    seq_b: int | None
    sym: str
    path: str
    a: Any
    b: Any
    byte_offset: int | None = None
    context_a: list[NormRec] = field(default_factory=list)
    context_b: list[NormRec] = field(default_factory=list)
    note: str = ""

    def one_line(self) -> str:
        seqs = f"A{_seq_str(self.seq_a)}/B{_seq_str(self.seq_b)}"
        where = f"{self.sym}.{self.path}" if self.path else self.sym or "-"
        return (f"{self.kind:<22} {seqs:<14} {where} "
                f"A={_fmt_value(self.a)} B={_fmt_value(self.b)}")

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "seq_a": self.seq_a,
            "seq_b": self.seq_b,
            "sym": self.sym,
            "path": self.path,
            "a": _json_value(self.a),
            "b": _json_value(self.b),
            "byte_offset": self.byte_offset,
            "note": self.note,
            "context_a": [_rec_json(r) for r in self.context_a],
            "context_b": [_rec_json(r) for r in self.context_b],
        }


@dataclass
class DiffResult:
    ok: bool
    first: Divergence | None
    total: int
    compared_calls: int
    per_symbol: dict[str, int]
    # False means the supplied evidence could not support a PASS at all
    # (malformed/incomplete input, reused run, or a comparison safety limit).
    # It is additive so existing callers that only inspect `ok` remain safe.
    conclusive: bool = True
    inconclusive_reasons: list[str] = field(default_factory=list)
    suggestions: list[MaskRule] = field(default_factory=list)
    # Beyond the SPEC field list, both additive: `suggest_masks` needs every
    # divergence of a stop_after=0 run, not just the first, and it has to be
    # able to say "this one is not maskable" somewhere a human will see it.
    divergences: list[Divergence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def kind_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.divergences:
            counts[d.kind] = counts.get(d.kind, 0) + 1
        return counts

    def render(self, verbose: bool = False) -> str:
        lines: list[str] = []
        verdict = ("ok" if self.ok else
                   "INCONCLUSIVE" if not self.conclusive else "FAIL")
        lines.append(
            f"tracediff {verdict}: {self.compared_calls} calls compared across "
            f"{len(self.per_symbol)} symbols, {self.total} divergence(s)")
        if self.first is not None:
            lines.append("")
            lines.extend(_render_divergence(self.first))
        for msg in self.warnings[:4]:
            lines.append(f"!  {msg}")
        if len(self.warnings) > 4:
            lines.append(f"!  ... {len(self.warnings) - 4} more warning(s)")
        if self.suggestions:
            lines.append(f"suggested masks: {len(self.suggestions)}")
            for rule in self.suggestions[:8 if verbose else 3]:
                lines.append(f"   mask {rule.sym}.{rule.path} "
                             f"{_fmt_ranges(rule.byte_ranges)}  {rule.why}")
            if len(self.suggestions) > (8 if verbose else 3):
                lines.append("   ...")
        if verbose:
            lines.append("")
            lines.append("calls compared per symbol:")
            for sym, n in sorted(self.per_symbol.items()):
                lines.append(f"   {n:6d}  {sym}")
            if len(self.divergences) > 1:
                lines.append("all divergences:")
                for d in self.divergences:
                    lines.append("   " + d.one_line())
        elif self.total > 1:
            lines.append(f"({self.total - 1} further divergence(s) suppressed: "
                         f"downstream of the first)")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "conclusive": self.conclusive,
            "inconclusive_reasons": list(self.inconclusive_reasons),
            "total": self.total,
            "compared_calls": self.compared_calls,
            "per_symbol": dict(sorted(self.per_symbol.items())),
            "kinds": self.kind_counts(),
            "first": self.first.to_json() if self.first else None,
            "divergences": [d.to_json() for d in self.divergences],
            "suggestions": [_mask_json(m) for m in self.suggestions],
            "warnings": list(self.warnings),
        }


class _Walk:
    """Mutable state threaded through the comparison."""

    def __init__(self, policy: Policy, stop_after: int) -> None:
        self.policy = policy
        self.stop_after = max(0, int(stop_after))
        self.eps = float(getattr(policy, "float_eps", 1e-9))
        self.max_children = int(getattr(policy, "max_children_compare", 0) or 0)
        self.ignore = set(getattr(policy, "ignore_symbols", ()) or ())
        self.compare_tid = getattr(policy, "thread_mode", "per-thread") == "global"
        self.divergences: list[Divergence] = []
        self.compared_calls = 0
        self.per_symbol: dict[str, int] = {}
        self.kids_a: dict[int, list[NormRec]] = {}
        self.kids_b: dict[int, list[NormRec]] = {}
        self._hist_a: list[NormRec] = []
        self._hist_b: list[NormRec] = []
        self.inconclusive_reasons: list[str] = []

    @property
    def stopped(self) -> bool:
        return self.stop_after != 0 and len(self.divergences) >= self.stop_after

    def reset_history(self) -> None:
        self._hist_a.clear()
        self._hist_b.clear()

    def push_a(self, rec: NormRec) -> None:
        self._hist_a.append(rec)
        del self._hist_a[:-CONTEXT_RECORDS]

    def push_b(self, rec: NormRec) -> None:
        self._hist_b.append(rec)
        del self._hist_b[:-CONTEXT_RECORDS]

    def count_pair(self, sym: str) -> None:
        self.compared_calls += 1
        self.per_symbol[sym] = self.per_symbol.get(sym, 0) + 1

    def emit(self, kind: str, *, sym: str = "", path: str = "",
             a: Any = None, b: Any = None, seq_a: int | None = None,
             seq_b: int | None = None, byte_offset: int | None = None,
             note: str = "") -> None:
        if self.stopped:
            return
        self.divergences.append(Divergence(
            kind=kind, seq_a=seq_a, seq_b=seq_b, sym=sym, path=path, a=a, b=b,
            byte_offset=byte_offset,
            context_a=list(self._hist_a), context_b=list(self._hist_b),
            note=note))
        logger.debug("divergence %s at %s.%s (A=%s B=%s)", kind, sym, path,
                     seq_a, seq_b)

    def mark_inconclusive(self, reason: str) -> None:
        if reason not in self.inconclusive_reasons:
            self.inconclusive_reasons.append(reason)


def diff(a: NormTrace, b: NormTrace, policy: Policy, *,
         stop_after: int = 1,
         require_distinct_subjects: bool = False) -> DiffResult:
    """Compare two normalized traces. A is the reference, B the candidate."""
    walk = _Walk(policy, stop_after)

    # Provenance and parser validity are gates, not ordinary differences.  A
    # partial trace must never contribute a clean-looking prefix comparison.
    if _preflight(walk, a, b, policy, require_distinct_subjects):
        return _result(walk)

    walk.kids_a = _child_map(a, walk.ignore)
    walk.kids_b = _child_map(b, walk.ignore)

    if getattr(policy, "thread_mode", "per-thread") == "global":
        _walk_sequence(walk, _roots(a.records, walk.ignore, _seqs(a)),
                       _roots(b.records, walk.ignore, _seqs(b)))
    else:
        threads_a = _ordered_threads(a, walk.ignore)
        threads_b = _ordered_threads(b, walk.ignore)
        if len(threads_a) != len(threads_b):
            # Not a symptom of a later divergence -- a shim that spawns or
            # loses a thread has already changed observable behaviour.
            walk.emit(KIND_THREAD_COUNT, sym="", path="threads",
                      a=len(threads_a), b=len(threads_b),
                      seq_a=_first_seq(threads_a), seq_b=_first_seq(threads_b),
                      note="thread count differs; threads are paired by "
                           "first-appearance order, extras are unpaired")
        # zip() would drop the tail of the longer side, so every call on an
        # unpaired thread would vanish from the comparison -- silently, and
        # out of `compared_calls` too. Pair the leftovers against an empty
        # sequence instead, which reports them as missing/extra calls.
        for idx in range(max(len(threads_a), len(threads_b))):
            if walk.stopped:
                break
            recs_a = threads_a[idx][1] if idx < len(threads_a) else []
            recs_b = threads_b[idx][1] if idx < len(threads_b) else []
            walk.reset_history()
            _walk_sequence(walk, recs_a, recs_b)

    if walk.compared_calls == 0:
        reason = "zero calls were compared; an empty comparison cannot pass"
        walk.mark_inconclusive(reason)
        walk.emit(KIND_TRACE_INVALID, sym="", path="calls", a=0, b=0,
                  note=reason)
    return _result(walk)


def _result(walk: _Walk) -> DiffResult:
    total = len(walk.divergences)
    conclusive = not walk.inconclusive_reasons
    return DiffResult(
        ok=total == 0 and walk.compared_calls > 0 and conclusive,
        first=walk.divergences[0] if walk.divergences else None,
        total=total, compared_calls=walk.compared_calls,
        per_symbol=walk.per_symbol, conclusive=conclusive,
        inconclusive_reasons=list(walk.inconclusive_reasons),
        divergences=walk.divergences)


def _preflight(walk: _Walk, a: NormTrace, b: NormTrace,
               policy: Policy, require_distinct_subjects: bool) -> bool:
    """Return True when the evidence is inadmissible and must not be walked."""
    fatal = False

    validator = getattr(policy, "validation_problems", None)
    if callable(validator):
        try:
            problems = list(validator(strict=True))
        except TypeError:  # compatibility with an older additive API
            problems = list(validator())
        for problem in problems:
            reason = f"unsafe normalization policy: {problem}"
            walk.mark_inconclusive(reason)
            walk.emit(KIND_POLICY_UNSAFE, path="policy", a=problem, b=problem,
                      note=reason)
        fatal = fatal or bool(problems)

    for side, nt in (("A", a), ("B", b)):
        problems = list(getattr(nt, "validation_errors", ()) or ())
        if not bool(getattr(nt, "complete", True)):
            problems.append("normal-completion footer was not observed")
        for key in ("v", "module", "arch", "tap", "maxcap", "contract"):
            if key not in nt.header:
                problems.append(f"normalized header is missing required {key!r}")
        if nt.header.get("tap") != TRACE_TAP_VERSION:
            problems.append(
                f"normalized header tap {nt.header.get('tap')!r} is not "
                f"supported version {TRACE_TAP_VERSION!r}")
        unknown = list(getattr(nt, "unknown_extent", ()) or ())
        problems.extend(
            f"unverified extent at {sym}.{path}" for sym, path in unknown)
        for problem in dict.fromkeys(problems):
            source = str(getattr(nt, "source", "") or side)
            reason = f"{side} trace {source}: {problem}"
            walk.mark_inconclusive(reason)
            walk.emit(KIND_TRACE_INVALID, path=f"trace.{side.lower()}",
                      a=problem if side == "A" else None,
                      b=problem if side == "B" else None, note=reason)
        fatal = fatal or bool(problems)

    run_a = str(getattr(a, "run_id", "") or "").strip()
    run_b = str(getattr(b, "run_id", "") or "").strip()
    for side, run_id in (("A", run_a), ("B", run_b)):
        if not run_id:
            reason = f"{side} trace has no run id; independence cannot be proven"
            walk.mark_inconclusive(reason)
            walk.emit(KIND_TRACE_INVALID, path=f"header.run.{side.lower()}",
                      a=run_a or None, b=run_b or None, note=reason)
            fatal = True
    if run_a and run_a == run_b:
        reason = (f"A and B use the same run id {run_a!r}; independent "
                  "executions are required")
        walk.mark_inconclusive(reason)
        walk.emit(KIND_SAME_RUN, path="header.run", a=run_a, b=run_b,
                  note=reason)
        fatal = True

    subject_a = str(getattr(a, "subject_hash", "") or "").strip()
    subject_b = str(getattr(b, "subject_hash", "") or "").strip()
    for side, subject in (("A", subject_a), ("B", subject_b)):
        if not _is_sha256(subject):
            reason = (f"{side} trace subject is not a 64-character lowercase "
                      "SHA-256")
            walk.mark_inconclusive(reason)
            walk.emit(KIND_TRACE_INVALID,
                      path=f"header.subject.{side.lower()}",
                      a=subject_a or None, b=subject_b or None, note=reason)
            fatal = True
    if (require_distinct_subjects and _is_sha256(subject_a)
            and subject_a == subject_b):
        reason = ("A and B are bound to the same subject binary; L2 requires "
                  "distinct original and candidate binaries")
        walk.mark_inconclusive(reason)
        walk.emit(KIND_SAME_SUBJECT, path="header.subject",
                  a=subject_a, b=subject_b, note=reason)
        fatal = True

    for key in sorted(set(a.header) | set(b.header)):
        present_a, present_b = key in a.header, key in b.header
        va = a.header[key] if present_a else "<missing>"
        vb = b.header[key] if present_b else "<missing>"
        if present_a == present_b and va == vb:
            continue
        reason = f"normalized trace header differs at {key!r}"
        walk.emit(KIND_HEADER_MISMATCH, path=f"header.{key}", a=va, b=vb,
                  note=reason)
        fatal = True

    if fatal:
        # Header/source disagreement makes the record pairing meaningless.  It
        # is a failed evidence gate, not a prefix that may still be certified.
        if not walk.inconclusive_reasons:
            walk.mark_inconclusive("trace provenance does not match")
        return True
    return False


def _is_sha256(value: str) -> bool:
    return (len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def suggest_masks(result: DiffResult, contract: Contract) -> list[MaskRule]:
    """Turn A-vs-A value mismatches into narrow, automatic mask rules.

    Intended input is a determinism run (`diff(a1, a2, policy, stop_after=0)`),
    where every divergence is by definition a normalizer gap rather than a
    bug. Rules are narrowed to the exact differing bytes: masking a whole
    struct because two padding bytes wobbled would also hide the field the
    shim gets wrong.
    """
    byte_offsets: dict[tuple[str, str], set[int]] = {}
    whole_value: dict[tuple[str, str], str] = {}
    warnings: list[str] = []

    for d in result.divergences:
        key = (d.sym or "*", d.path)
        if d.kind == KIND_UNCAPTURED:
            warnings.append(
                f"{d.sym}.{d.path}: captured on one run and not the other; a "
                f"mask cannot fix this, the extent is being read "
                f"nondeterministically")
            continue
        if d.kind != KIND_VALUE_MISMATCH:
            warnings.append(
                f"{d.kind} at {d.sym or '<trace>'}"
                f"{'.' + d.path if d.path else ''}: structural, not maskable")
            continue
        if d.path == "ret" or d.path.startswith("ret."):
            # A return value that changes between two identical runs is a real
            # problem. Masking it would make every later comparison of that
            # symbol vacuous.
            msg = (f"{d.sym}.ret is nondeterministic (A={_fmt_value(d.a)} "
                   f"B={_fmt_value(d.b)}); NOT masked, investigate")
            warnings.append(msg)
            d.note = f"{d.note} | WARNING: {msg}" if d.note else f"WARNING: {msg}"
            logger.warning("refusing to mask a nondeterministic return: %s", msg)
            continue
        if _is_embedded_field_path(d.path):
            # Same refusal as `ret`, same reason. The bytes behind an embedded
            # pointer are ALREADY masked; this path is the identity token read
            # out of them, and an identity that wobbles between two identical
            # runs is a defect. Masking it would silently switch the field off
            # and hand back the hole the tokens were added to close.
            msg = (f"{d.sym}.{d.path} is an embedded pointer identity "
                   f"(A={_fmt_value(d.a)} B={_fmt_value(d.b)}); NOT masked, "
                   f"declare the field volatile in the contract if it really "
                   f"is not comparable")
            warnings.append(msg)
            d.note = f"{d.note} | WARNING: {msg}" if d.note else f"WARNING: {msg}"
            logger.warning("refusing to mask an unstable identity: %s", msg)
            continue
        if d.note == _NOTE_ONE_SIDED_FIELD:
            # Masking blanks a value; it cannot conjure a field the other run
            # never recorded, so a rule here would never close the loop.
            warnings.append(
                f"{d.sym}.{d.path}: recorded on one side only; a mask cannot "
                f"fix a field that is missing, the recorder is inconsistent")
            continue
        if d.note.startswith(_NOTE_KIND_DIFFERS):
            warnings.append(
                f"{d.sym}.{d.path}: recorded kind differs between runs "
                f"({d.a} vs {d.b}); masking does not normalize kinds")
            continue

        if d.byte_offset is not None and _is_hexish(d.a) and _is_hexish(d.b):
            if len(d.a) != len(d.b):
                warnings.append(
                    f"{d.sym}.{d.path}: captured length differs between runs "
                    f"({len(d.a) // 2} vs {len(d.b) // 2} bytes); masking "
                    f"cannot fix a length change")
                continue
            offs = _hex_diff_offsets(d.a, d.b)
            if offs:
                byte_offsets.setdefault(key, set()).update(offs)
                continue
            warnings.append(f"{d.sym}.{d.path}: byte offset reported but bytes "
                            f"compare equal; differ bug")
            continue

        if _is_symbol_token(d.a) or _is_symbol_token(d.b):
            warnings.append(
                f"{d.sym}.{d.path}: symbolic identity is unstable "
                f"({d.a} vs {d.b}); NOT masked, the identity graph is the "
                f"thing being verified")
            continue
        whole_value[key] = (f"scalar differs across identical runs "
                            f"({_fmt_value(d.a)} vs {_fmt_value(d.b)})")

    rules: list[MaskRule] = []
    for (sym, path), offs in sorted(byte_offsets.items()):
        ranges = _coalesce(sorted(offs))
        fields = _covering_fields(contract, sym, path, ranges)
        why = (f"auto: {len(offs)} byte(s) nondeterministic across identical "
               f"runs at {_fmt_ranges(ranges)}")
        if fields:
            why += f" ({', '.join(fields)})"
        rules.append(MaskRule(sym=sym, path=path, byte_ranges=ranges,
                              why=why, auto=True))
    for (sym, path), reason in sorted(whole_value.items()):
        rules.append(MaskRule(sym=sym, path=path, byte_ranges=None,
                              why=f"auto: {reason}; no byte view available",
                              auto=True))

    result.suggestions = rules
    for msg in warnings:
        if msg not in result.warnings:
            result.warnings.append(msg)
    return rules


# --- sequence walking ------------------------------------------------------


def _walk_sequence(walk: _Walk, la: list[NormRec], lb: list[NormRec]) -> None:
    i = j = 0
    while i < len(la) and j < len(lb):
        if walk.stopped:
            return
        ra, rb = la[i], lb[j]
        if ra.sym == rb.sym:
            _compare_call(walk, ra, rb)
            walk.push_a(ra)
            walk.push_b(rb)
            i += 1
            j += 1
            continue

        skip_b = _find_ahead(lb, j, ra.sym)     # B inserted calls
        skip_a = _find_ahead(la, i, rb.sym)     # B dropped calls
        if skip_b is not None and skip_a is not None and skip_a == skip_b:
            # Ambiguous: describing a swap as one insertion plus one deletion
            # is worse than calling it what it is.
            walk.emit(KIND_SYMBOL_MISMATCH, sym=ra.sym, path="",
                      a=ra.sym, b=rb.sym, seq_a=ra.seq, seq_b=rb.seq,
                      note="call order differs; both symbols reappear at the "
                           "same distance")
            walk.push_a(ra)
            walk.push_b(rb)
            i += 1
            j += 1
        elif skip_b is not None and (skip_a is None or skip_b < skip_a):
            for k in range(j, j + skip_b):
                walk.emit(KIND_EXTRA_CALL, sym=lb[k].sym, path="",
                          a=None, b=lb[k].sym, seq_b=lb[k].seq, seq_a=ra.seq,
                          note=f"call only in B; resynchronized on {ra.sym}")
                walk.push_b(lb[k])
                if walk.stopped:
                    return
            j += skip_b
        elif skip_a is not None:
            for k in range(i, i + skip_a):
                walk.emit(KIND_MISSING_CALL, sym=la[k].sym, path="",
                          a=la[k].sym, b=None, seq_a=la[k].seq, seq_b=rb.seq,
                          note=f"call only in A; resynchronized on {rb.sym}")
                walk.push_a(la[k])
                if walk.stopped:
                    return
            i += skip_a
        else:
            walk.emit(KIND_SYMBOL_MISMATCH, sym=ra.sym, path="",
                      a=ra.sym, b=rb.sym, seq_a=ra.seq, seq_b=rb.seq,
                      note=f"no resynchronization point within "
                           f"{RESYNC_WINDOW} calls")
            walk.push_a(ra)
            walk.push_b(rb)
            i += 1
            j += 1

    while i < len(la) and not walk.stopped:
        walk.emit(KIND_MISSING_CALL, sym=la[i].sym, path="", a=la[i].sym,
                  b=None, seq_a=la[i].seq, note="B ended first")
        walk.push_a(la[i])
        i += 1
    while j < len(lb) and not walk.stopped:
        walk.emit(KIND_EXTRA_CALL, sym=lb[j].sym, path="", a=None,
                  b=lb[j].sym, seq_b=lb[j].seq, note="A ended first")
        walk.push_b(lb[j])
        j += 1


def _find_ahead(seq: list[NormRec], cur: int, sym: str) -> int | None:
    """Distance from `cur` to the next `sym`, within the resync window."""
    end = min(len(seq), cur + 1 + RESYNC_WINDOW)
    for pos in range(cur + 1, end):
        if seq[pos].sym == sym:
            return pos - cur
    return None


def _compare_call(walk: _Walk, ra: NormRec, rb: NormRec) -> None:
    walk.count_pair(ra.sym)
    _compare_thread(walk, ra, rb)
    if walk.stopped:
        return
    _compare_fields(walk, ra, rb)
    if walk.stopped:
        return
    _compare_children(walk, ra, rb, 0)


def _compare_thread(walk: _Walk, ra: NormRec, rb: NormRec) -> None:
    """In global mode, thread assignment is part of observable call order."""
    if walk.compare_tid and ra.tid != rb.tid:
        walk.emit(KIND_THREAD_MISMATCH, sym=ra.sym, path="thread",
                  a=ra.tid, b=rb.tid, seq_a=ra.seq, seq_b=rb.seq,
                  note="normalized thread identity differs in global order")


def _compare_fields(walk: _Walk, ra: NormRec, rb: NormRec) -> None:
    for name in sorted(set(ra.inn) | set(rb.inn)):
        _compare_val(walk, ra, rb, f"in.{name}",
                     ra.inn.get(name), rb.inn.get(name))
        if walk.stopped:
            return
    for name in sorted(set(ra.out) | set(rb.out)):
        _compare_val(walk, ra, rb, f"out.{name}",
                     ra.out.get(name), rb.out.get(name))
        if walk.stopped:
            return
    if ra.ret is not None or rb.ret is not None:
        _compare_val(walk, ra, rb, "ret", ra.ret, rb.ret)
        if walk.stopped:
            return
    if ra.lasterr != rb.lasterr:
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path="lasterr",
                  a=ra.lasterr, b=rb.lasterr, seq_a=ra.seq, seq_b=rb.seq,
                  note="GetLastError differs" if None not in
                       (ra.lasterr, rb.lasterr)
                       else "last error recorded on one side only")


def _compare_val(walk: _Walk, ra: NormRec, rb: NormRec, path: str,
                 va: NormVal | None, vb: NormVal | None) -> None:
    if va is None and vb is None:
        return
    if va is None or vb is None:
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=path,
                  a=None if va is None else _val_repr(va),
                  b=None if vb is None else _val_repr(vb),
                  seq_a=ra.seq, seq_b=rb.seq,
                  note=_NOTE_ONE_SIDED_FIELD)
        return
    if va.k != vb.k:
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=path,
                  a=va.k, b=vb.k, seq_a=ra.seq, seq_b=rb.seq,
                  note=f"{_NOTE_KIND_DIFFERS}: {va.k} vs {vb.k}")
        return

    cap_a, cap_b = bool(va.captured), bool(vb.captured)
    if cap_a != cap_b:
        walk.emit(KIND_UNCAPTURED, sym=ra.sym, path=path,
                  a="captured" if cap_a else "uncaptured",
                  b="captured" if cap_b else "uncaptured",
                  seq_a=ra.seq, seq_b=rb.seq,
                  note="one side recorded bytes and the other declined; "
                       "usually a runtime extent field read differently")
        return
    if (va.b is None) != (vb.b is None):
        walk.emit(KIND_UNCAPTURED, sym=ra.sym, path=path,
                  a=_val_repr(va), b=_val_repr(vb),
                  seq_a=ra.seq, seq_b=rb.seq,
                  note="bytes present on one side only despite both claiming "
                       "capture")
        return

    if not _values_equal(va.v, vb.v, walk.eps):
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=path,
                  a=va.v, b=vb.v, seq_a=ra.seq, seq_b=rb.seq,
                  note="value differs")
        if walk.stopped:
            return

    # Before the bytes, deliberately: the bytes an embedded pointer occupies
    # are masked, so a wrong pointer usually shows up ONLY here -- and where
    # it does also disturb the bytes, "this field points at the wrong object"
    # is a far more precise diagnosis than "byte 8 differs".
    _compare_embedded(walk, ra, rb, path, va, vb)
    if walk.stopped:
        return

    if va.b is not None and vb.b is not None:
        _compare_bytes(walk, ra, rb, path, va.b, vb.b)


def _compare_embedded(walk: _Walk, ra: NormRec, rb: NormRec, path: str,
                      va: NormVal, vb: NormVal) -> None:
    """Compare the pointer fields the normalizer pulled out of a struct."""
    fa = getattr(va, "fields", None) or {}
    fb = getattr(vb, "fields", None) or {}
    if fa == fb:
        return
    for key in sorted(set(fa) | set(fb)):
        ta, tb = fa.get(key), fb.get(key)
        if ta == tb:
            continue
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=f"{path}.{key}",
                  a=ta, b=tb, seq_a=ra.seq, seq_b=rb.seq,
                  note=_NOTE_EMBEDDED_IDENTITY if ta is not None
                  and tb is not None else _NOTE_EMBEDDED_ONE_SIDED)
        if walk.stopped:
            return


def _compare_bytes(walk: _Walk, ra: NormRec, rb: NormRec, path: str,
                   ha: str, hb: str) -> None:
    offs = _hex_diff_offsets(ha, hb)
    if offs:
        off = offs[0]
        note = f"{len(offs)} byte(s) differ"
        if len(ha) != len(hb):
            note += f"; length also differs ({len(ha) // 2} vs {len(hb) // 2})"
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=path, a=ha, b=hb,
                  seq_a=ra.seq, seq_b=rb.seq, byte_offset=off, note=note)
        return
    if len(ha) != len(hb):
        walk.emit(KIND_VALUE_MISMATCH, sym=ra.sym, path=path, a=ha, b=hb,
                  seq_a=ra.seq, seq_b=rb.seq,
                  byte_offset=min(len(ha), len(hb)) // 2,
                  note=f"captured length differs: {len(ha) // 2} vs "
                       f"{len(hb) // 2} bytes (common prefix matches)")


def _compare_children(walk: _Walk, ra: NormRec, rb: NormRec,
                      nesting: int) -> None:
    kids_a = walk.kids_a.get(ra.seq, [])
    kids_b = walk.kids_b.get(rb.seq, [])
    if nesting >= MAX_CALLBACK_NESTING:
        if kids_a or kids_b:
            reason = (f"callback nesting comparison limit "
                      f"{MAX_CALLBACK_NESTING} reached under {ra.sym}; "
                      "remaining callbacks were not verified")
            walk.mark_inconclusive(reason)
            walk.emit(KIND_COMPARE_LIMIT, sym=ra.sym, path="callbacks.depth",
                      a=len(kids_a), b=len(kids_b), seq_a=ra.seq,
                      seq_b=rb.seq, note=reason)
        return
    if walk.max_children:
        if len(kids_a) > walk.max_children or len(kids_b) > walk.max_children:
            reason = (f"callback child comparison limit {walk.max_children} "
                      f"reached under {ra.sym}; A has {len(kids_a)}, B has "
                      f"{len(kids_b)}")
            walk.mark_inconclusive(reason)
            walk.emit(KIND_COMPARE_LIMIT, sym=ra.sym, path="callbacks.count",
                      a=len(kids_a), b=len(kids_b), seq_a=ra.seq,
                      seq_b=rb.seq, note=reason)
            if walk.stopped:
                return
        kids_a = kids_a[:walk.max_children]
        kids_b = kids_b[:walk.max_children]
    if not kids_a and not kids_b:
        return

    # Alignment runs on (sym, ordered args) rather than on the name alone:
    # every progress callback shares a name, so a name-only comparison points
    # at the end of the list instead of at the invocation that went missing.
    syms_a = [c.sym for c in kids_a]
    syms_b = [c.sym for c in kids_b]
    sigs_a = [_child_sig(c) for c in kids_a]
    sigs_b = [_child_sig(c) for c in kids_b]
    if sigs_a != sigs_b:
        idx = _first_diff_index(sigs_a, sigs_b)
        if len(sigs_a) == len(sigs_b) and sorted(sigs_a) == sorted(sigs_b):
            # Same bag in a different order: a reorder, not N value changes.
            walk.emit(KIND_CALLBACK_MISMATCH, sym=ra.sym, path=f"cb[{idx}]",
                      a=sigs_a[idx], b=sigs_b[idx],
                      seq_a=kids_a[idx].seq, seq_b=kids_b[idx].seq,
                      note=f"callbacks reordered under {ra.sym} "
                           f"(same set, different sequence)")
            return
        if syms_a != syms_b or len(kids_a) != len(kids_b):
            ca = kids_a[idx] if idx < len(kids_a) else None
            cb = kids_b[idx] if idx < len(kids_b) else None
            walk.emit(KIND_CALLBACK_MISMATCH, sym=ra.sym, path=f"cb[{idx}]",
                      a=sigs_a[idx] if idx < len(sigs_a) else None,
                      b=sigs_b[idx] if idx < len(sigs_b) else None,
                      seq_a=ca.seq if ca else ra.seq,
                      seq_b=cb.seq if cb else rb.seq,
                      note=_callback_note(ra.sym, sigs_a, sigs_b, idx, ca, cb))
            return
        # Same names, same count, different arguments: the individual field
        # comparison below localizes it far better than "callback-mismatch".

    for ca, cb in zip(kids_a, kids_b):
        if walk.stopped:
            return
        walk.count_pair(ca.sym)
        _compare_thread(walk, ca, cb)
        if walk.stopped:
            return
        _compare_fields(walk, ca, cb)
        if walk.stopped:
            return
        _compare_children(walk, ca, cb, nesting + 1)


# --- trace shaping ---------------------------------------------------------


def _seqs(nt: NormTrace) -> set[int]:
    return {r.seq for r in nt.records}


def _is_orphan(rec: NormRec, present: set[int] | None) -> bool:
    """A nested record whose parent is not in the trace.

    It is reachable neither as a root (depth > 0) nor through `_child_map`
    (nobody compares that parent seq), so without this it would never be
    compared at all. Happens whenever the parent symbol is dropped -- an
    `ignore_symbols` entry naming the caller, or a torn trace.
    """
    if present is None:
        return False
    parent = getattr(rec.origin, "parent", None)
    return parent is None or parent not in present


def _roots(recs: list[NormRec], ignore: set[str],
           present: set[int] | None = None) -> list[NormRec]:
    out = [r for r in recs
           if r.sym not in ignore
           and (r.depth <= 0 or _is_orphan(r, present))]
    out.sort(key=lambda r: r.seq)
    return out


def _ordered_threads(nt: NormTrace,
                     ignore: set[str]) -> list[tuple[int, list[NormRec]]]:
    """Threads paired by first appearance, not by raw OS tid."""
    groups: dict[int, list[NormRec]] = {}
    source = nt.threads if getattr(nt, "threads", None) else None
    if source:
        for tid, recs in source.items():
            groups[tid] = list(recs)
    else:
        for rec in nt.records:
            groups.setdefault(rec.tid, []).append(rec)
    present = _seqs(nt)
    out: list[tuple[int, list[NormRec]]] = []
    for tid, recs in groups.items():
        roots = _roots(recs, ignore, present)
        if roots:
            out.append((tid, roots))
    out.sort(key=lambda kv: kv[1][0].seq)
    return out


def _child_map(nt: NormTrace, ignore: set[str]) -> dict[int, list[NormRec]]:
    out: dict[int, list[NormRec]] = {}
    for rec in nt.records:
        if rec.sym in ignore:
            continue
        parent = getattr(rec.origin, "parent", None)
        if parent is None:
            continue
        out.setdefault(int(parent), []).append(rec)
    for recs in out.values():
        recs.sort(key=lambda r: r.seq)
    return out


def _callback_note(parent: str, sigs_a: list[str], sigs_b: list[str],
                   idx: int, ca: NormRec | None, cb: NormRec | None) -> str:
    if ca is None:
        return f"B invokes an extra callback under {parent}"
    if cb is None:
        return f"B never invokes {ca.sym} under {parent}"
    if ca.sym != cb.sym:
        return f"different callback under {parent}: {ca.sym} vs {cb.sym}"
    # Same name either side: decide insertion vs deletion by which signature
    # turns up again further along the other list.
    if sigs_b[idx] in sigs_a[idx + 1:]:
        return f"B skips one {ca.sym} invocation under {parent}"
    if sigs_a[idx] in sigs_b[idx + 1:]:
        return f"B adds one {cb.sym} invocation under {parent}"
    if len(sigs_a) > len(sigs_b):
        return f"B invokes {ca.sym} fewer times under {parent}"
    return f"B invokes {cb.sym} more times under {parent}"


def _child_sig(rec: NormRec) -> str:
    """Identity of a callback invocation: name plus its ordered arguments."""
    args = ",".join(f"{k}={_val_repr(rec.inn[k])}" for k in sorted(rec.inn))
    return f"{rec.sym}({args})"


def _val_repr(v: NormVal) -> str:
    if v.b is not None:
        return f"{v.k}:{v.v!r}/{v.b}"
    return f"{v.k}:{v.v!r}"


# --- value comparison ------------------------------------------------------


def _values_equal(x: Any, y: Any, eps: float) -> bool:
    if x is None or y is None:
        return x is None and y is None
    if isinstance(x, bool) or isinstance(y, bool):
        return x is y
    if isinstance(x, float) or isinstance(y, float):
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            if math.isnan(x) and math.isnan(y):
                return True
            if math.isinf(x) or math.isinf(y):
                return x == y
            return abs(x - y) <= eps
    return x == y


def _hex_diff_offsets(ha: str, hb: str) -> list[int]:
    """Byte indices where two hex strings differ, skipping masked bytes.

    Hex digit case carries no information: 0xAA and 0xaa are one byte. The
    comparison is therefore case insensitive, but only on the slow path, so
    the common all-equal case still costs one string compare per byte.
    """
    n = min(len(ha), len(hb)) // 2
    out = []
    for i in range(n):
        x = ha[2 * i:2 * i + 2]
        y = hb[2 * i:2 * i + 2]
        if x == y or x == ".." or y == "..":
            continue
        if x.lower() != y.lower():
            out.append(i)
    return out


def _coalesce(offsets: list[int]) -> list[tuple[int, int]]:
    ranges: list[list[int]] = []
    for off in offsets:
        if ranges and off == ranges[-1][0] + ranges[-1][1]:
            ranges[-1][1] += 1
        else:
            ranges.append([off, 1])
    return [(o, n) for o, n in ranges]


def _covering_fields(contract: Contract, sym: str, path: str,
                     ranges: list[tuple[int, int]]) -> list[str]:
    """Struct fields the suggested ranges land in, for the `why` text."""
    spec = contract.symbols.get(sym) if contract else None
    if spec is None:
        return []
    section, _, name = path.partition(".")
    if section not in ("in", "out"):
        return []
    arg = spec.arg_by_name(name)
    struct_name = arg.struct if arg else None
    if not struct_name:
        return []
    struct = contract.structs.get(struct_name)
    if struct is None:
        return []
    names: list[str] = []
    for off, size in ranges:
        for f in struct.fields:
            if off < f.off + f.size and f.off < off + size:
                label = f"{struct.name}.{f.name}"
                if label not in names:
                    names.append(label)
    return names


def _is_hexish(v: Any) -> bool:
    return (isinstance(v, str) and len(v) % 2 == 0 and len(v) > 0
            and set(v) <= _HEX_CHARS)


def _is_symbol_token(v: Any) -> bool:
    return isinstance(v, str) and v.startswith("@")


def _is_embedded_field_path(path: str) -> bool:
    """`in.<arg>.<field>` / `out.<arg>.<field>`, the shape `_compare_embedded`
    emits. A mask addresses a whole value or byte ranges within it, so it has
    no way to name a field path in the first place."""
    section, _, rest = path.partition(".")
    return section in ("in", "out") and "." in rest


def _first_diff_index(xs: list[Any], ys: list[Any]) -> int:
    for i in range(min(len(xs), len(ys))):
        if xs[i] != ys[i]:
            return i
    return min(len(xs), len(ys))


def _first_seq(threads: list[tuple[int, list[NormRec]]]) -> int | None:
    return threads[0][1][0].seq if threads else None


# --- rendering -------------------------------------------------------------


def _render_divergence(d: Divergence) -> list[str]:
    lines = [f"first divergence: {d.kind}",
             f"  seq          A={_seq_str(d.seq_a)}  B={_seq_str(d.seq_b)}",
             f"  symbol       {d.sym or '-'}",
             f"  path         {d.path or '-'}",
             f"  A            {_fmt_value(d.a, d.byte_offset)}",
             f"  B            {_fmt_value(d.b, d.byte_offset)}"]
    if d.byte_offset is not None:
        detail = ""
        if _is_hexish(d.a) and _is_hexish(d.b):
            ba = _byte_at(d.a, d.byte_offset)
            bb = _byte_at(d.b, d.byte_offset)
            if ba or bb:
                detail = f"  (A={ba or '--'} B={bb or '--'})"
        lines.append(f"  byte offset  {d.byte_offset}{detail}")
    if d.note:
        lines.append(f"  note         {d.note}")
    if d.context_a:
        lines.append(f"  context A    {_fmt_context(d.context_a)}")
    if d.context_b:
        lines.append(f"  context B    {_fmt_context(d.context_b)}")
    return lines


def _fmt_context(recs: list[NormRec]) -> str:
    return " -> ".join(f"#{r.seq} {r.sym}" for r in recs)


def _fmt_value(v: Any, byte_offset: int | None = None) -> str:
    if v is None:
        return "<absent>"
    if isinstance(v, str):
        if byte_offset is not None and _is_hexish(v) and len(v) > 96:
            return _hex_window(v, byte_offset)
        return v if len(v) <= 96 else v[:93] + "..."
    return repr(v)


def _hex_window(hexstr: str, off: int, span: int = 6) -> str:
    total = len(hexstr) // 2
    start = max(0, off - span)
    end = min(total, off + span + 1)
    chunk = " ".join(hexstr[2 * i:2 * i + 2] for i in range(start, end))
    lead = "..." if start > 0 else ""
    tail = "..." if end < total else ""
    return f"{lead}{chunk}{tail} (bytes {start}-{end - 1} of {total})"


def _byte_at(hexstr: str, off: int) -> str:
    return hexstr[2 * off:2 * off + 2] if len(hexstr) >= 2 * off + 2 else ""


def _fmt_ranges(ranges: list[tuple[int, int]] | None) -> str:
    if ranges is None:
        return "[whole value]"
    if not ranges:
        return "[]"
    return "[" + ",".join(f"{o}+{n}" for o, n in ranges) + "]"


def _seq_str(seq: int | None) -> str:
    return "-" if seq is None else f"#{seq}"


def _rec_json(rec: NormRec) -> dict[str, Any]:
    return {"seq": rec.seq, "tid": rec.tid, "sym": rec.sym,
            "depth": rec.depth}


def _json_value(v: Any) -> Any:
    if isinstance(v, str) and len(v) > _MAX_JSON_VALUE:
        return v[:_MAX_JSON_VALUE] + f"...[{len(v)} chars]"
    if isinstance(v, (int, float, bool, str)) or v is None:
        return v
    return repr(v)


def _mask_json(rule: MaskRule) -> dict[str, Any]:
    to_json = getattr(rule, "to_json", None)
    if callable(to_json):
        return to_json()
    if is_dataclass(rule):
        return asdict(rule)
    return {"repr": repr(rule)}


# --- self test -------------------------------------------------------------


def _selftest() -> None:  # pragma: no cover - exercised by running the module
    import json

    from .trace import REC_CALL, REC_CALLBACK, Rec

    def mk(seq: int, sym: str, *, tid: int = 1, depth: int = 0,
           parent: int | None = None, inn: dict[str, NormVal] | None = None,
           out: dict[str, NormVal] | None = None,
           ret: NormVal | None = None,
           lasterr: int | None = None) -> NormRec:
        origin = Rec(t=REC_CALLBACK if depth else REC_CALL, seq=seq, sym=sym,
                     tid=tid, depth=depth, parent=parent)
        return NormRec(seq=seq, tid=tid, sym=sym, depth=depth,
                       parent_sym=None, inn=inn or {}, out=out or {},
                       ret=ret, lasterr=lasterr, origin=origin)

    run_counter = iter(range(1, 10000))

    def tr(recs: list[NormRec], *,
           header: dict[str, Any] | None = None,
           run_id: str | None = None, complete: bool = True,
           errors: list[str] | None = None,
           subject_hash: str = "1" * 64) -> NormTrace:
        threads: dict[int, list[NormRec]] = {}
        for r in recs:
            threads.setdefault(r.tid, []).append(r)
        return NormTrace(header=header or {"v": 1,
                                           "module": "oldlib.dll",
                                           "arch": "x64",
                                           "tap": TRACE_TAP_VERSION,
                                           "maxcap": 65536,
                                           "contract": "0" * 64,
                                           "label": "selftest"}, threads=threads,
                         records=list(recs), symbol_table={},
                         unknown_extent=[],
                         run_id=(run_id if run_id is not None
                                 else f"selftest-{next(run_counter)}"),
                         subject_hash=subject_hash,
                         complete=complete,
                         validation_errors=list(errors or ()),
                         source="selftest")

    def i32(v: int) -> NormVal:
        return NormVal(k="i32", v=v)

    def buf(hexs: str) -> NormVal:
        return NormVal(k="ptr", v="@h#1", b=hexs)

    class _TestPolicy(Policy):
        """Exercise guarded legacy modes without weakening production gates."""
        def validation_problems(self, *, strict: bool = True) -> list[str]:
            return []

    pol = Policy(masks=[], thread_mode="global")
    contract = Contract(module="oldlib.dll")

    def base() -> list[NormRec]:
        return [
            mk(1, "Init", inn={"flags": i32(0)}, ret=i32(0)),
            mk(2, "Open", inn={"name": NormVal(k="str", v="in.bin")},
               out={"h": NormVal(k="handle", v="@h#1")}, ret=i32(0)),
            mk(3, "Process", inn={"h": NormVal(k="handle", v="@h#1"),
                                  "buf": buf("18000000010000000c000000")},
               out={"buf": buf("18000000010000000c000000")}, ret=i32(0),
               lasterr=0),
            mk(4, "Close", inn={"h": NormVal(k="handle", v="@h#1")},
               ret=i32(0)),
        ]

    # clean
    res = diff(tr(base()), tr(base()), pol)
    assert res.ok and res.total == 0, res.render()
    assert res.compared_calls == 4, res.compared_calls
    assert res.per_symbol["Process"] == 1
    print("[ok] clean pair -> ok=True,", res.compared_calls, "calls")

    # Empty, malformed, reused, and wrong-provenance evidence must never PASS.
    res = diff(tr([]), tr([]), pol)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_TRACE_INVALID, res.first
    print("[ok] empty pair is inconclusive, never PASS")

    bad = tr(base(), complete=False, errors=["missing completion footer"])
    res = diff(bad, tr(base()), pol)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_TRACE_INVALID, res.first
    assert res.compared_calls == 0
    print("[ok] invalid/incomplete trace rejected before record walk")

    res = diff(tr(base(), run_id="same"), tr(base(), run_id="same"), pol)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_SAME_RUN, res.first
    print("[ok] identical nonempty run ids rejected")

    res = diff(tr(base(), subject_hash="a" * 64),
               tr(base(), subject_hash="a" * 64), pol,
               require_distinct_subjects=True)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_SAME_SUBJECT, res.first
    print("[ok] L2 rejects identical subject binaries")

    hdr_b = {"v": 1, "module": "different.dll", "arch": "x86",
             "tap": TRACE_TAP_VERSION, "maxcap": 32768,
             "contract": "0" * 64,
             "label": "other"}
    res = diff(tr(base()), tr(base(), header=hdr_b), pol, stop_after=0)
    assert not res.ok and not res.conclusive, res.render()
    paths = {d.path for d in res.divergences}
    assert {"header.module", "header.arch", "header.label",
            "header.maxcap"} <= paths, paths
    assert res.compared_calls == 0
    print("[ok] normalized module/arch/label/maxcap mismatches rejected")

    wrong_tap = tr(base())
    wrong_tap.header["tap"] = "999"
    res = diff(tr(base()), wrong_tap, pol)
    assert not res.ok and res.first.kind == KIND_TRACE_INVALID, res.render()
    assert "supported version" in res.first.note, res.first.note
    print("[ok] unsupported recorder version rejected")

    # value-mismatch on a scalar return
    b_recs = base()
    b_recs[2].ret = i32(-1)
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.first.kind == KIND_VALUE_MISMATCH, res.first
    assert res.first.path == "ret" and res.first.b == -1
    assert res.total == 1 and res.first.context_a[-1].sym == "Open"
    print("[ok] value-mismatch (ret):", res.first.one_line())

    # value-mismatch on bytes, with byte_offset
    b_recs = base()
    b_recs[2].out["buf"] = buf("18000000020000000c000000")
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.first.kind == KIND_VALUE_MISMATCH, res.first
    assert res.first.path == "out.buf", res.first.path
    assert res.first.byte_offset == 4, res.first.byte_offset
    print("[ok] value-mismatch (bytes) at offset", res.first.byte_offset)

    # the same byte, masked out -> must not fire
    b_recs = base()
    b_recs[2].inn["buf"] = buf("18000000..0000000c000000")
    b_recs[2].out["buf"] = buf("18000000..0000000c000000")
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.ok, res.render()
    print("[ok] masked bytes ('..') do not fire")

    # An embedded pointer field: the bytes it lives in are masked, so this is
    # the only signal a wrong-but-readable pointer leaves behind.
    def pbuf(hexs: str, data: str | None) -> NormVal:
        return NormVal(k="ptr", v="@h#2", b=hexs,
                       fields=None if data is None else {"data": data})

    def with_field(a_data: str, b_data: str,
                   b_hex: str = "18000000........0c000000") -> DiffResult:
        a_recs, b_recs = base(), base()
        a_recs[2].out["buf"] = pbuf("18000000........0c000000", a_data)
        b_recs[2].out["buf"] = pbuf(b_hex, b_data)
        return diff(tr(a_recs), tr(b_recs), pol)

    res = with_field("@ext#2", "@ext#2")
    assert res.ok, res.render()
    res = with_field("@ext#2", "@ext#7")
    assert res.first.kind == KIND_VALUE_MISMATCH, res.first
    assert res.first.path == "out.buf.data", res.first.path
    assert (res.first.a, res.first.b) == ("@ext#2", "@ext#7"), res.first
    print("[ok] embedded pointer identity ->", res.first.one_line())

    # A field present on one side only is reported, not skipped.
    res = with_field("@ext#2", None)
    assert res.first.path == "out.buf.data" and res.first.b is None, res.first
    assert "one side only" in res.first.note, res.first.note

    # Ordering: when the pointer is wrong AND the bytes moved, the field is
    # the reported divergence -- it names the defect, the bytes only echo it.
    res = with_field("@ext#2", "@ext#7", b_hex="18000000........0d000000")
    assert res.first.path == "out.buf.data", res.first.path
    print("[ok] field comparison precedes byte comparison")

    # suggest_masks must refuse: masking cannot address a field path, and an
    # identity that wobbles A-vs-A is a defect rather than noise.
    det_f = with_field("@ext#2", "@ext#7")
    rules_f = suggest_masks(det_f, contract)
    assert rules_f == [], rules_f
    assert any("NOT masked" in w and "out.buf.data" in w
               for w in det_f.warnings), det_f.warnings
    print("[ok] suggest_masks refuses", det_f.warnings[0][:72] + "...")

    # length difference on captured bytes
    b_recs = base()
    b_recs[2].out["buf"] = buf("18000000010000000c00000000000000")
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.first.kind == KIND_VALUE_MISMATCH and res.first.byte_offset == 12
    print("[ok] byte length difference at offset", res.first.byte_offset)

    # missing-call must not cascade
    b_recs = [r for r in base() if r.sym != "Process"]
    res = diff(tr(base()), tr(b_recs), pol, stop_after=0)
    assert res.total == 1, [d.one_line() for d in res.divergences]
    assert res.first.kind == KIND_MISSING_CALL and res.first.sym == "Process"
    assert res.compared_calls == 3, res.compared_calls
    print("[ok] missing-call resynchronized, total =", res.total)

    # extra-call
    a_recs = [r for r in base() if r.sym != "Process"]
    res = diff(tr(a_recs), tr(base()), pol, stop_after=0)
    assert res.total == 1 and res.first.kind == KIND_EXTRA_CALL, res.render()
    print("[ok] extra-call resynchronized, total =", res.total)

    # symbol-mismatch when nothing resynchronizes
    b_recs = base()
    b_recs[2] = mk(3, "ProcessEx")
    res = diff(tr(base()), tr(b_recs), pol, stop_after=0)
    assert res.first.kind == KIND_SYMBOL_MISMATCH, res.first
    assert res.first.a == "Process" and res.first.b == "ProcessEx"
    print("[ok] symbol-mismatch:", res.first.a, "vs", res.first.b)

    # thread-count
    b_recs = base() + [mk(5, "Init", tid=2, ret=i32(0))]
    per_thread_pol = _TestPolicy(masks=[], thread_mode="per-thread")
    res = diff(tr(base()), tr(b_recs), per_thread_pol)
    assert res.first.kind == KIND_THREAD_COUNT, res.first
    assert res.first.a == 1 and res.first.b == 2
    print("[ok] thread-count:", res.first.a, "vs", res.first.b)

    # Global ordering must also preserve which normalized thread made a call.
    b_recs = base()
    b_recs[2].tid = 2
    b_recs[2].origin.tid = 2
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.first.kind == KIND_THREAD_MISMATCH, res.first
    assert (res.first.a, res.first.b) == (1, 2), res.first
    print("[ok] global normalized thread mismatch is observable")

    # uncaptured-vs-captured
    b_recs = base()
    b_recs[2].out["buf"] = NormVal(k="ptr", v="@h#1", b=None, captured=False)
    res = diff(tr(base()), tr(b_recs), pol)
    assert res.first.kind == KIND_UNCAPTURED, res.first
    assert res.first.path == "out.buf"
    print("[ok] uncaptured-vs-captured on", res.first.path)

    # callback-mismatch: dropped child
    def with_cbs(pcts: list[int]) -> list[NormRec]:
        recs = base()
        for n, pct in enumerate(pcts):
            recs.append(mk(10 + n, "cb_progress", depth=1, parent=3,
                           inn={"pct": i32(pct)}, ret=i32(0)))
        return recs

    res = diff(tr(with_cbs([25, 50, 100])), tr(with_cbs([25, 100])), pol)
    assert res.first.kind == KIND_CALLBACK_MISMATCH, res.first
    assert res.first.path == "cb[1]", res.first.path
    print("[ok] callback-mismatch (dropped):", res.first.note)

    # callback-mismatch: reordered children (same bag, different order)
    res = diff(tr(with_cbs([25, 50, 100])), tr(with_cbs([50, 25, 100])), pol)
    assert res.first.kind == KIND_CALLBACK_MISMATCH, res.first
    assert "reordered" in res.first.note, res.first.note
    assert res.first.path == "cb[0]", res.first.path
    print("[ok] callback-mismatch (reordered):", res.first.note)

    # a value change inside a matched callback is a value-mismatch, not a
    # callback-mismatch
    res = diff(tr(with_cbs([25, 50, 100])), tr(with_cbs([25, 51, 100])), pol)
    assert res.first.kind == KIND_VALUE_MISMATCH, res.first
    assert res.first.sym == "cb_progress" and res.first.path == "in.pct"
    print("[ok] callback value change ->", res.first.one_line())

    # A configured child bound and the hard nesting guard are safety stops,
    # never permission to certify the compared prefix.
    limit_pol = _TestPolicy(masks=[], thread_mode="global",
                            max_children_compare=2)
    res = diff(tr(with_cbs([10, 20, 30])),
               tr(with_cbs([10, 20, 30])), limit_pol)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_COMPARE_LIMIT, res.first
    assert res.first.path == "callbacks.count"
    print("[ok] max_children truncation is inconclusive")

    def deep_callbacks() -> list[NormRec]:
        recs = [mk(1, "Root", ret=i32(0))]
        parent = 1
        for depth in range(1, MAX_CALLBACK_NESTING + 2):
            seq = depth + 1
            recs.append(mk(seq, "NestedCB", depth=depth, parent=parent,
                           inn={"depth": i32(depth)}, ret=i32(0)))
            parent = seq
        return recs

    res = diff(tr(deep_callbacks()), tr(deep_callbacks()), pol)
    assert not res.ok and not res.conclusive, res.render()
    assert res.first.kind == KIND_COMPARE_LIMIT, res.first
    assert res.first.path == "callbacks.depth"
    print("[ok] callback nesting guard is inconclusive")

    # suggest_masks over an A-vs-A determinism run
    a_recs, b_recs = base(), base()
    a_recs[2].out["buf"] = buf("1800000001000000aabbccdd")
    b_recs[2].out["buf"] = buf("1800000001000000aa00ffdd")
    a_recs[1].ret = i32(0)
    b_recs[1].ret = i32(7)
    a_recs[0].lasterr = 0
    b_recs[0].lasterr = 122
    det = diff(tr(a_recs), tr(b_recs), pol, stop_after=0)
    assert det.total == 3, [d.one_line() for d in det.divergences]
    rules = suggest_masks(det, contract)
    by_path = {(r.sym, r.path): r for r in rules}
    assert ("Process", "out.buf") in by_path, by_path
    assert by_path[("Process", "out.buf")].byte_ranges == [(9, 2)], \
        by_path[("Process", "out.buf")].byte_ranges
    assert by_path[("Process", "out.buf")].auto is True
    assert ("Init", "lasterr") in by_path, by_path
    assert by_path[("Init", "lasterr")].byte_ranges is None
    assert not any(r.path == "ret" for r in rules), rules
    assert any("nondeterministic" in w for w in det.warnings), det.warnings
    print("[ok] suggest_masks ->", _fmt_ranges(
        by_path[("Process", "out.buf")].byte_ranges), "+ ret warning")

    # rendering and json
    b_recs = base()
    b_recs[2].out["buf"] = buf("18000000020000000c000000")
    res = diff(tr(base()), tr(b_recs), pol)
    text = res.render()
    assert len(text.splitlines()) <= 40, len(text.splitlines())
    assert "out.buf" in text and "byte offset  4" in text
    blob = json.dumps(res.to_json())
    assert json.loads(blob)["first"]["byte_offset"] == 4
    suggest_masks(det, contract)
    json.dumps(det.to_json())
    print("[ok] render() is", len(text.splitlines()), "lines; to_json() "
          "serializes")
    print()
    print(text)
    print()
    print("all tracediff self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.ERROR)
    _selftest()
