"""Normalization policy and contract-derived mask rules.

Strict policies mask only embedded pointer address bytes. Pointer identity is
compared separately, and all other captured bytes remain visible.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .model import ArgSpec, Contract, StructSpec

logger = logging.getLogger(__name__)

_WILDCARD_CHARS = "*?["


def match_pattern(pattern: str, value: str) -> bool:
    """Match a rule pattern against a symbol name or field path.

    Exact equality is tested before glob interpretation because decorated
    C++ export names legitimately contain `?` and `[`, which fnmatch would
    otherwise read as wildcards and mis-match.
    """
    if pattern == value or pattern == "*":
        return True
    if any(c in pattern for c in _WILDCARD_CHARS):
        return fnmatchcase(value, pattern)
    return False


@dataclass
class MaskRule:
    """One "do not compare these bytes" declaration.

    `byte_ranges` is a list of (offset, size) pairs, matching the shape
    `StructSpec.masked_ranges()` returns. `None` means the whole value.
    """

    sym: str = "*"            # symbol name, glob, or "*"
    path: str = ""            # "in.buf" | "out.buf" | "ret" | "lasterr" | "*"
    byte_ranges: list[tuple[int, int]] | None = None   # None = whole value
    why: str = ""
    auto: bool = False        # derived, not hand written

    @property
    def whole_value(self) -> bool:
        return self.byte_ranges is None

    def matches(self, sym: str, path: str) -> bool:
        # An empty path is treated as "*": a rule that names only a symbol
        # applies to every field of it. The spec lists no other meaning for
        # the "" default, and the alternative (match nothing) would make the
        # dataclass default useless.
        if not match_pattern(self.sym, sym):
            return False
        if self.path == "":
            return True
        return match_pattern(self.path, path)

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"sym": self.sym, "path": self.path}
        if self.byte_ranges is not None:
            d["ranges"] = [[o, s] for o, s in self.byte_ranges]
        if self.why:
            d["why"] = self.why
        if self.auto:
            d["auto"] = True
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "MaskRule":
        raw = d.get("ranges")
        return cls(
            sym=d.get("sym", "*"), path=d.get("path", ""),
            byte_ranges=None if raw is None
            else [(int(o), int(s)) for o, s in raw],
            why=d.get("why", ""), auto=bool(d.get("auto", False)))


@dataclass
class Policy:
    masks: list[MaskRule]
    # Verification is deliberately fail-closed.  A non-zero tolerance can
    # make two observably different floating-point results compare equal, so
    # callers that need a tolerance must first turn it into an explicit,
    # reviewed semantic comparator rather than a global epsilon.
    float_eps: float = 0.0
    # Strict verification preserves the recorder's global event order and
    # checks the normalized thread assignment on every event. Splitting the
    # trace into independent thread streams can miss cross-thread reordering.
    thread_mode: str = "global"         # strict: global only
    symbolize_pointers: bool = True
    ignore_symbols: list[str] = field(default_factory=list)
    max_children_compare: int = 0       # 0 = unlimited
    _verified_mask_keys: frozenset[tuple] = field(
        default_factory=frozenset, init=False, repr=False, compare=False)

    def validation_problems(self, *, strict: bool = True,
                            contract: Contract | None = None) -> list[str]:
        """Return policy settings that can make a clean diff vacuous.

        Production verification prefers false negatives to false positives.
        Consequently every broad erasure mechanism is rejected in strict
        mode. Byte-range masks remain usable only when exactly derived for
        pointer bytes: that representation layer compares identity separately;
        whole-value and user-authored range masks do not have that property.
        """
        problems: list[str] = []
        if self.thread_mode not in ("per-thread", "global"):
            problems.append(f"unsupported thread_mode {self.thread_mode!r}")
        elif strict and self.thread_mode != "global":
            problems.append(
                "thread_mode='per-thread' can hide cross-thread event "
                "reordering; strict verification requires 'global'")
        if not math.isfinite(self.float_eps) or self.float_eps < 0:
            problems.append(f"float_eps must be finite and >= 0, got {self.float_eps!r}")
        elif strict and self.float_eps != 0:
            problems.append(
                f"float_eps={self.float_eps!r} can hide a real value change; "
                "strict verification requires 0")
        if strict and self.ignore_symbols:
            problems.append(
                "ignore_symbols removes calls from comparison: "
                + ", ".join(map(str, self.ignore_symbols)))
        if strict and not self.symbolize_pointers:
            problems.append(
                "symbolize_pointers=False erases pointer/handle identity")
        if self.max_children_compare < 0:
            problems.append("max_children_compare must be >= 0")
        elif strict and self.max_children_compare:
            problems.append(
                f"max_children_compare={self.max_children_compare} truncates "
                "callback comparison")
        allowed_mask_keys = set(self._verified_mask_keys)
        if contract is not None:
            allowed_mask_keys = _derived_mask_keys(contract)
        for i, rule in enumerate(self.masks):
            where = f"{rule.sym}.{rule.path or '*'}"
            if strict and rule.byte_ranges is None:
                problems.append(
                    f"mask[{i}] {where} hides a whole value")
                continue
            if rule.byte_ranges is None:
                continue
            for off, size in rule.byte_ranges:
                if off < 0 or size <= 0:
                    problems.append(
                        f"mask[{i}] {where} has invalid range ({off}, {size})")
            if strict and _rule_key(rule) not in allowed_mask_keys:
                problems.append(
                    f"mask[{i}] {where} is not an exact mask derived from "
                    "the active contract")
        return problems

    def assert_safe(self, *, strict: bool = True,
                    contract: Contract | None = None) -> None:
        problems = self.validation_problems(strict=strict, contract=contract)
        if problems:
            raise ValueError(
                "unsafe normalization policy:\n  " + "\n  ".join(problems))
        if strict and contract is not None:
            self._verified_mask_keys = frozenset(_derived_mask_keys(contract))

    @classmethod
    def derive(cls, contract: Contract,
               extra: list[MaskRule] | None = None) -> "Policy":
        """Auto-emit pointer-byte masks for every struct-typed argument.

        Callback arguments are walked too: callback records land in the
        trace under the callback's own name, so a mask keyed on the parent
        symbol would never fire for them.
        """
        masks: list[MaskRule] = []
        for sym in sorted(contract.symbols.values(), key=lambda s: s.name):
            _derive_args(contract, sym.name, sym.args, masks)
        for cb in sorted(contract.callbacks.values(), key=lambda c: c.name):
            _derive_args(contract, cb.name, cb.args, masks)
        logger.debug("derived %d auto mask rules from %s",
                     len(masks), contract.module)
        pol = cls(masks=masks)
        pol._verified_mask_keys = frozenset(_rule_key(r) for r in masks)
        return pol.merged_with(extra) if extra else pol

    def masks_for(self, sym: str, path: str) -> list[MaskRule]:
        return [m for m in self.masks if m.matches(sym, path)]

    def merged_with(self, rules: list[MaskRule]) -> "Policy":
        """Append rules, dropping ones already present.

        Deduping matters because `--write-policy` folds determinism
        suggestions back into a saved policy on every oracle run, and
        without it the file grows a duplicate set each time.
        """
        out = list(self.masks)
        seen = {_rule_key(r) for r in out}
        for r in rules:
            key = _rule_key(r)
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return replace(self, masks=out)

    def to_json(self) -> dict[str, Any]:
        return {
            "masks": [m.to_json() for m in self.masks],
            "float_eps": self.float_eps,
            "thread_mode": self.thread_mode,
            "symbolize_pointers": self.symbolize_pointers,
            "ignore_symbols": list(self.ignore_symbols),
            "max_children_compare": self.max_children_compare,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Policy":
        return cls(
            masks=[MaskRule.from_json(m) for m in d.get("masks", [])],
            float_eps=float(d.get("float_eps", 0.0)),
            thread_mode=d.get("thread_mode", "global"),
            symbolize_pointers=bool(d.get("symbolize_pointers", True)),
            ignore_symbols=list(d.get("ignore_symbols", [])),
            max_children_compare=int(d.get("max_children_compare", 0)))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_json(), indent=2, ensure_ascii=False),
            encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))


def _derive_args(contract: Contract, sym: str, args: list[ArgSpec],
                 out: list[MaskRule]) -> None:
    for arg in args:
        name = arg.struct or (arg.extent.struct if arg.extent else None)
        if not name:
            continue
        spec = contract.structs.get(name)
        if spec is None:
            # Contract.validate() already reports this; derive must not raise
            # on a contract the caller chose to use anyway.
            logger.warning("%s.%s: undeclared struct '%s', no mask derived",
                           sym, arg.name, name)
            continue
        # Pointer bytes go in here too: raw addresses would diff on every
        # call. Their identity survives as a token (see normalize.py), so
        # masking the bytes loses nothing and removes the noise.
        ranges = spec.noncomparable_ranges()
        if not ranges:
            continue
        why = _derive_why(spec)
        # Both directions unconditionally: dir is advisory, and a mask on a
        # path that never appears in the trace simply never fires.
        for path in (f"in.{arg.name}", f"out.{arg.name}"):
            out.append(MaskRule(sym=sym, path=path, byte_ranges=list(ranges),
                                why=why, auto=True))


def _derive_why(spec: StructSpec) -> str:
    """Say WHICH kind of non-comparable byte a derived rule covers.

    A reader of a saved policy has to be able to tell "this range is
    allocator garbage" from "this range is a pointer we compare as an
    identity token elsewhere"; the two invite completely different reactions
    when a diff turns up nearby.
    """
    parts: list[str] = []
    pointers = spec.pointer_fields()
    if pointers:
        parts.append("pointer identity compared as tokens ("
                     + ", ".join(f.name for f in pointers) + ")")
    return f"{spec.name}: " + " + ".join(parts)


def _rule_key(r: MaskRule) -> tuple:
    ranges = (None if r.byte_ranges is None
              else tuple((int(o), int(s)) for o, s in r.byte_ranges))
    return (r.sym, r.path, ranges)


def _derived_mask_keys(contract: Contract) -> set[tuple]:
    masks: list[MaskRule] = []
    for sym in sorted(contract.symbols.values(), key=lambda s: s.name):
        _derive_args(contract, sym.name, sym.args, masks)
    for cb in sorted(contract.callbacks.values(), key=lambda c: c.name):
        _derive_args(contract, cb.name, cb.args, masks)
    return {_rule_key(rule) for rule in masks}


if __name__ == "__main__":
    import tempfile

    from .model import Extent, FieldSpec, StructSpec, SymbolSpec

    logging.basicConfig(level=logging.DEBUG)

    buf = StructSpec(
        name="OLD_BUF", size=24,
        fields=[FieldSpec("size", 0, 4, "u32"),
                FieldSpec("data", 8, 8, "ptr"),
                FieldSpec("len", 16, 4, "u32")])
    con = Contract(module="oldlib.dll", arch="x64")
    con.structs["OLD_BUF"] = buf
    con.symbols["Process"] = SymbolSpec(
        name="Process", ret="i32",
        args=[ArgSpec("h", "handle"),
              ArgSpec("buf", "ptr", dir="inout", struct="OLD_BUF"),
              ArgSpec("flags", "i32")])
    con.symbols["Close"] = SymbolSpec(
        name="Close", ret="i32", args=[ArgSpec("h", "handle", releases="h")])
    con.symbols["ProcessMany"] = SymbolSpec(
        name="ProcessMany", ret="i32",
        args=[ArgSpec("count", "u32"),
              ArgSpec("items", "ptr", struct="OLD_BUF",
                      extent=Extent(arg="count", scale=24))])
    assert con.validate() == [], con.validate()

    pol = Policy.derive(con)
    got = {(m.sym, m.path): m.byte_ranges for m in pol.masks}
    assert set(got) == {("Process", "in.buf"), ("Process", "out.buf"),
                        ("ProcessMany", "in.items"),
                        ("ProcessMany", "out.items")}, sorted(got)
    assert all(v == [(8, 8)] for v in got.values()), got
    assert all(m.auto for m in pol.masks)
    print(f"derive: {len(pol.masks)} rules, ranges {got[('Process', 'in.buf')]}")

    # A NON-volatile pointer field: the bytes are still masked (a raw address
    # diffs every run) but the reason has to say so, because the field is
    # compared -- as a token -- rather than dropped.
    live = StructSpec(
        name="LIVE_BUF", size=24,
        fields=[FieldSpec("size", 0, 4, "u32"),
                FieldSpec("data", 8, 8, "ptr"),
                FieldSpec("len", 16, 4, "u32")])
    assert live.masked_ranges() == [(4, 4), (20, 4)], live.masked_ranges()
    assert live.pointer_ranges() == [(8, 8)], live.pointer_ranges()
    assert live.noncomparable_ranges() == [(8, 8)], \
        live.noncomparable_ranges()
    con2 = Contract(module="oldlib.dll", arch="x64")
    con2.structs["LIVE_BUF"] = live
    con2.symbols["Process"] = SymbolSpec(
        name="Process", ret="i32",
        args=[ArgSpec("buf", "ptr", dir="inout", struct="LIVE_BUF")])
    rule = Policy.derive(con2).masks_for("Process", "in.buf")[0]
    assert rule.byte_ranges == [(8, 8)], rule.byte_ranges
    assert "pointer identity" in rule.why, \
        rule.why
    print(f"derive: pointer field -> {rule.why}")

    # masks_for wildcards on both axes.
    pol2 = pol.merged_with([
        MaskRule(sym="*", path="lasterr", why="OS noise"),
        MaskRule(sym="Process", path="*", byte_ranges=[(0, 1)], why="glob path"),
        MaskRule(sym="Proc*", path="ret", byte_ranges=[(0, 4)], why="glob sym"),
        MaskRule(sym="Close", why="empty path == all paths"),
    ])
    assert len(pol2.masks) == len(pol.masks) + 4
    assert [m.why for m in pol2.masks_for("Nothing", "lasterr")] == ["OS noise"]
    whys = [m.why for m in pol2.masks_for("Process", "ret")]
    assert whys == ["glob path", "glob sym"], whys
    assert [m.why for m in pol2.masks_for("Close", "in.h")] == \
        ["empty path == all paths"], pol2.masks_for("Close", "in.h")
    assert pol2.masks_for("ProcessMany", "in.items")[0].byte_ranges == \
        [(8, 8)]
    print("masks_for: wildcard resolution ok")

    # merged_with dedupes so repeated --write-policy runs stay stable.
    assert pol2.merged_with(list(pol2.masks)).masks == pol2.masks
    print("merged_with: dedupe ok")

    # Round trip, including non-default scalar settings.
    pol3 = replace(pol2, float_eps=1e-6, thread_mode="global",
                   symbolize_pointers=False, ignore_symbols=["GetTickCount"],
                   max_children_compare=8)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "policy.json"
        pol3.save(p)
        back = Policy.load(p)
        assert back == pol3, (back, pol3)
        assert back.masks[0].byte_ranges == [(8, 8)]
        assert isinstance(back.masks[0].byte_ranges[0], tuple)
        back.save(p)
        assert Policy.load(p) == pol3
    print("save/load: exact round trip ok")
    print("policy.py self-test PASS")
