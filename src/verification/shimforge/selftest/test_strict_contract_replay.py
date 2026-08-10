"""Fail-closed regressions for contract decoding and replay admission."""

from __future__ import annotations

from pathlib import Path

import pytest

from shimforge.gen_replay import ReplayError, plan_replay
from shimforge.model import (
    ArgSpec,
    Contract,
    ContractError,
    Extent,
    SymbolSpec,
)
from shimforge.trace import REC_CALL, REC_NOTE, Rec, Trace, Val, make_header


SELFTEST_DIR = Path(__file__).resolve().parent


def _load_text(tmp_path: Path, text: str) -> Contract:
    path = tmp_path / "contract.json"
    path.write_text(text, encoding="utf-8")
    return Contract.load(path)


def test_selftest_contract_still_passes_strict_schema() -> None:
    contract = Contract.load(SELFTEST_DIR / "contract.json")
    assert contract.module == "oldlib.dll"
    assert contract.validate() == []


@pytest.mark.parametrize("raw", [
    '{"module":"a.dll","module":"b.dll"}',
    '{"module":"a.dll","unsupported":1}',
    '{"module":1}',
    '{"module":null}',
    '{"module":"a.dll","symbols":[]}',
    '{"module":"a.dll","real_module":null}',
    '{"module":"a.dll","symbols":{"F":{"noname":1}}}',
    '{"module":"a.dll","symbols":{"F":{"ordinal":true}}}',
    '{"module":"a.dll","symbols":{"F":{"args":{}}}}',
    '{"module":"a.dll","symbols":{"F":{"args":['
    '{"name":"p","kind":"ptr","extent":{"fixed":4,"typo":1}}]}}}',
    '{"module":"a.dll","structs":{"S":{"size":4,"fields":['
    '{"name":"x","off":true,"size":4,"kind":"u32"}]}}}',
    '{"module":NaN}',
    '{"module":Infinity}',
    '{"module":-Infinity}',
])
def test_contract_json_rejects_ambiguous_or_coerced_input(
        tmp_path: Path, raw: str) -> None:
    with pytest.raises(ContractError):
        _load_text(tmp_path, raw)


def test_extent_rejects_redundant_or_meaningless_fields() -> None:
    with pytest.raises(ContractError, match="exactly one"):
        Extent.from_json({"fixed": 4, "unknown": False})
    with pytest.raises(ContractError, match="only valid"):
        Extent.from_json({"fixed": 4, "scale": 2})


def test_float_contracts_are_not_approval_safe_without_bit_exact_wire() -> None:
    contract = Contract(module="old.dll", symbols={
        "F": SymbolSpec(name="F", ret="f64", args=[ArgSpec("x", "f32")]),
    })
    problems = contract.validate()
    assert any("floating-point returns" in p for p in problems)
    assert any("floating-point arguments" in p for p in problems)


def _contract_and_trace(*, pointer: bool = False) -> tuple[Contract, Trace]:
    args = ([ArgSpec("p", "ptr", extent=Extent(fixed=4))]
            if pointer else [])
    contract = Contract(module="old.dll", symbols={
        "F": SymbolSpec(name="F", ret="i32", args=args),
    })
    inn = ({"p": Val("ptr", p="1", n=4, b="00000000")}
           if pointer else {})
    header = make_header(
        contract.module, contract.arch, pid=1, run="selftest",
        contract=contract.fingerprint(), subject="1" * 64)
    trace = Trace(
        header=header,
        records=[Rec(REC_CALL, 0, sym="F", tid=1, depth=0,
                     inn=inn, ret=Val("i32", v=0))],
    )
    return contract, trace


def test_replay_accepts_only_complete_conformant_evidence() -> None:
    contract, trace = _contract_and_trace()
    plan = plan_replay(contract, trace)
    assert len(plan.calls) == 1
    assert plan.skipped == []


def test_replay_rejects_missing_footer_state() -> None:
    contract, trace = _contract_and_trace()
    trace.complete = False
    trace.footer = {}
    with pytest.raises(ReplayError, match="invalid or incomplete"):
        plan_replay(contract, trace)


def test_replay_rejects_runtime_note_even_on_complete_trace() -> None:
    contract, trace = _contract_and_trace()
    trace.notes.append(Rec(REC_NOTE, 1, sym="F", msg="capture fault"))
    with pytest.raises(ReplayError, match="runtime note"):
        plan_replay(contract, trace)


def test_replay_rejects_partial_capture() -> None:
    contract, trace = _contract_and_trace(pointer=True)
    trace.records[0].inn["p"].b = None
    with pytest.raises(ReplayError, match="partial capture"):
        plan_replay(contract, trace)


def test_runtime_has_no_incomplete_success_override() -> None:
    source = (SELFTEST_DIR.parent / "runtime" / "replay_main.c").read_text(
        encoding="utf-8")
    assert "SHIMFORGE_REPLAY_ALLOW_INCOMPLETE" not in source
    assert "NOT an equivalence PASS" in source
