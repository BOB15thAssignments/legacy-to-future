"""Approval-only gates that deliberately prefer false negatives."""

from __future__ import annotations

from pathlib import Path

from shimforge import oracle_check, runner
from shimforge.model import ArgSpec, Contract, Extent, SymbolSpec
from shimforge.trace import REC_CALL, Rec, Trace, Val, make_header


def _complete_trace(contract: Contract, records: list[Rec]) -> Trace:
    header = make_header(
        contract.module, contract.arch, "approval-test",
        pid=123, run="approval-run", contract=contract.fingerprint(),
        subject="1" * 64)
    return Trace(
        header=header, records=records, complete=True,
        footer={"t": "end", "records": len(records), "bytes": 0,
                "sha256": "0" * 64})


def test_unhashed_host_executable_cannot_be_scenario_subject(
        tmp_path: Path) -> None:
    contract = tmp_path / "contract.json"
    original = tmp_path / "old.dll"
    tap = tmp_path / "tap.dll"
    app = tmp_path / "app.exe"
    for path in (contract, original, tap, app):
        path.write_bytes(b"test")

    cfg = oracle_check.OracleConfig(
        contract=contract, original_dll=original, tap_dll=tap,
        scenario=[r"C:\host\unbound.exe"], work_dir=tmp_path / "work",
        app_files=[app])
    problems = cfg.problems()
    assert any("scenario[0] must resolve to one staged executable" in p
               for p in problems)
    assert any("scenario executable" in p and "absent from app_files" in p
               for p in problems) is False


def test_each_input_must_vary_not_only_an_unrelated_flag() -> None:
    contract = Contract(module="old.dll", symbols={
        "F": SymbolSpec(
            name="F", ret="i32",
            args=[
                ArgSpec("buf", "ptr", extent=Extent(fixed=2)),
                ArgSpec("flag", "u32"),
            ],
        )
    })
    assert contract.validate() == []
    records = [
        Rec(
            t=REC_CALL, seq=i + 1, sym="F", tid=1,
            inn={
                "buf": Val("ptr", p="1000", n=2, b="aabb"),
                "flag": Val("u32", v=i),
            },
            ret=Val("i32", v=0),
        )
        for i in range(3)
    ]
    problems = oracle_check.trace_approval_coverage_problems(
        _complete_trace(contract, records), contract)
    assert any("F.buf: 1 distinct input value class" in p for p in problems)


def test_standalone_l2_trace_must_cover_every_contract_symbol() -> None:
    contract = Contract(module="old.dll", symbols={
        "Seen": SymbolSpec(name="Seen", ret="i32"),
        "Missing": SymbolSpec(name="Missing", ret="i32"),
    })
    assert contract.validate() == []
    records = [
        Rec(t=REC_CALL, seq=i + 1, sym="Seen", tid=1,
            ret=Val("i32", v=0))
        for i in range(3)
    ]
    problems = oracle_check.trace_approval_coverage_problems(
        _complete_trace(contract, records), contract)
    assert any("Missing: 0 call(s)" in p for p in problems)


def test_approval_job_forbids_helper_process_resource_evasion() -> None:
    assert runner._JOB_MAX_PROCESSES == 1
