"""Regression tests for evidence states that must never produce PASS."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from shimforge.model import (
    ArgSpec,
    Contract,
    ContractError,
    Extent,
    FieldSpec,
    StructSpec,
    SymbolSpec,
)
from shimforge.gen_tap import generate_tap
from shimforge import oracle_check, pe_surface
from shimforge.pe_surface import ExportEntry, Surface, compare_contract_surface
from shimforge.policy import MaskRule, Policy
from shimforge.runner import RunResult, compare_runs, run_scenario


SELFTEST_DIR = Path(__file__).resolve().parent


def _result(raw: bytes) -> RunResult:
    return RunResult(
        exit_code=0,
        stdout=raw.decode("utf-8", "replace"),
        stderr="",
        duration_s=0.1,
        stdout_raw=raw,
        stderr_raw=b"",
    )


def test_raw_legacy_output_cannot_collapse_to_same_replacement_text() -> None:
    a = _result(b"\x80")
    b = _result(b"\x81")
    assert a.stdout == b.stdout == "\ufffd"
    assert any("stdout raw bytes differ" in p for p in compare_runs(a, b))


def test_arbitrary_range_mask_is_rejected_even_when_marked_auto() -> None:
    contract = Contract.load(SELFTEST_DIR / "contract.json")
    policy = Policy.derive(contract).merged_with([
        MaskRule(sym="*", path="*", byte_ranges=[(0, 1 << 30)], auto=True)
    ])
    with pytest.raises(ValueError, match="not an exact mask"):
        policy.assert_safe(contract=contract)


def test_unknown_pointer_extent_is_not_a_reduced_credit_contract() -> None:
    contract = Contract(module="old.dll", symbols={
        "F": SymbolSpec(
            name="F", ret="i32",
            args=[ArgSpec("p", "ptr", extent=Extent(unknown=True))],
        )
    })
    assert any("extent is unknown" in p for p in contract.validate())


def test_volatile_field_is_not_silently_erased() -> None:
    contract = Contract(module="old.dll")
    contract.structs["S"] = StructSpec(
        name="S", size=4,
        fields=[FieldSpec("value", 0, 4, "u32", volatile=True)],
    )
    assert any("volatile fields erase" in p for p in contract.validate())


def _surface(*entries: ExportEntry) -> Surface:
    exports = {e.key: e for e in entries}
    return Surface(
        module="old.dll", arch="x64", exports=exports,
        by_ordinal={e.ordinal: e for e in entries}, machine="AMD64")


def _contract(*symbols: SymbolSpec) -> Contract:
    return Contract(
        module="old.dll", arch="x64", real_module="old_real.dll",
        symbols={s.name: s for s in symbols})


def test_uncontracted_noname_export_cannot_be_forwarded_untraced(
        tmp_path: Path) -> None:
    original = _surface(
        ExportEntry("Call", 1, 0x1000, None, False),
        ExportEntry(None, 2, 0x1010, None, False),
    )
    contract = _contract(SymbolSpec("Call", ordinal=1))

    problems = compare_contract_surface(contract, original)
    assert any("NONAME ordinal #2 is missing from the contract" in p
               for p in problems)
    with pytest.raises(ContractError, match="missing from the contract"):
        generate_tap(contract, tmp_path / "tap", surface=original)
    assert not (tmp_path / "tap").exists()


def test_l0_structural_gate_checks_original_against_contract() -> None:
    original = _surface(
        ExportEntry("Call", 1, 0x1000, None, False),
        ExportEntry(None, 2, 0x1010, None, False),
    )
    contract = _contract(SymbolSpec("Call", ordinal=1))

    class SurfaceReader:
        compare_contract_surface = staticmethod(compare_contract_surface)

        @staticmethod
        def read_exports(_path: Path) -> Surface:
            return original

        @staticmethod
        def compare_surface(_tap: Surface, _original: Surface,
                            _names: set[str], _ords: set[int]) -> list[str]:
            # Even a clean binary-to-binary surface comparison cannot excuse
            # an export omitted from the recording contract.
            return []

    problems, evidence = oracle_check._compare_surface(
        SurfaceReader, Path("tap.dll"), Path("old.dll"), set(), set(),
        contract)
    assert any("NONAME ordinal #2 is missing from the contract" in p
               for p in problems)
    assert evidence["contract_surface_problems"]


def test_data_and_forwarder_exports_cannot_earn_callable_trace_credit() -> None:
    original = _surface(
        ExportEntry("State", 1, 0x2000, None, True),
        ExportEntry("Delegated", 2, 0x2010, ("kernel32", "Sleep"), False),
    )
    contract = _contract(
        SymbolSpec("State", ordinal=1),
        SymbolSpec("Delegated", ordinal=2),
    )
    problems = compare_contract_surface(contract, original)
    assert any("data export 'State'" in p and "unverifiable" in p
               for p in problems)
    assert any("original forwarder 'Delegated'" in p and
               "recorded call boundary" in p for p in problems)


def test_exact_named_and_noname_contract_can_generate(tmp_path: Path) -> None:
    original = _surface(
        ExportEntry("Call", 1, 0x1000, None, False),
        ExportEntry(None, 2, 0x1010, None, False),
    )
    contract = _contract(
        SymbolSpec("Call", ordinal=1),
        SymbolSpec("Version", ordinal=2, noname=True, ret="u32"),
    )
    assert compare_contract_surface(contract, original) == []
    outputs = generate_tap(contract, tmp_path / "tap", surface=original)
    definition = Path(outputs["tap.def"]).read_text(encoding="utf-8")
    assert "Call @1" in definition
    assert "Version @2 NONAME" in definition


def test_tap_generation_without_original_surface_is_refused(
        tmp_path: Path) -> None:
    contract = _contract(SymbolSpec("Call", ordinal=1))
    with pytest.raises(ContractError, match="original PE surface"):
        generate_tap(contract, tmp_path / "tap")


def test_export_attribute_exception_is_not_collapsed_to_nonforward(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Header:
        machine = "AMD64"

    class BadEntry:
        name = "Call"
        ordinal = 1
        function_rva = 0x1000

        @property
        def is_forwarded(self) -> bool:
            raise RuntimeError("parser fault")

    class ExportDirectory:
        name = "old.dll"
        entries = [BadEntry()]

    class Binary:
        header = Header()
        has_exports = True

        @staticmethod
        def get_export() -> ExportDirectory:
            return ExportDirectory()

    image = tmp_path / "old.dll"
    image.write_bytes(b"not used: parser is replaced")
    monkeypatch.setattr(pe_surface, "_parse", lambda _path: Binary())
    with pytest.raises(ValueError, match="unreadable forwarder metadata"):
        pe_surface.read_exports(image)


def test_export_kind_attribute_exception_is_not_collapsed_to_code(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Header:
        machine = "AMD64"

    class Entry:
        name = "Call"
        ordinal = 1
        function_rva = 0x1000
        is_forwarded = False

    class ExportDirectory:
        name = "old.dll"
        entries = [Entry()]

    class BadSection:
        @property
        def characteristics(self) -> int:
            raise RuntimeError("section parser fault")

    class Binary:
        header = Header()
        has_exports = True

        @staticmethod
        def get_export() -> ExportDirectory:
            return ExportDirectory()

        @staticmethod
        def section_from_rva(_rva: int) -> BadSection:
            return BadSection()

    image = tmp_path / "old.dll"
    image.write_bytes(b"not used: parser is replaced")
    monkeypatch.setattr(pe_surface, "_parse", lambda _path: Binary())
    with pytest.raises(ValueError, match="unreadable code/data kind"):
        pe_surface.read_exports(image)


def test_export_directory_exception_is_not_collapsed_to_empty_surface(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Header:
        machine = "AMD64"

    class Binary:
        header = Header()
        has_exports = True

        @staticmethod
        def get_export() -> None:
            raise RuntimeError("export directory parser fault")

    image = tmp_path / "old.dll"
    image.write_bytes(b"not used: parser is replaced")
    monkeypatch.setattr(pe_surface, "_parse", lambda _path: Binary())
    with pytest.raises(ValueError, match="could not read export directory"):
        pe_surface.read_exports(image)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job-object runner")
def test_output_limit_is_failed_evidence() -> None:
    result = run_scenario(
        [sys.executable, "-c", "import sys;sys.stdout.write('x'*10000)"],
        SELFTEST_DIR,
        watch_dirs=[],
        sample=False,
        max_output_bytes=128,
    )
    assert result.output_limit_exceeded
    assert len(result.stdout_raw or b"") == 128
    assert any("output capture limit exceeded" in p
               for p in compare_runs(result, result))
