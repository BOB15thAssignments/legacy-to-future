"""Failure-injection regressions for the native trace recorder.

The invariant under test is deliberately one-sided: every injected evidence
loss must make the requested trace path incomplete.  Rejecting extra runs is
acceptable; allowing even one lossy run to retain an ``end`` footer is not.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from shimforge.trace import read_trace


PKG = Path(__file__).resolve().parents[1]
RUNTIME = PKG / "runtime"
HARNESS = Path(__file__).with_name("recorder_fault_harness.c")
SUBJECT = "2" * 64


@pytest.fixture(scope="session")
def recorder_x86(tmp_path_factory: pytest.TempPathFactory) -> Path:
    clang = shutil.which("clang") or r"C:\Program Files\LLVM\bin\clang.exe"
    if not Path(clang).is_file():
        pytest.skip("clang is required for the native recorder regression")
    out = tmp_path_factory.mktemp("recorder-native") / "fault-harness-x86.exe"
    cmd = [
        clang,
        "-target", "i686-pc-windows-msvc",
        "-Wall", "-Wextra", "-Werror", "-O1",
        "-DTR_TEST_FAULT_INJECT",
        str(HARNESS), str(RUNTIME / "tr_record.c"),
        "-I", str(RUNTIME),
        "-o", str(out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def _run(exe: Path, path: Path, *, fault: str | None = None,
         mode: str | None = None) -> None:
    env = dict(os.environ)
    for name in ("TAP_PASSTHROUGH", "TAP_LABEL", "SHIMFORGE_TR_FAIL",
                 "SHIMFORGE_TR_MODE"):
        env.pop(name, None)
    env.update({
        "TAP_TRACE": str(path),
        "TAP_SUBJECT_SHA256": SUBJECT,
        "TAP_MAXCAP": "1048576",
    })
    if fault is not None:
        env["SHIMFORGE_TR_FAIL"] = fault
    if mode is not None:
        env["SHIMFORGE_TR_MODE"] = mode
    proc = subprocess.run([str(exe)], env=env, capture_output=True,
                          timeout=30, check=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)


def test_recorder_baseline_commits_complete_trace(
        recorder_x86: Path, tmp_path: Path) -> None:
    path = tmp_path / "baseline.jsonl"
    _run(recorder_x86, path)
    assert path.is_file()
    trace = read_trace(path)
    assert trace.valid and trace.complete, trace.validation_errors
    assert len(trace.records) == 1


@pytest.mark.parametrize("fault", [
    "write:1",    # header write
    "write:2",    # call-record write
    "write:3",    # footer write
    "flush:2",    # call-record flush
    "flush:3",    # footer flush
    "flush:4",    # final pre-commit flush
    "commit:1",   # durable storage commit
    "close:1",    # close after a seemingly successful footer
    "tls:1",      # per-thread state cannot be installed
    "move:1",     # atomic promotion of the authoritative path
    "alloc:1",    # trace-path environment copy
    "alloc:2",    # max-capture environment copy
    "alloc:3",    # subject-hash environment copy
    "alloc:4",    # sibling partial path
    "alloc:5",    # header serialization buffer
    "alloc:6",    # per-thread state allocation
    "alloc:7",    # first call's serialization buffer
    "alloc:8",    # integrity-footer serialization buffer
])
def test_any_recorder_fault_suppresses_authoritative_footer(
        recorder_x86: Path, tmp_path: Path, fault: str) -> None:
    path = tmp_path / (fault.replace(":", "-") + ".jsonl")
    _run(recorder_x86, path, fault=fault)
    if path.exists():
        trace = read_trace(path)
        assert not trace.valid
        assert not trace.complete
        assert b'"t":"end"' not in path.read_bytes()


def test_lossy_serialization_is_sticky(
        recorder_x86: Path, tmp_path: Path) -> None:
    path = tmp_path / "unknown-extent.jsonl"
    _run(recorder_x86, path, mode="unknown")
    assert path.is_file()
    trace = read_trace(path)
    assert not trace.valid
    assert not trace.complete
    assert b'"t":"end"' not in path.read_bytes()


def test_diagnostic_note_cannot_race_into_a_success_footer(
        recorder_x86: Path, tmp_path: Path) -> None:
    path = tmp_path / "note.jsonl"
    _run(recorder_x86, path, mode="note")
    assert path.is_file()
    trace = read_trace(path)
    assert not trace.valid
    assert not trace.complete
    assert b'"t":"end"' not in path.read_bytes()


def test_first_allocation_failure_invalidates_stale_authoritative_trace(
        recorder_x86: Path, tmp_path: Path) -> None:
    path = tmp_path / "stale.jsonl"
    path.write_bytes(b'{"t":"end","forged":true}\n')
    _run(recorder_x86, path, fault="alloc:1")
    assert path.is_file()
    assert path.read_bytes() == b""
