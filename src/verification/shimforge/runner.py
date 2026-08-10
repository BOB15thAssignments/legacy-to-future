"""Run DLL test scenarios and collect process and filesystem observations."""

from __future__ import annotations

import ctypes
import hashlib
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from itertools import zip_longest
from pathlib import Path
from typing import Any, Mapping, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "RunResult", "run_scenario", "compare_runs", "apply_normalizers",
    "COMMON_NORMALIZERS", "REMOVED", "snapshot_dir",
]

# Sentinel hash for "this file existed before the run and is gone after it".
# `output_files` is a delta, so a deletion needs a representable value.
REMOVED = "<removed>"

_HASH_CHUNK = 1 << 20
_PIPE_CHUNK = 1 << 16
DEFAULT_MAX_OUTPUT_BYTES = 16 << 20
SAMPLE_INTERVAL_S = 0.05
# Fast samples at the start of a run, where handle counts move most.
_SAMPLE_RAMP = 20

# (pattern, replacement); pattern may be a str or a compiled re.Pattern.
NormalizerRule = tuple[Any, str]

# Opt-in substitutions for the usual sources of run-to-run text noise. Order
# matters: the broad rules would otherwise eat parts of the specific ones.
COMMON_NORMALIZERS: tuple[NormalizerRule, ...] = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
                r"(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"),
     "<GUID>"),
    (re.compile(r"(?i)\b[a-z]:\\users\\[^\\\s\"']+\\appdata\\local\\temp\\"
                r"[^\s\"']*"), "<TEMP>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"(?i)\bpid\s*[=:#]?\s*\d+"), "pid=<PID>"),
    (re.compile(r"\b0x[0-9a-fA-F]{4,16}\b"), "<ADDR>"),
    # Bare hex pointer: require at least one a-f digit so that plain decimal
    # counters (sizes, indices) survive untouched.
    (re.compile(r"\b(?=[0-9a-fA-F]{8,16}\b)(?=[0-9a-fA-F]*[a-fA-F])"
                r"[0-9a-fA-F]{8,16}\b"), "<ADDR>"),
    (re.compile(r"\b1\d{9}(?:\d{3})?\b"), "<EPOCH>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s*(?:ns|us|ms|sec|secs|seconds?)\b"), "<DUR>"),
)


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    output_files: dict[str, str] = field(default_factory=dict)
    peak_handles: int | None = None
    peak_bytes: int | None = None
    resource_samples: int | None = None
    timed_out: bool = False
    output_limit_exceeded: bool = False
    capture_errors: list[str] = field(default_factory=list)
    filesystem_errors: list[str] = field(default_factory=list)
    # Used to bind an on-disk trace header to the process the runner actually
    # launched. PID is provenance, not an observable compared across runs.
    pid: int | None = None
    # Keep the exact process bytes.  Legacy Windows programs commonly emit an
    # OEM/ANSI codepage, and decoding two different invalid byte strings with
    # errors="replace" can collapse both to the same U+FFFD text and create a
    # false PASS.  `stdout`/`stderr` remain the display/normalizer view only.
    stdout_raw: bytes | None = None
    stderr_raw: bytes | None = None

    def summary(self) -> str:
        return (f"exit={self.exit_code} {self.duration_s:.3f}s "
            f"files={len(self.output_files)} "
            f"handles={self.peak_handles} bytes={self.peak_bytes} "
            f"samples={self.resource_samples}"
            + (" TIMEOUT" if self.timed_out else "")
            + (" OUTPUT-LIMIT" if self.output_limit_exceeded else "")
            + (" CAPTURE-ERROR" if self.capture_errors else ""))


def run_scenario(cmd: Sequence[str], cwd: str | Path, *,
                 timeout: float = 120,
                 watch_dirs: Sequence[str | Path] | None = None,
                 env: Mapping[str, str] | None = None,
                 normalizers: Sequence[NormalizerRule] | None = None,
                 sample: bool = True,
                 sample_interval_s: float = SAMPLE_INTERVAL_S,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> RunResult:
    """Run `cmd` in `cwd` and report everything observable about the run.

    `watch_dirs` are hashed before and after; `output_files` holds only the
    delta (added or changed files, plus deletions as `REMOVED`) so that
    pre-existing inputs do not drown the signal.

    `env=None` inherits the parent environment. Passing a mapping REPLACES it
    wholesale, which on Windows means the caller is responsible for SystemRoot
    and friends -- build from `os.environ.copy()`.

    `sample`/`sample_interval_s` are extensions over the spec signature; both
    are keyword-only with safe defaults.
    """
    cwd = Path(cwd)
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be > 0")
    argv = [str(c) for c in cmd]
    roots = _resolve_watch_dirs(watch_dirs, cwd)
    before_errors: list[str] = []
    before = _snapshot(roots, before_errors)
    if before_errors:
        raise OSError("unsafe/unreadable pre-run watch state: "
                      + "; ".join(before_errors))

    run_env = dict(env) if env is not None else None
    started = time.perf_counter()
    proc = subprocess.Popen(
        argv, cwd=str(cwd), env=run_env,
        stdin=subprocess.DEVNULL,          # a scenario blocked on stdin would
        stdout=subprocess.PIPE,            # burn the whole timeout for nothing
        stderr=subprocess.PIPE,
        text=False,
        creationflags=0,
    )
    job = _assign_kill_on_close_job(proc)
    if proc.stdout is None or proc.stderr is None:
        if job is not None:
            _close_handle(job)
        else:
            proc.kill()
        raise OSError("subprocess output pipes were not created")
    out_reader = _PipeCapture(proc.stdout, max_output_bytes, "stdout")
    err_reader = _PipeCapture(proc.stderr, max_output_bytes, "stderr")
    out_reader.start()
    err_reader.start()
    sampler = _Sampler(proc.pid, sample_interval_s) if sample else None
    if sampler is not None:
        sampler.start()

    timed_out = False
    output_limit_exceeded = False
    try:
        deadline = started + timeout
        while proc.poll() is None:
            if out_reader.overflow.is_set() or err_reader.overflow.is_set():
                output_limit_exceeded = True
                if job is not None:
                    _close_handle(job)
                    job = None
                else:
                    proc.kill()
                break
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                timed_out = True
                if job is not None:
                    # Closing a KILL_ON_JOB_CLOSE job terminates the whole
                    # descendant tree, including helpers holding our pipes.
                    _close_handle(job)
                    job = None
                else:
                    proc.kill()
                break
            try:
                proc.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("process tree did not terminate: %s", argv[0])
    finally:
        if sampler is not None:
            sampler.stop()
        if job is not None:
            _close_handle(job)
        out_reader.join(10)
        err_reader.join(10)
    duration = time.perf_counter() - started

    out, err = bytes(out_reader.data), bytes(err_reader.data)
    output_limit_exceeded = (output_limit_exceeded
                             or out_reader.overflow.is_set()
                             or err_reader.overflow.is_set())
    capture_errors = [x for x in (out_reader.error, err_reader.error) if x]
    if out_reader.is_alive() or err_reader.is_alive():
        capture_errors.append("output reader did not reach EOF")

    after_errors: list[str] = []
    after = _snapshot(roots, after_errors)
    return RunResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=apply_normalizers((out or b"").decode("utf-8", "replace"),
                                 normalizers),
        stderr=apply_normalizers((err or b"").decode("utf-8", "replace"),
                                 normalizers),
        duration_s=duration,
        output_files=_delta(before, after),
        peak_handles=sampler.peak_handles if sampler is not None else None,
        peak_bytes=sampler.peak_bytes if sampler is not None else None,
        resource_samples=sampler.sample_count if sampler is not None else None,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        capture_errors=capture_errors,
        filesystem_errors=after_errors,
        pid=proc.pid,
        stdout_raw=out or b"",
        stderr_raw=err or b"",
    )


def compare_runs(a: RunResult, b: RunResult, *,
                 ignore_stderr: bool = False) -> list[str]:
    """Return problem strings; empty list == the two runs are indistinguishable.

    Wall time, handle and memory counts are deliberately NOT compared here --
    they are never bit-stable and the noninterference check compares them
    against explicit thresholds instead.
    """
    problems: list[str] = []
    if a.timed_out or b.timed_out:
        problems.append(f"timed out: A={a.timed_out} B={b.timed_out}")
    if a.output_limit_exceeded or b.output_limit_exceeded:
        problems.append("output capture limit exceeded: "
                        f"A={a.output_limit_exceeded} "
                        f"B={b.output_limit_exceeded}")
    if a.capture_errors or b.capture_errors:
        problems.append(f"output capture failed: A={a.capture_errors!r} "
                        f"B={b.capture_errors!r}")
    if a.filesystem_errors or b.filesystem_errors:
        problems.append(f"watched filesystem could not be proven: "
                        f"A={a.filesystem_errors!r} "
                        f"B={b.filesystem_errors!r}")
    if a.exit_code != b.exit_code:
        problems.append(f"exit code differs: A={a.exit_code} B={b.exit_code}")
    if (a.stdout_raw is not None or b.stdout_raw is not None) and \
            a.stdout_raw != b.stdout_raw:
        problems.append(
            "stdout raw bytes differ: "
            f"A={_byte_summary(a.stdout_raw)} B={_byte_summary(b.stdout_raw)}")
    problems.extend(_text_diff("stdout", a.stdout, b.stdout))
    if not ignore_stderr:
        if (a.stderr_raw is not None or b.stderr_raw is not None) and \
                a.stderr_raw != b.stderr_raw:
            problems.append(
                "stderr raw bytes differ: "
                f"A={_byte_summary(a.stderr_raw)} B={_byte_summary(b.stderr_raw)}")
        problems.extend(_text_diff("stderr", a.stderr, b.stderr))
    problems.extend(_file_diff(a.output_files, b.output_files))
    return problems


def apply_normalizers(text: str,
                      normalizers: Sequence[NormalizerRule] | None) -> str:
    if not normalizers or not text:
        return text
    for pattern, repl in normalizers:
        text = re.sub(pattern, repl, text)
    return text


def snapshot_dir(root: str | Path) -> dict[str, str]:
    """sha256 of every file under `root`, keyed by posix relative path."""
    return _snapshot([("", Path(root))])


# --------------------------------------------------------------------------
# file observation


def _resolve_watch_dirs(watch_dirs: Sequence[str | Path] | None,
                        cwd: Path) -> list[tuple[str, Path]]:
    if not watch_dirs:
        return []
    roots: list[Path] = []
    for d in watch_dirs:
        p = Path(d)
        roots.append(Path(os.path.normpath(str(p if p.is_absolute() else cwd / p))))
    if len(roots) == 1:
        return [("", roots[0])]
    # Multiple roots share one key space, so prefix with the directory name and
    # break ties by occurrence order rather than by full path: keys must stay
    # comparable between two runs that live in different parent directories.
    labels: list[str] = []
    seen: dict[str, int] = {}
    for r in roots:
        base = r.name or "root"
        seen[base] = seen.get(base, 0) + 1
        labels.append(base if seen[base] == 1 else f"{base}#{seen[base]}")
    return list(zip(labels, roots))


def _snapshot(roots: Sequence[tuple[str, Path]],
              errors: list[str] | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for label, root in roots:
        if _is_link_or_junction(root):
            message = f"watch root is a symlink/junction: {root}"
            if errors is None:
                raise OSError(message)
            errors.append(message)
            continue
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            try:
                if _is_link_or_junction(path):
                    message = f"watched path is a symlink/junction: {path}"
                    if errors is None:
                        raise OSError(message)
                    errors.append(message)
                    continue
                if not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                key = f"{label}/{rel}" if label else rel
                out[key] = _sha256(path)
            except OSError as exc:
                if errors is None:
                    raise
                # A file still held open by the child is not a hard failure;
                # record the condition so approval callers fail with the
                # exact path instead of silently omitting it.
                try:
                    rel = path.relative_to(root).as_posix()
                except ValueError:
                    rel = path.name
                key = f"{label}/{rel}" if label else rel
                out[key] = f"<unreadable:{exc.errno}>"
                if errors is not None:
                    errors.append(f"unreadable watched path {path}: {exc}")
    return out


def _is_link_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction()) if callable(is_junction) else False
    except OSError:
        return True


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _delta(before: dict[str, str], after: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in sorted(after):
        if before.get(key) != after[key]:
            out[key] = after[key]
    for key in sorted(before):
        if key not in after:
            out[key] = REMOVED
    return dict(sorted(out.items()))


# --------------------------------------------------------------------------
# comparison helpers


def _clip(text: str | None, limit: int = 160) -> str:
    if text is None:
        return "<absent>"
    text = text.replace("\r", "")
    return text if len(text) <= limit else text[:limit] + "..."


def _text_diff(label: str, a: str, b: str) -> list[str]:
    if a == b:
        return []
    la, lb = a.splitlines(), b.splitlines()
    for i, (x, y) in enumerate(zip_longest(la, lb), 1):
        if x != y:
            return [f"{label} differs at line {i}: "
                    f"A={_clip(x)!r} B={_clip(y)!r}"]
    # Equal line-by-line but unequal as strings: trailing newline only.
    return [f"{label} differs in trailing whitespace "
            f"({len(a)} vs {len(b)} chars)"]


def _file_diff(a: dict[str, str], b: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for key in sorted(set(a) | set(b)):
        ha, hb = a.get(key), b.get(key)
        if ha == hb:
            continue
        if ha is None:
            problems.append(f"output file only in B: {key} ({_short(hb)})")
        elif hb is None:
            problems.append(f"output file only in A: {key} ({_short(ha)})")
        elif ha == REMOVED or hb == REMOVED:
            problems.append(f"output file removal differs: {key} "
                            f"A={_short(ha)} B={_short(hb)}")
        else:
            problems.append(f"output file content differs: {key} "
                            f"A={_short(ha)} B={_short(hb)}")
    return problems


def _short(h: str | None) -> str:
    if h is None:
        return "<absent>"
    return h if len(h) <= 16 else h[:16]


def _byte_summary(data: bytes | None) -> str:
    if data is None:
        return "<not-captured>"
    digest = hashlib.sha256(data).hexdigest()[:16]
    return f"{len(data)}B sha256={digest}"


# --------------------------------------------------------------------------
# handle / memory sampling
#
# The OS counters are best effort and degrade to None. Approval callers treat
# None or too few samples as failed evidence; diagnostic callers can still
# inspect the rest of the RunResult.


class _PipeCapture(threading.Thread):
    """Drain one child pipe with a hard in-memory evidence limit."""

    def __init__(self, pipe: Any, limit: int, label: str) -> None:
        super().__init__(daemon=True, name=f"shimforge-{label}-reader")
        self.pipe = pipe
        self.limit = limit
        self.label = label
        self.data = bytearray()
        self.overflow = threading.Event()
        self.error = ""

    def run(self) -> None:
        try:
            read = getattr(self.pipe, "read1", self.pipe.read)
            while True:
                chunk = read(_PIPE_CHUNK)
                if not chunk:
                    return
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow.set()
                    return
        except Exception as exc:               # pragma: no cover - defensive
            self.error = f"{self.label}: {type(exc).__name__}: {exc}"
        finally:
            try:
                self.pipe.close()
            except Exception:
                pass


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_BASIC_UI_RESTRICTIONS = 4
JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020
JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080
# Approval sampling observes the launched process.  Allowing helpers would
# let a tap move work/resources into an unsampled child and still appear
# cheaper than the baseline.  Legacy targets that require a process tree need
# a future job-wide accounting backend; until then they fail closed.
_JOB_MAX_PROCESSES = 1
_JOB_MAX_MEMORY = 1 << 30


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", ctypes.c_uint32)]


def _assign_kill_on_close_job(proc: subprocess.Popen) -> int | None:
    """Put the child in a fail-closed Windows job that owns descendants.

    Assignment happens immediately after process creation.  A fully atomic
    assignment needs STARTUPINFOEX/PROC_THREAD_ATTRIBUTE_JOB_LIST; until that
    is added, refusing to continue when assignment fails is still materially
    safer than silently running without tree ownership.
    """
    if os.name != "nt":
        return None
    k32 = _kernel32()
    if k32 is None:
        proc.kill()
        raise OSError("kernel32 unavailable; refusing uncontained scenario")
    k32.CreateJobObjectW.restype = ctypes.c_void_p
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    k32.SetInformationJobObject.restype = ctypes.c_int
    k32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    k32.AssignProcessToJobObject.restype = ctypes.c_int
    k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    job = k32.CreateJobObjectW(None, None)
    if not job:
        proc.kill()
        raise OSError(ctypes.get_last_error(),
                      "CreateJobObjectW failed; refusing uncontained scenario")
    handle = int(job)
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY)
    info.BasicLimitInformation.ActiveProcessLimit = _JOB_MAX_PROCESSES
    info.JobMemoryLimit = _JOB_MAX_MEMORY
    if not k32.SetInformationJobObject(
            ctypes.c_void_p(handle), JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info), ctypes.sizeof(info)):
        err = ctypes.get_last_error()
        _close_handle(handle)
        proc.kill()
        raise OSError(err, "SetInformationJobObject failed")
    ui = _JOBOBJECT_BASIC_UI_RESTRICTIONS()
    ui.UIRestrictionsClass = (
        JOB_OBJECT_UILIMIT_HANDLES
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_EXITWINDOWS)
    if not k32.SetInformationJobObject(
            ctypes.c_void_p(handle), JOB_OBJECT_BASIC_UI_RESTRICTIONS,
            ctypes.byref(ui), ctypes.sizeof(ui)):
        err = ctypes.get_last_error()
        _close_handle(handle)
        proc.kill()
        raise OSError(err, "could not apply job UI restrictions")
    process_handle = int(getattr(proc, "_handle", 0) or 0)
    if not process_handle or not k32.AssignProcessToJobObject(
            ctypes.c_void_p(handle), ctypes.c_void_p(process_handle)):
        err = ctypes.get_last_error()
        _close_handle(handle)
        proc.kill()
        raise OSError(err, "AssignProcessToJobObject failed; refusing "
                      "uncontained scenario")
    return handle


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class _Sampler(threading.Thread):
    """Polls a live process for handle count and peak working set."""

    def __init__(self, pid: int, interval: float) -> None:
        # Daemon: a WinAPI call wedged in this thread must not keep the
        # interpreter alive after the scenario is done.
        super().__init__(daemon=True, name=f"shimforge-sampler-{pid}")
        self.pid = pid
        self.interval = max(0.005, float(interval))
        self.peak_handles: int | None = None
        self.peak_bytes: int | None = None
        self.sample_count = 0
        self._stop_evt = threading.Event()

    def stop(self, join_timeout: float = 1.0) -> None:
        self._stop_evt.set()
        if self.is_alive():
            self.join(join_timeout)

    def run(self) -> None:
        handle = _open_process(self.pid)
        if handle is None:
            return
        try:
            # Sample once immediately, then ramp: a scenario that lives 100ms
            # would otherwise be described by a single sample taken before it
            # had opened anything.
            self._sample(handle)
            for _ in range(_SAMPLE_RAMP):
                if self._stop_evt.wait(min(self.interval, 0.005)):
                    return
                self._sample(handle)
            while not self._stop_evt.wait(self.interval):
                self._sample(handle)
        except Exception:                       # pragma: no cover - defensive
            logger.debug("sampler for pid %d stopped early", self.pid,
                         exc_info=True)
        finally:
            # One last read after the process is gone. PeakWorkingSetSize is a
            # kernel maintained high-water mark and stays readable while we
            # hold the handle, so this catches spikes that fell between polls.
            # The handle count does not survive exit and simply fails here.
            self._sample(handle)
            _close_handle(handle)

    def _sample(self, handle: int) -> None:
        count = _handle_count(handle)
        observed = False
        if count is not None:
            self.peak_handles = max(self.peak_handles or 0, count)
            observed = True
        peak = _peak_working_set(handle)
        if peak is not None:
            self.peak_bytes = max(self.peak_bytes or 0, peak)
            observed = True
        if observed:
            self.sample_count += 1


def _kernel32() -> Any | None:
    if os.name != "nt":
        return None
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:                             # pragma: no cover - defensive
        return None


def _open_process(pid: int) -> int | None:
    k32 = _kernel32()
    if k32 is None:
        return None
    # Holding a handle for the whole run also pins the pid, which removes the
    # (small) chance of sampling a recycled process id.
    for access in (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                   PROCESS_QUERY_LIMITED_INFORMATION):
        try:
            k32.OpenProcess.restype = ctypes.c_void_p
            k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int,
                                        ctypes.c_uint32]
            handle = k32.OpenProcess(access, False, pid)
        except Exception:                       # pragma: no cover - defensive
            return None
        if handle:
            return int(handle)
    logger.debug("OpenProcess(%d) failed: %d", pid, ctypes.get_last_error())
    return None


def _close_handle(handle: int) -> None:
    k32 = _kernel32()
    if k32 is None:
        return
    try:
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle(ctypes.c_void_p(handle))
    except Exception:                           # pragma: no cover - defensive
        pass


def _handle_count(handle: int) -> int | None:
    k32 = _kernel32()
    if k32 is None:
        return None
    try:
        k32.GetProcessHandleCount.argtypes = [ctypes.c_void_p,
                                              ctypes.POINTER(ctypes.c_uint32)]
        count = ctypes.c_uint32(0)
        if not k32.GetProcessHandleCount(ctypes.c_void_p(handle),
                                         ctypes.byref(count)):
            return None
        return int(count.value)
    except Exception:                           # pragma: no cover - defensive
        return None


def _peak_working_set(handle: int) -> int | None:
    k32 = _kernel32()
    if k32 is None:
        return None
    counters = _PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    # K32GetProcessMemoryInfo lives in kernel32 since Win7; psapi.dll is the
    # older home of the same export.
    for lib, name in ((k32, "K32GetProcessMemoryInfo"),
                      (None, "GetProcessMemoryInfo")):
        try:
            if lib is None:
                lib = ctypes.WinDLL("psapi", use_last_error=True)
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_void_p,
                           ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
                           ctypes.c_uint32]
            if fn(ctypes.c_void_p(handle), ctypes.byref(counters),
                  ctypes.sizeof(counters)):
                return int(counters.PeakWorkingSetSize)
        except Exception:
            continue
    return None
