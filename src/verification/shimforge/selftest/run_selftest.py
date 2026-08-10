"""shimforge acceptance test.

Proves the chain end to end on a synthetic v1/v2 pair whose defects are known
in advance, because a differ that never fires looks exactly like a differ that
works.

Two tiers of stage:

  native/*   pure C. Builds every artifact and runs the app against the real
             v1 library, the correct shim and each buggy shim. Asserts the
             correct shim is observationally identical and that each planted
             defect actually changes something at the boundary. These stages
             depend on nothing but clang, so they always run.

  trace/*    the toolkit itself: tap generation, recording, normalization,
             first-divergence diffing. Each stage SKIPs with a printed reason
             when a prerequisite is unavailable -- never silently, and never
             by substituting a stand-in.

A stage that cannot run is not a stage that passed. SKIP is therefore a failing
exit by default. `--allow-skip` exists only for incremental development.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

SELFTEST_DIR = Path(__file__).resolve().parent
PKG_DIR = SELFTEST_DIR.parent
TOOLS_DIR = PKG_DIR.parent
BUILD_DIR = SELFTEST_DIR / "build"
RUN_DIR = BUILD_DIR / "run"
TAP_DIR = BUILD_DIR / "tap"
CONTRACT_PATH = SELFTEST_DIR / "contract.json"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from shimforge.model import Contract, ContractError  # noqa: E402
from shimforge.trace import Trace, read_trace  # noqa: E402

logger = logging.getLogger(__name__)

# label -> the DLL that plays oldlib.dll in that run directory
IMPLS = {
    "old": "oldlib.dll",
    "ok": "shim_ok.dll",
    "bug_offset": "shim_bug_offset.dll",
    "bug_callback": "shim_bug_callback.dll",
    "bug_handle": "shim_bug_handle.dll",
    "bug_ptr": "shim_bug_ptr.dll",
}
BUILD_ARTIFACTS = [
    "oldlib.dll", "oldlib.lib", "newlib.dll", "newlib.lib", "app.exe",
    "shim_ok.dll", "shim_bug_offset.dll", "shim_bug_callback.dll",
    "shim_bug_handle.dll", "shim_bug_ptr.dll",
]

TRACE_ENV = "TAP_TRACE"
TAP_ENV_VARS = ("TAP_TRACE", "TAP_PASSTHROUGH", "TAP_LABEL", "TAP_MAXCAP",
                "TAP_SUBJECT_SHA256", "SHIMFORGE_TRACE", "TR_TRACE")
_SELFTEST_MUTEX: int | None = None
_ERROR_ALREADY_EXISTS = 183


@dataclass(frozen=True)
class Planted:
    """A defect deliberately compiled into one shim, and its trace signature.

    The expectations are exact rather than permissive. A differ that fires on
    the wrong record is as broken as one that does not fire, and an assertion
    loose enough to accept both cannot tell them apart. If tracediff changes
    how it addresses a divergence, this table is supposed to fail.
    """

    shim: str
    kinds: frozenset[str]
    syms: frozenset[str]
    path: str | None = None          # exact path
    path_prefix: str | None = None   # or a prefix, for indexed paths
    why: str = ""
    # Whether the app's own stdout / output file can see the defect. False is
    # the interesting case and the reason the toolkit exists: the boundary
    # looks perfect and only the trace differential disagrees. It is asserted
    # either way -- a defect that quietly became visible would make the trace
    # assertion prove less than it claims.
    native_visible: bool = True


PLANTED = (
    Planted(
        shim="bug_offset",
        kinds=frozenset({"value-mismatch"}),
        syms=frozenset({"Read"}), path="out.out",
        why="v2 format tag left in place: every readback byte shifted right by 4",
    ),
    # The dropped tick changes no return value and no output byte, so the only
    # possible signature is the callback sequence itself. tracediff addresses
    # callbacks as slots under the call that invoked them, hence Process/cb[N].
    Planted(
        shim="bug_callback",
        kinds=frozenset({"callback-mismatch", "missing-call"}),
        syms=frozenset({"Process"}), path_prefix="cb",
        why="0 percent progress callback swallowed by the thunk",
    ),
    Planted(
        shim="bug_handle",
        kinds=frozenset({"value-mismatch"}),
        syms=frozenset({"Close"}), path="ret",
        why="Close always reads slot 0's v2 handle, which the first Close "
            "already cleared, so the second Close passes NULL to newlib",
    ),
    # The out struct comes back naming a different object than the one the
    # caller passed in. Content is copied, so nothing the app reads changes;
    # the pointer bytes are masked, so byte comparison sees nothing either.
    # The ONLY signal is the symbolized embedded pointer field, which is the
    # whole reason struct pointer fields are tokenized instead of masked.
    Planted(
        shim="bug_ptr",
        kinds=frozenset({"value-mismatch"}),
        syms=frozenset({"Process"}), path="out.buf.data",
        why="out struct points at the shim's own alias buffer instead of the "
            "caller's buffer; same bytes, different object",
        native_visible=False,
    ),
)

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


class SkipStage(Exception):
    """Raised by a stage that cannot run yet. Carries the reason verbatim."""


@dataclass
class StageResult:
    name: str
    status: str
    detail: str = ""


@dataclass
class Ctx:
    """Everything stages hand to each other."""

    args: argparse.Namespace
    contract: Contract | None = None
    native: dict[str, dict[str, Any]] = field(default_factory=dict)
    traces: dict[str, Trace] = field(default_factory=dict)
    norm: dict[str, Any] = field(default_factory=dict)
    policy: Any = None
    tap_dll: Path | None = None


_IMPORT_ERRORS: dict[str, str] = {}


def _optional(name: str) -> Any:
    """Import shimforge.<name>, remembering why it failed instead of raising."""
    try:
        return importlib.import_module(f"shimforge.{name}")
    except Exception as exc:                       # noqa: BLE001 - reported, not swallowed
        _IMPORT_ERRORS[name] = f"{type(exc).__name__}: {exc}"
        return None


def _need(*names: str) -> list[Any]:
    mods = []
    missing = []
    for n in names:
        m = _optional(n)
        if m is None:
            missing.append(f"{n} ({_IMPORT_ERRORS.get(n, 'missing')})")
        mods.append(m)
    if missing:
        raise SkipStage("not available: " + "; ".join(missing))
    return mods


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _acquire_selftest_mutex() -> bool:
    """Refuse concurrent runs that would interleave the fixed trace files."""
    global _SELFTEST_MUTEX
    if os.name != "nt":
        return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                      ctypes.c_wchar_p]
    name = "Local\\shimforge-selftest-" + hashlib.sha256(
        str(SELFTEST_DIR).casefold().encode("utf-8")).hexdigest()[:24]
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        return False
    if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return False
    _SELFTEST_MUTEX = int(handle)
    return True


def _run_app(workdir: Path, outname: str = "out.bin",
             env: dict[str, str] | None = None,
             timeout: int = 60) -> dict[str, Any]:
    exe = workdir / "app.exe"
    outfile = workdir / outname
    # Never let output from an earlier run make a crashed/no-output run look
    # successful.  This is a fixed self-test filename inside a fixed run dir.
    if outfile.exists():
        if not outfile.is_file():
            raise AssertionError(f"expected output path is not a file: {outfile}")
        outfile.unlink()
    proc = subprocess.run(
        [str(exe), outname], cwd=str(workdir), capture_output=True,
        timeout=timeout, env=env, check=False)
    return {
        "exit": proc.returncode,
        "stdout_raw": proc.stdout,
        "stderr_raw": proc.stderr,
        "stdout": proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n"),
        "stderr": proc.stderr.decode("utf-8", "replace").replace("\r\n", "\n"),
        "outfile": _sha256(outfile) if outfile.is_file() else None,
    }


def _first_difference(a: str, b: str) -> str:
    """The first differing line pair, which is what a reader actually needs."""
    la, lb = a.splitlines(), b.splitlines()
    for i in range(max(len(la), len(lb))):
        x = la[i] if i < len(la) else "<eof>"
        y = lb[i] if i < len(lb) else "<eof>"
        if x != y:
            return f"line {i + 1}: {x!r} != {y!r}"
    return "identical"


# --------------------------------------------------------------------------
# native stages
# --------------------------------------------------------------------------

def stage_build(ctx: Ctx) -> str:
    if ctx.args.no_build:
        missing = [n for n in BUILD_ARTIFACTS if not (BUILD_DIR / n).is_file()]
        if missing:
            raise AssertionError(f"--no-build but missing: {missing}")
        return f"reused {len(BUILD_ARTIFACTS)} artifacts in {BUILD_DIR.name}/"

    script = SELFTEST_DIR / "build.ps1"
    # Same compiler resolution as the tap build. build.ps1's own default is a
    # hard coded LLVM path, so without this the native stages fail on a machine
    # where clang is on PATH but installed somewhere else -- while the tap
    # stage, which resolves through PATH, would have built fine.
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(script), "-Clang", _clang(), "-Clean"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=600, check=False)
    if proc.returncode != 0:
        raise AssertionError(
            f"build.ps1 exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    missing = [n for n in BUILD_ARTIFACTS if not (BUILD_DIR / n).is_file()]
    if missing:
        raise AssertionError(f"build.ps1 succeeded but did not produce {missing}")
    for label in IMPLS:
        d = RUN_DIR / label
        for f in ("app.exe", "oldlib.dll"):
            if not (d / f).is_file():
                raise AssertionError(f"run dir {label} missing {f}")
    return f"built {len(BUILD_ARTIFACTS)} artifacts + {len(IMPLS)} run dirs"


def stage_native_determinism(ctx: Ctx) -> str:
    """The app itself must be deterministic, or nothing downstream can be."""
    # Same output filename both times: the app prints the name it was given,
    # so varying it would manufacture the difference being tested for.
    a = _run_app(RUN_DIR / "old", "out.bin")
    b = _run_app(RUN_DIR / "old", "out.bin")
    if a["exit"] != 0:
        raise AssertionError(f"app.exe exit {a['exit']}\n{a['stdout']}{a['stderr']}")
    if b["exit"] != 0:
        raise AssertionError(f"second app.exe exit {b['exit']}\n"
                             f"{b['stdout']}{b['stderr']}")
    if a["stdout_raw"] != b["stdout_raw"]:
        raise AssertionError("app stdout is nondeterministic: "
                             + _first_difference(a["stdout"], b["stdout"]))
    if a["stderr_raw"] != b["stderr_raw"]:
        raise AssertionError("app stderr is nondeterministic: "
                             + _first_difference(a["stderr"], b["stderr"]))
    if a["outfile"] is None or b["outfile"] is None:
        raise AssertionError("app did not create the required out.bin")
    if a["outfile"] != b["outfile"]:
        raise AssertionError("app output file is nondeterministic")
    ctx.native["old"] = a
    return (f"2 runs identical, {len(a['stdout'].splitlines())} stdout lines, "
            f"out.bin {a['outfile'][:12]}")


def _baseline(ctx: Ctx) -> dict[str, Any]:
    if "old" not in ctx.native:
        raise SkipStage("no oldlib baseline (native/determinism did not complete)")
    return ctx.native["old"]


def stage_native_ok(ctx: Ctx) -> str:
    """The correct shim must be observationally indistinguishable."""
    old = _baseline(ctx)
    got = _run_app(RUN_DIR / "ok", "out.bin")
    ctx.native["ok"] = got
    if got["exit"] != old["exit"]:
        raise AssertionError(f"exit {got['exit']} != {old['exit']}")
    if got["stdout_raw"] != old["stdout_raw"]:
        raise AssertionError("stdout differs: "
                             + _first_difference(old["stdout"], got["stdout"]))
    if got["stderr_raw"] != old["stderr_raw"]:
        raise AssertionError("stderr differs: "
                             + _first_difference(old["stderr"], got["stderr"]))
    if got["outfile"] != old["outfile"]:
        raise AssertionError("out.bin hash differs")
    return "exit, stdout, stderr and out.bin all identical to oldlib"


def stage_native_bugs(ctx: Ctx) -> str:
    """Every planted defect must be observable, and survivable.

    A shim that crashes is caught by any smoke test; the interesting defect is
    the one the app runs straight through, which is what a trace differential
    exists to find.
    """
    old = _baseline(ctx)
    notes = []
    for planted in PLANTED:
        got = _run_app(RUN_DIR / planted.shim, "out.bin")
        ctx.native[planted.shim] = got
        if got["exit"] != 0:
            raise AssertionError(
                f"{planted.shim}: app exited {got['exit']} -- a crashing shim "
                f"is not the defect class under test\n{got['stdout']}")
        same_out = got["stdout_raw"] == old["stdout_raw"]
        same_file = got["outfile"] == old["outfile"]
        if not planted.native_visible:
            # Declared invisible at the boundary. Assert that, rather than
            # assuming it: if the app CAN see this defect after all, the trace
            # stage that claims to be the only witness is overselling itself.
            if not (same_out and same_file):
                raise AssertionError(
                    f"{planted.shim}: declared invisible at the boundary but "
                    f"the app can see it -- stdout "
                    + _first_difference(old["stdout"], got["stdout"])
                    + f"; out.bin same={same_file}")
            notes.append(f"{planted.shim}: INVISIBLE at the boundary "
                         f"(identical exit, stdout and out.bin) -- only a "
                         f"trace differential can catch it")
            continue
        if same_out and same_file:
            raise AssertionError(
                f"{planted.shim}: indistinguishable from oldlib at the boundary "
                f"-- the planted defect ({planted.why}) is undetectable, so the "
                f"trace assertion for it would be vacuous")
        if not same_out:
            notes.append(f"{planted.shim}: stdout "
                         + _first_difference(old["stdout"], got["stdout"]))
        else:
            notes.append(f"{planted.shim}: out.bin hash only")
    return " | ".join(notes)


def stage_contract(ctx: Ctx) -> str:
    """contract.json must load, and describe the DLL that was actually built."""
    try:
        contract = Contract.load(CONTRACT_PATH)
    except ContractError as exc:
        raise AssertionError(str(exc)) from exc
    ctx.contract = contract

    exports, source = _read_exports(BUILD_DIR / "oldlib.dll")
    declared = {name: sym.ordinal for name, sym in contract.symbols.items()}
    problems = []
    for name, ordinal in sorted(declared.items()):
        if ordinal not in exports:
            problems.append(f"{name}: contract ordinal {ordinal} not exported")
            continue
        actual_name = exports[ordinal]
        sym = contract.symbols[name]
        if sym.noname:
            if actual_name:
                problems.append(f"{name}: declared NONAME but exported as "
                                f"'{actual_name}'")
        elif actual_name != name:
            problems.append(f"ordinal {ordinal}: contract says {name}, "
                            f"dll says '{actual_name}'")
    extra = set(exports) - set(declared.values())
    if extra:
        problems.append(f"dll exports ordinals absent from contract: {sorted(extra)}")
    if problems:
        raise AssertionError("; ".join(problems))

    unknown = [(s.name, a.name) for s in contract.symbols.values()
               for a in s.args if a.kind == "ptr" and not a.records_bytes]
    return (f"{len(declared)} symbols match oldlib.dll exports (via {source}); "
            f"{len(contract.structs)} structs; "
            f"unknown-extent args: {unknown or 'none'}")


def _read_exports(dll: Path) -> tuple[dict[int, str], str]:
    """{ordinal: name} for a built DLL. Prefers pe_surface, falls back to lief.

    The fallback is an independent read of the same PE, not a stand-in for
    pe_surface: this stage has to be able to check the contract against reality
    even before pe_surface exists.
    """
    pe_surface = _optional("pe_surface")
    if pe_surface is not None and hasattr(pe_surface, "read_exports"):
        surface = pe_surface.read_exports(dll)
        return ({e.ordinal: (e.name or "") for e in surface.by_ordinal.values()},
                "pe_surface")
    import lief  # dependency of the package; not a substitute module

    binary = lief.PE.parse(str(dll))
    table = binary.get_export()
    return ({int(e.ordinal): (e.name or "") for e in table.entries}, "lief")


# --------------------------------------------------------------------------
# trace stages
# --------------------------------------------------------------------------

def _stage_tap_run_dir(label: str, dirname: str, tap_dll: Path) -> Path:
    """A run directory where app.exe loads the tap and the tap loads `label`."""
    d = TAP_DIR / dirname
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    shutil.copy2(BUILD_DIR / "app.exe", d / "app.exe")
    shutil.copy2(tap_dll, d / "oldlib.dll")
    shutil.copy2(BUILD_DIR / IMPLS[label], d / "oldlib_real.dll")
    if label != "old":
        shutil.copy2(BUILD_DIR / "newlib.dll", d / "newlib.dll")
    return d


def stage_tap_build(ctx: Ctx) -> str:
    gen_tap, pe_surface = _need("gen_tap", "pe_surface")
    if ctx.contract is None:
        raise SkipStage("contract stage did not complete")

    outdir = BUILD_DIR / "tapsrc"
    outdir.mkdir(parents=True, exist_ok=True)
    # Hand over the real export table so the tap reproduces ordinals and the
    # NONAME at 8 exactly, rather than re-deriving them from the contract.
    surface = pe_surface.read_exports(BUILD_DIR / "oldlib.dll")
    gen_tap.generate_tap(ctx.contract, outdir, surface=surface)

    tap_c = outdir / "tap.c"
    tap_def = outdir / "tap.def"
    if not tap_c.is_file() or not tap_def.is_file():
        raise SkipStage(f"gen_tap ran but produced no tap.c/tap.def in {outdir}")
    runtime_c = PKG_DIR / "runtime" / "tr_record.c"
    if not runtime_c.is_file():
        raise SkipStage(f"runtime/tr_record.c missing ({runtime_c})")

    tap_dll = BUILD_DIR / "tap.dll"
    cmd = [
        _clang(), "-shared", "-Wall", "-Wextra", "-O1",
        "-I", str(PKG_DIR / "runtime"),
        "-o", str(tap_dll), str(tap_c), str(runtime_c),
        f"-Wl,/DEF:{tap_def}",
    ]
    # Explicit utf-8: text=True alone decodes with the locale codec, which on a
    # cp949 (or any non-utf8) console throws inside subprocess' reader thread
    # the moment a build path contains non-ASCII characters.
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300,
                          check=False)
    if proc.returncode != 0:
        raise AssertionError(f"tap build failed:\n{proc.stdout}\n{proc.stderr}")
    ctx.tap_dll = tap_dll
    return (f"tap.dll from generated tap.c ({tap_c.stat().st_size} B) "
            f"+ tr_record.c")


def _clang() -> str:
    found = shutil.which("clang")
    return found or r"C:\Program Files\LLVM\bin\clang.exe"


def _record(ctx: Ctx, label: str, run_id: str) -> Trace:
    """Run the app against `label` through the tap and read back the trace."""
    if ctx.tap_dll is None:
        raise SkipStage("no tap.dll (tap-build did not complete)")
    d = _stage_tap_run_dir(label, f"{label}-{run_id}", ctx.tap_dll)
    trace_path = d / "trace.jsonl"
    env = dict(os.environ)
    # The parent environment is not evidence. Remove every recorder control
    # and set the complete, reviewed values explicitly so TAP_MAXCAP=0 or an
    # inherited passthrough flag cannot manufacture a clean trace.
    for var in TAP_ENV_VARS:
        env.pop(var, None)
    env[TRACE_ENV] = str(trace_path)
    env["TAP_LABEL"] = "shimforge-selftest"
    env["TAP_MAXCAP"] = str(1024 * 1024)
    env["TAP_SUBJECT_SHA256"] = _sha256(BUILD_DIR / IMPLS[label])

    result = _run_app(d, "out.bin", env=env)
    if result["exit"] != 0:
        raise AssertionError(f"{label}: tapped app exited {result['exit']}\n"
                             f"{result['stdout']}{result['stderr']}")
    baseline = ctx.native.get(label)
    if baseline is None:
        raise SkipStage(f"no recording-off baseline for {label}")
    changed = []
    for key in ("exit", "stdout_raw", "stderr_raw", "outfile"):
        if result[key] != baseline[key]:
            changed.append(key)
    if changed:
        raise AssertionError(
            f"{label}: enabling trace recording changed observable behaviour "
            f"({', '.join(changed)}); the recorder is not transparent")
    if not trace_path.is_file():
        found = sorted(d.glob("*.jsonl"))
        if not found:
            raise SkipStage(
                f"tap wrote no trace in {d}; tried env {list(TRACE_ENV_VARS)}")
        trace_path = found[0]
    trace = read_trace(trace_path)
    if not trace.calls:
        raise AssertionError(f"{label}: trace {trace_path.name} has no calls")
    return trace


def stage_record_old(ctx: Ctx) -> str:
    ctx.traces["old"] = _record(ctx, "old", "a")
    ctx.traces["old2"] = _record(ctx, "old", "b")
    counts = ctx.traces["old"].symbol_counts()
    return (f"{len(ctx.traces['old'].calls)} records, "
            f"{len(counts)} distinct symbols: "
            + ", ".join(f"{k}x{v}" for k, v in sorted(counts.items())))


def _normalize_all(ctx: Ctx) -> tuple[Any, Any]:
    policy_mod, normalize_mod, tracediff_mod = _need(
        "policy", "normalize", "tracediff")
    if ctx.contract is None:
        raise SkipStage("contract stage did not complete")
    if ctx.policy is None:
        ctx.policy = policy_mod.Policy.derive(ctx.contract)
    return normalize_mod, tracediff_mod


def stage_oracle_determinism(ctx: Ctx) -> str:
    """L0 check 3. Until this is empty every later diff is noise."""
    normalize_mod, tracediff_mod = _normalize_all(ctx)
    if "old2" not in ctx.traces:
        raise SkipStage("no recorded traces (record stage did not complete)")
    a = normalize_mod.normalize(ctx.traces["old"], ctx.contract, ctx.policy)
    b = normalize_mod.normalize(ctx.traces["old2"], ctx.contract, ctx.policy)
    ctx.norm["old"] = a
    # stop_after=0: the determinism pass wants every nondeterministic field in
    # one go so it can propose masks for all of them.
    result = tracediff_mod.diff(a, b, ctx.policy, stop_after=0)
    if result.total != 0 or not result.ok:
        first = getattr(result, "first", None)
        suggestions = [getattr(s, "path", "?") for s in
                       getattr(result, "suggestions", [])]
        raise AssertionError(
            f"A-vs-A diff not empty: {result.total} divergence(s); first="
            f"{_describe(first)}; mask suggestions={suggestions}")
    # "no divergence over nothing" is not the property being asserted: a
    # normalizer that dropped every record would satisfy the check above.
    if not result.compared_calls:
        raise AssertionError(
            f"A-vs-A diff compared 0 calls although the trace holds "
            f"{len(ctx.traces['old'].calls)} -- an empty comparison is a "
            f"vacuous pass, not a determinism result")
    return f"A-vs-A empty over {result.compared_calls} compared calls"


def stage_oracle_full(ctx: Ctx) -> str:
    """The whole five-check L0 driver against the original library."""
    oracle, = _need("oracle_check")
    if ctx.tap_dll is None:
        raise SkipStage("no tap.dll (tap-build did not complete)")
    cfg = oracle.OracleConfig(
        contract=CONTRACT_PATH,
        original_dll=BUILD_DIR / "oldlib.dll",
        tap_dll=ctx.tap_dll,
        # {run_dir} expands to the staged directory, which is the only place
        # the tap is the DLL that actually gets loaded. A bare "app.exe" would
        # be resolved by CreateProcess against PATH, not against cwd.
        scenario=["{run_dir}\\app.exe", "out.bin"],
        work_dir=TAP_DIR / "oracle",
        consumers=[BUILD_DIR / "app.exe"],
        app_files=[BUILD_DIR / "app.exe"],
        trace_env=TRACE_ENV,
    )
    report = oracle.check_oracle(cfg)
    bad = [o.name for o in report.outcomes if not o.ok]
    if bad:
        raise AssertionError(f"failing checks: {bad}\n{report.render()}")
    return "; ".join(f"{o.name}: {o.detail}" for o in report.outcomes)


def _describe(div: Any) -> str:
    if div is None:
        return "none"
    parts = [str(getattr(div, "kind", "?"))]
    sym = getattr(div, "sym", "")
    path = getattr(div, "path", "")
    if sym:
        parts.append(sym)
    if path:
        parts.append(path)
    off = getattr(div, "byte_offset", None)
    if off is not None:
        parts.append(f"@{off}")
    return " ".join(parts)


def _ab(div: Any) -> str:
    """`A=.. B=..`, but only when both sides are short enough to read.

    A shifted 256 byte readback renders as two 512 character hex strings; that
    is what the divergence report is for, not what a one line stage detail is
    for.
    """
    a, b = repr(getattr(div, "a", None)), repr(getattr(div, "b", None))
    if max(len(a), len(b)) > 40:
        return ""
    return f" A={a} B={b}"


def _boundary_visibility(ctx: Ctx, planted: Planted) -> str:
    """What the APP could see, measured rather than assumed.

    The point of a trace differential is the defect nobody downstream can
    observe, so whether this one was visible at the boundary is part of the
    result, not a footnote.
    """
    base, got = ctx.native.get("old"), ctx.native.get(planted.shim)
    if not base or not got:
        return "boundary visibility not measured"
    if got["stdout_raw"] == base["stdout_raw"] and \
            got["stderr_raw"] == base["stderr_raw"] and \
            got["outfile"] == base["outfile"]:
        return ("app CANNOT see this: identical stdout and out.bin -- the "
                "trace differential is the only witness")
    return "app can also see this at the boundary"


def _diff_against_old(ctx: Ctx, label: str) -> Any:
    normalize_mod, tracediff_mod = _normalize_all(ctx)
    if "old" not in ctx.traces:
        raise SkipStage("no recorded traces (record stage did not complete)")
    if "old" not in ctx.norm:
        ctx.norm["old"] = normalize_mod.normalize(
            ctx.traces["old"], ctx.contract, ctx.policy)
    trace_b = _record(ctx, label, "b")
    ctx.traces[label] = trace_b
    norm_b = normalize_mod.normalize(trace_b, ctx.contract, ctx.policy)
    return tracediff_mod.diff(ctx.norm["old"], norm_b, ctx.policy, stop_after=1)


def stage_diff_ok(ctx: Ctx) -> str:
    result = _diff_against_old(ctx, "ok")
    if not result.ok:
        raise AssertionError(
            f"correct shim reported divergent: {_describe(result.first)}\n"
            + result.render(verbose=True))
    if not result.compared_calls:
        raise AssertionError(
            "diff compared 0 calls -- 'clean' over an empty comparison proves "
            "nothing about the correct shim")
    return f"clean over {result.compared_calls} compared calls"


def _make_bug_stage(planted: Planted) -> Callable[[Ctx], str]:
    def stage(ctx: Ctx) -> str:
        result = _diff_against_old(ctx, planted.shim)
        if result.ok or result.first is None:
            raise AssertionError(
                f"differ found nothing, but {planted.shim} really does "
                f"misbehave ({planted.why}) -- this is a differ bug, not a "
                f"shim bug")
        div = result.first
        got_kind = str(getattr(div, "kind", ""))
        got_sym = str(getattr(div, "sym", "") or "")
        got_path = str(getattr(div, "path", "") or "")
        problems = []
        if got_kind not in planted.kinds:
            problems.append(f"kind {got_kind!r} not in {sorted(planted.kinds)}")
        if got_sym not in planted.syms:
            problems.append(f"sym {got_sym!r} not in {sorted(planted.syms)}")
        if planted.path is not None and got_path != planted.path:
            problems.append(f"path {got_path!r} != {planted.path!r}")
        if planted.path_prefix is not None and not got_path.startswith(
                planted.path_prefix):
            problems.append(
                f"path {got_path!r} does not start with {planted.path_prefix!r}")
        if problems:
            raise AssertionError(
                "divergence found but it is the wrong one: "
                + "; ".join(problems)
                + f" (got {_describe(div)})")
        return (f"{_describe(div)}{_ab(div)} -- {planted.why} "
                f"[{_boundary_visibility(ctx, planted)}]")

    stage.__name__ = f"stage_diff_{planted.shim}"
    return stage


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

def build_stages() -> list[tuple[str, Callable[[Ctx], str]]]:
    stages: list[tuple[str, Callable[[Ctx], str]]] = [
        ("native/build", stage_build),
        ("native/determinism", stage_native_determinism),
        ("native/shim-ok-identical", stage_native_ok),
        ("native/planted-defects-visible", stage_native_bugs),
        ("native/contract-vs-dll", stage_contract),
        ("trace/tap-build", stage_tap_build),
        ("trace/record-old-x2", stage_record_old),
        ("trace/oracle-determinism", stage_oracle_determinism),
        ("trace/oracle-full", stage_oracle_full),
        ("trace/diff-shim-ok", stage_diff_ok),
    ]
    stages += [(f"trace/diff-{p.shim}", _make_bug_stage(p)) for p in PLANTED]
    return stages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-build", action="store_true",
                        help="reuse build/ instead of running build.ps1")
    parser.add_argument("--allow-skip", action="store_true",
                        help="development only: return success despite skipped stages")
    parser.add_argument("--strict", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    if not _acquire_selftest_mutex():
        print("[FAIL] another shimforge selftest is already using the fixed "
              "build/trace workspace", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")

    ctx = Ctx(args=args)
    results: list[StageResult] = []
    for name, fn in build_stages():
        try:
            detail = fn(ctx)
            results.append(StageResult(name, PASS, detail))
        except SkipStage as exc:
            results.append(StageResult(name, SKIP, str(exc)))
        except AssertionError as exc:
            results.append(StageResult(name, FAIL, str(exc).replace("\n", " | ")))
        except Exception as exc:                   # noqa: BLE001
            if args.verbose:
                logger.exception("%s blew up", name)
            results.append(StageResult(
                name, FAIL, f"{type(exc).__name__}: {exc}"))
        print(f"[{results[-1].status}] {name}: {results[-1].detail}", flush=True)

    width = max(len(r.name) for r in results)
    print("\n" + "=" * (width + 60))
    print(f"{'STAGE'.ljust(width)}  STATUS  DETAIL")
    print("-" * (width + 60))
    for r in results:
        detail = r.detail if len(r.detail) <= 200 else r.detail[:197] + "..."
        print(f"{r.name.ljust(width)}  {r.status:<6}  {detail}")
    print("=" * (width + 60))

    n_pass = sum(1 for r in results if r.status == PASS)
    n_fail = sum(1 for r in results if r.status == FAIL)
    n_skip = sum(1 for r in results if r.status == SKIP)
    print(f"{n_pass} passed, {n_fail} failed, {n_skip} skipped")
    allow_skip = args.allow_skip and not args.strict
    if n_skip and allow_skip:
        print("WARNING: skipped stages are NOT passes; --allow-skip only "
              "relaxes the process exit for incremental development")
    if _IMPORT_ERRORS:
        print("unavailable modules: "
              + ", ".join(f"{k} [{v}]" for k, v in sorted(_IMPORT_ERRORS.items())))

    if n_fail:
        return 1
    if n_skip and not allow_skip:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
