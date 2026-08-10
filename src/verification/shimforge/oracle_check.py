"""L0 validation for the recording tap and its evidence.

The checks cover PE structure, pass-through behavior, trace determinism,
contract coverage, and recording overhead.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib
import json
import logging
import math
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from . import runner
from . import trace as trace_mod
from .model import Contract, ContractError, POINTER_KINDS
from .runner import RunResult

logger = logging.getLogger(__name__)

__all__ = [
    "OracleConfig", "CheckOutcome", "OracleReport", "check_oracle",
    "trace_approval_coverage_problems", "main",
]

CHECK_ORDER = ("structural", "passthrough", "determinism", "coverage",
               "noninterference")
ORACLE_REPORT_SCHEMA = "shimforge-oracle/2"

# Credit scoring targets. A symbol called once with one argument shape has been
# touched, not verified; these are the "enough to mean something" thresholds.
CREDIT_TARGET_CALLS = 3
CREDIT_TARGET_CLASSES = 2
CREDIT_W_CALLS = 0.4
CREDIT_W_CLASSES = 0.4
CREDIT_W_SPEC = 0.2
DEFAULT_MAX_CAPTURE_BYTES = 1 << 20
HARD_MAX_CAPTURE_BYTES = 16 << 20

ORACLE_CONFIG_KEYS = {
    "_comment", "contract", "original_dll", "tap_dll", "scenario",
    "work_dir", "policy", "consumers", "app_files", "dll_name",
    "real_dll_name", "watch_dirs", "normalizers", "common_normalizers",
    "env", "trace_env", "label_env", "passthrough_env",
    "max_capture_bytes", "determinism_runs", "timeout_s", "ignore_stderr",
    "required_names", "required_ordinals", "min_coverage",
    "min_mean_credit", "min_calls_per_symbol", "min_classes_per_symbol",
    "require_bytes_complete", "time_ratio_max", "handle_delta_max",
    "bytes_delta_max", "min_measurable_s", "require_measurable_time",
    "require_resource_metrics", "require_observable_baseline", "write_policy",
}

_WINDOWS_RESERVED_LEAVES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _leaf_problem(value: str, label: str, *, allow_empty: bool = False) -> str:
    """Return a reason when *value* is unsafe as a staged file leaf.

    ``dll_name`` and ``real_dll_name`` are joined to a disposable run
    directory immediately before copy.  Treating either as a path would let a
    typo (or a hostile config) escape that directory.  Windows also accepts a
    surprising set of device aliases as apparent filenames, so reject those
    here rather than discovering them during a run.
    """
    if not value:
        return "" if allow_empty else f"{label} is empty"
    if value in (".", "..") or Path(value).name != value:
        return f"{label} must be a filename only, not a path: {value!r}"
    if value[-1:] in (" ", "."):
        return f"{label} must not end in a space or dot: {value!r}"
    if any(ord(ch) < 32 or ch in '<>:"/\\|?*' for ch in value):
        return f"{label} contains a Windows-invalid filename character: {value!r}"
    stem = value.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_LEAVES:
        return f"{label} is a reserved Windows device name: {value!r}"
    return ""


def _is_reparse_point(path: Path) -> bool:
    """True for symlinks and Windows junction/other reparse points."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        # An uninspectable path is not safe to delete or follow.
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    junction = getattr(path, "is_junction", None)
    if callable(junction) and junction():
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _strict_bool(d: dict[str, Any], key: str, default: bool) -> bool:
    value = d.get(key, default)
    if type(value) is not bool:
        raise ValueError(f"{key} must be true or false, got {value!r}")
    return value


def _strict_int(d: dict[str, Any], key: str, default: int) -> int:
    value = d.get(key, default)
    if type(value) is not int:
        raise ValueError(f"{key} must be an integer, got {value!r}")
    return value


def _strict_float(d: dict[str, Any], key: str, default: float) -> float:
    value = d.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number, got {value!r}")
    return float(value)


def _strict_list(d: dict[str, Any], key: str,
                 default: list[Any] | None = None) -> list[Any]:
    value = d.get(key, [] if default is None else default)
    if type(value) is not list:
        raise ValueError(f"{key} must be a JSON array, got {value!r}")
    return value


def _strict_str(d: dict[str, Any], key: str, default: str = "") -> str:
    value = d.get(key, default)
    if type(value) is not str:
        raise ValueError(f"{key} must be a string, got {value!r}")
    return value


# --------------------------------------------------------------------------
# configuration


@dataclass
class OracleConfig:
    """Everything the five checks need, loaded from a JSON file.

    Relative paths resolve against the directory holding the config file, so a
    config can sit next to the artifacts it names.
    """

    contract: Path
    original_dll: Path
    tap_dll: Path
    scenario: list[str]
    work_dir: Path

    policy: Path | None = None
    consumers: list[Path] = field(default_factory=list)
    app_files: list[Path] = field(default_factory=list)

    # Name the application actually loads. Defaults to the original's filename.
    dll_name: str = ""
    # Renamed original the tap forwards to; defaults to Contract.real_module.
    real_dll_name: str = ""

    watch_dirs: list[str] = field(default_factory=lambda: ["."])
    normalizers: list[tuple[str, str]] = field(default_factory=list)
    # Off by default. `runner.COMMON_NORMALIZERS` erases anything that merely
    # LOOKS like an address or an epoch, which includes 8-digit hex checksums
    # and 10-digit counters -- exactly the values an app prints to show its
    # data survived intact. Erasing them by default lets the passthrough check
    # pass while the tap is visibly corrupting output. Opt in per target once
    # the run-to-run noise is understood.
    common_normalizers: bool = False
    env: dict[str, str] = field(default_factory=dict)

    # How the tap learns where to write its trace, how it is labelled and how
    # it is muted. Defaults match runtime/tr_record.c; they stay configurable
    # because they are a contract with the generated C runtime, not with this
    # module.
    trace_env: str = "TAP_TRACE"
    label_env: str = "TAP_LABEL"
    passthrough_env: str = "TAP_PASSTHROUGH"
    # runtime/tr_record.c intentionally fixes this control name to
    # TAP_MAXCAP.  Set it for every run so a hostile/stale parent environment
    # cannot silently turn byte capture off.
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES

    determinism_runs: int = 2
    timeout_s: float = 120.0
    ignore_stderr: bool = False

    required_names: list[str] = field(default_factory=list)
    required_ordinals: list[int] = field(default_factory=list)

    min_coverage: float = 1.0
    # Coverage is an approval gate, not a dashboard.  By default every
    # required export/callback must have enough calls, enough distinct input
    # classes, a complete contract and complete bytes.  Higher thresholds are
    # allowed; problems() rejects lower ones because they bypass approval
    # evidence rather than merely tuning it.
    min_mean_credit: float = 1.0
    min_calls_per_symbol: int = CREDIT_TARGET_CALLS
    min_classes_per_symbol: int = CREDIT_TARGET_CLASSES
    require_bytes_complete: bool = True

    time_ratio_max: float = 3.0
    handle_delta_max: int = 64
    bytes_delta_max: int = 128 << 20
    # Below this, wall clock is dominated by process startup and the ratio is
    # meaningless; report it but do not fail on it.
    min_measurable_s: float = 0.05
    require_measurable_time: bool = True
    require_resource_metrics: bool = True
    require_observable_baseline: bool = True

    write_policy: bool = False
    source: str = ""

    @classmethod
    def from_json(cls, d: dict[str, Any], base: Path) -> "OracleConfig":
        if type(d) is not dict:
            raise ValueError("oracle config must be a JSON object")
        unknown = sorted(set(d) - ORACLE_CONFIG_KEYS)
        if unknown:
            raise ValueError("unknown oracle config key(s): "
                             + ", ".join(map(repr, unknown)))

        def p(value: Any) -> Path:
            if type(value) is not str or not value:
                raise ValueError(f"path must be a non-empty string, got {value!r}")
            path = Path(str(value))
            return path if path.is_absolute() else (base / path)

        def plist(key: str) -> list[Path]:
            return [p(x) for x in _strict_list(d, key)]

        for required in ("contract", "original_dll", "tap_dll", "scenario"):
            if required not in d:
                raise ValueError(f"missing required config key: {required}")
        scenario = _strict_list(d, "scenario")
        if any(type(x) is not str for x in scenario):
            raise ValueError("scenario entries must all be strings")
        watch_dirs = _strict_list(d, "watch_dirs", ["."])
        if any(type(x) is not str for x in watch_dirs):
            raise ValueError("watch_dirs entries must all be strings")
        required_names = _strict_list(d, "required_names")
        if any(type(x) is not str or not x for x in required_names):
            raise ValueError("required_names entries must be non-empty strings")
        required_ordinals = _strict_list(d, "required_ordinals")
        if any(type(x) is not int for x in required_ordinals):
            raise ValueError("required_ordinals entries must be integers")
        normalizers_raw = _strict_list(d, "normalizers")
        normalizers: list[tuple[str, str]] = []
        for i, rule in enumerate(normalizers_raw):
            if (type(rule) is not list or len(rule) != 2
                    or any(type(x) is not str for x in rule)):
                raise ValueError(
                    f"normalizers[{i}] must be [pattern, replacement] strings")
            normalizers.append((rule[0], rule[1]))
        env_raw = d.get("env", {})
        if type(env_raw) is not dict or any(
                type(k) is not str or type(v) is not str
                for k, v in env_raw.items()):
            raise ValueError("env must be an object of string keys and values")

        cfg = cls(
            contract=p(d["contract"]),
            original_dll=p(d["original_dll"]),
            tap_dll=p(d["tap_dll"]),
            scenario=list(scenario),
            work_dir=p(d.get("work_dir", "oracle_work")),
            policy=p(d["policy"]) if d.get("policy") else None,
            consumers=plist("consumers"),
            app_files=plist("app_files"),
            dll_name=_strict_str(d, "dll_name"),
            real_dll_name=_strict_str(d, "real_dll_name"),
            watch_dirs=list(watch_dirs),
            normalizers=normalizers,
            common_normalizers=_strict_bool(d, "common_normalizers", False),
            env=dict(env_raw),
            trace_env=_strict_str(d, "trace_env", "TAP_TRACE"),
            label_env=_strict_str(d, "label_env", "TAP_LABEL"),
            passthrough_env=_strict_str(
                d, "passthrough_env", "TAP_PASSTHROUGH"),
            max_capture_bytes=_strict_int(
                d, "max_capture_bytes", DEFAULT_MAX_CAPTURE_BYTES),
            determinism_runs=_strict_int(d, "determinism_runs", 2),
            timeout_s=_strict_float(d, "timeout_s", 120.0),
            ignore_stderr=_strict_bool(d, "ignore_stderr", False),
            required_names=list(required_names),
            required_ordinals=list(required_ordinals),
            min_coverage=_strict_float(d, "min_coverage", 1.0),
            min_mean_credit=_strict_float(d, "min_mean_credit", 1.0),
            min_calls_per_symbol=_strict_int(
                d, "min_calls_per_symbol", CREDIT_TARGET_CALLS),
            min_classes_per_symbol=_strict_int(
                d, "min_classes_per_symbol", CREDIT_TARGET_CLASSES),
            require_bytes_complete=_strict_bool(
                d, "require_bytes_complete", True),
            time_ratio_max=_strict_float(d, "time_ratio_max", 3.0),
            handle_delta_max=_strict_int(d, "handle_delta_max", 64),
            bytes_delta_max=_strict_int(d, "bytes_delta_max", 128 << 20),
            min_measurable_s=_strict_float(d, "min_measurable_s", 0.05),
            require_measurable_time=_strict_bool(
                d, "require_measurable_time", True),
            require_resource_metrics=_strict_bool(
                d, "require_resource_metrics", True),
            require_observable_baseline=_strict_bool(
                d, "require_observable_baseline", True),
            write_policy=_strict_bool(d, "write_policy", False),
        )
        return cfg

    @classmethod
    def load(cls, path: str | Path) -> "OracleConfig":
        path = Path(path)
        # utf-8-sig, not utf-8: Notepad and PowerShell's Set-Content both write
        # a BOM, and json.loads rejects it outright.
        d = json.loads(path.read_text(encoding="utf-8-sig"))
        cfg = cls.from_json(d, path.resolve().parent)
        cfg.source = str(path)
        return cfg

    @property
    def target_dll_name(self) -> str:
        return self.dll_name or self.original_dll.name

    def problems(self) -> list[str]:
        out: list[str] = []
        for label, path in (("contract", self.contract),
                            ("original_dll", self.original_dll),
                            ("tap_dll", self.tap_dll)):
            if not Path(path).is_file():
                out.append(f"{label} not found: {path}")
        for c in self.consumers:
            if not Path(c).exists():
                out.append(f"consumer not found: {c}")
        for f in self.app_files:
            if not Path(f).exists():
                out.append(f"app_file not found: {f}")
        if self.policy and not self.policy.is_file():
            out.append(f"configured policy file not found: {self.policy}")
        try:
            if self.original_dll.resolve() == self.tap_dll.resolve():
                out.append("original_dll and tap_dll resolve to the same file")
        except OSError as exc:
            out.append(f"artifact path could not be resolved: {exc}")
        if not self.scenario:
            out.append("scenario command is empty")
        elif any(not arg for arg in self.scenario):
            out.append("scenario contains an empty argument")

        for label, value in (("dll_name", self.dll_name),
                             ("real_dll_name", self.real_dll_name)):
            problem = _leaf_problem(value, label, allow_empty=True)
            if problem:
                out.append(problem)
        target_problem = _leaf_problem(self.target_dll_name, "target_dll_name")
        if target_problem:
            out.append(target_problem)
        if (self.real_dll_name
                and self.real_dll_name.casefold() == self.target_dll_name.casefold()):
            out.append("real_dll_name must differ from the DLL name loaded by "
                       "the application")

        for label, value in (("trace_env", self.trace_env),
                             ("passthrough_env", self.passthrough_env)):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                out.append(f"{label} is not a conservative environment "
                           f"variable name: {value!r}")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.label_env):
            out.append(f"label_env is not a conservative environment "
                       f"variable name: {self.label_env!r}")
        controls = [self.trace_env, self.passthrough_env, self.label_env]
        if len({v.casefold() for v in controls}) != len(controls):
            out.append("trace_env, label_env and passthrough_env must be distinct")
        if any(v.casefold() == "tap_maxcap" for v in controls):
            out.append("trace_env, label_env and passthrough_env must not "
                       "alias the fixed TAP_MAXCAP control")
        for key, value in self.env.items():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
                out.append(f"env key is not a conservative Windows variable "
                           f"name: {key!r}")
            if "\x00" in value:
                out.append(f"env value for {key!r} contains NUL")
            if key.casefold().startswith("tap_"):
                out.append(f"env may not pre-set recorder control {key!r}")
            if key.casefold() in {"path", "temp", "tmp"}:
                out.append(f"env may not override isolated {key.upper()}")

        for wd in self.watch_dirs:
            path = Path(wd)
            if (not wd or path.is_absolute() or path.drive
                    or ".." in path.parts):
                out.append(f"watch_dir must remain inside each run directory: "
                           f"{wd!r}")
        if not any(Path(wd) == Path(".") for wd in self.watch_dirs):
            out.append("watch_dirs must include '.' so every staged file "
                       "change remains observable")

        for i, (pattern, _replacement) in enumerate(self.normalizers):
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                out.append(f"normalizers[{i}] has invalid regex: {exc}")
                continue
            if compiled.search("") is not None:
                out.append(f"normalizers[{i}] matches empty text and could "
                           "erase observables")
        if self.normalizers:
            out.append("custom observable normalizers are forbidden in "
                       "fail-closed mode")
        if self.common_normalizers:
            out.append("common_normalizers=true is forbidden in fail-closed "
                       "mode")

        numeric_ranges = (
            ("min_coverage", self.min_coverage, 0.0, 1.0),
            ("min_mean_credit", self.min_mean_credit, 0.0, 1.0),
        )
        for label, value, low, high in numeric_ranges:
            if not math.isfinite(value) or not low <= value <= high:
                out.append(f"{label} must be finite and in [{low}, {high}], "
                           f"got {value!r}")
        positive = (("timeout_s", self.timeout_s),
                    ("time_ratio_max", self.time_ratio_max))
        for label, value in positive:
            if not math.isfinite(value) or value <= 0:
                out.append(f"{label} must be finite and > 0, got {value!r}")
        if not math.isfinite(self.min_measurable_s) or self.min_measurable_s < 0:
            out.append("min_measurable_s must be finite and >= 0")
        if self.determinism_runs < 2:
            out.append("determinism_runs must be >= 2")
        if self.min_calls_per_symbol < 1:
            out.append("min_calls_per_symbol must be >= 1")
        if self.min_classes_per_symbol < 1:
            out.append("min_classes_per_symbol must be >= 1")
        if self.handle_delta_max < 0:
            out.append("handle_delta_max must be >= 0")
        if self.bytes_delta_max < 0:
            out.append("bytes_delta_max must be >= 0")
        if not (1 <= self.max_capture_bytes <= HARD_MAX_CAPTURE_BYTES):
            out.append(f"max_capture_bytes must be in [1, "
                       f"{HARD_MAX_CAPTURE_BYTES}]")
        if any(not (1 <= ordinal <= 65535)
               for ordinal in self.required_ordinals):
            out.append("required_ordinals must all be in [1, 65535]")

        # These switches/thresholds are not ordinary tuning in fail-closed
        # verification: relaxing any one removes evidence while still
        # allowing the report to say PASS.  More demanding values remain
        # valid; less demanding values require a different, explicitly
        # non-approval tool.
        if self.ignore_stderr:
            out.append("ignore_stderr=true is forbidden in fail-closed mode")
        if self.min_coverage < 1.0:
            out.append("min_coverage must be 1.0 in fail-closed mode")
        if self.min_mean_credit < 1.0:
            out.append("min_mean_credit must be 1.0 in fail-closed mode")
        if self.min_calls_per_symbol < CREDIT_TARGET_CALLS:
            out.append(f"min_calls_per_symbol must be >= {CREDIT_TARGET_CALLS} "
                       "in fail-closed mode")
        if self.min_classes_per_symbol < CREDIT_TARGET_CLASSES:
            out.append(f"min_classes_per_symbol must be >= "
                       f"{CREDIT_TARGET_CLASSES} in fail-closed mode")
        for label, enabled in (
                ("require_bytes_complete", self.require_bytes_complete),
                ("require_resource_metrics", self.require_resource_metrics),
                ("require_measurable_time", self.require_measurable_time),
                ("require_observable_baseline", self.require_observable_baseline)):
            if not enabled:
                out.append(f"{label}=false is forbidden in fail-closed mode")
        if self.write_policy:
            out.append("write_policy=true is not an approval mode; strict "
                       "policies accept only masks derived from the contract")

        if self.time_ratio_max > 3.0:
            out.append("time_ratio_max must be <= 3.0 in fail-closed mode")
        if self.handle_delta_max > 64:
            out.append("handle_delta_max must be <= 64 in fail-closed mode")
        if self.bytes_delta_max > (128 << 20):
            out.append("bytes_delta_max must be <= 134217728 in fail-closed mode")
        if self.min_measurable_s < 0.05:
            out.append("min_measurable_s must be >= 0.05 in fail-closed mode")

        leaves: dict[str, Path] = {}
        for app_file in self.app_files:
            leaf_problem = _leaf_problem(app_file.name, "app_file leaf")
            if leaf_problem:
                out.append(leaf_problem)
            key = app_file.name.casefold()
            if key in leaves and leaves[key] != app_file:
                out.append(f"app_files contain duplicate staged leaf "
                           f"{app_file.name!r}: {leaves[key]} and {app_file}")
            leaves[key] = app_file
        # The command being measured must be one of the immutable artifacts
        # copied into each run directory.  Otherwise an absolute host program
        # (or a typo that falls through PATH) can change while the evidence
        # manifest still claims every input stayed fixed.
        if not self.app_files:
            out.append("app_files must include the scenario executable so "
                       "the launched code is staged and SHA-256 bound")
        elif self.scenario:
            command = self.scenario[0]
            marker = "{run_dir}"
            if command.count(marker) > 1:
                out.append("scenario[0] may contain {run_dir} at most once")
            candidate = command.replace(marker + "\\", "").replace(
                marker + "/", "")
            if marker in candidate:
                out.append("scenario[0] must be either a staged leaf name or "
                           "{run_dir}\\<staged-leaf>")
            command_path = Path(candidate)
            if (not candidate or command_path.is_absolute()
                    or command_path.drive or len(command_path.parts) != 1
                    or candidate in (".", "..")
                    or "/" in candidate or "\\" in candidate):
                out.append("scenario[0] must resolve to one staged executable "
                           f"leaf, got {command!r}")
            elif candidate.casefold() not in leaves:
                out.append(f"scenario executable {candidate!r} is absent "
                           "from app_files")
        if self.work_dir.exists() and not self.work_dir.is_dir():
            out.append(f"work_dir is not a directory: {self.work_dir}")
        if _is_reparse_point(self.work_dir):
            out.append(f"work_dir must not be a symlink/junction/reparse point: "
                       f"{self.work_dir}")
        try:
            resolved_work = self.work_dir.resolve()
            if resolved_work == Path(resolved_work.anchor):
                out.append("work_dir must not be a filesystem root")
        except OSError as exc:
            out.append(f"work_dir could not be resolved safely: {exc}")
        return out


# --------------------------------------------------------------------------
# results


@dataclass
class CheckOutcome:
    name: str
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)
    suggestions: list = field(default_factory=list)

    @property
    def skipped(self) -> bool:
        return self.data.get("status") == "skipped"

    @property
    def superseded_by(self) -> str:
        """Name of a later outcome that re-ran this check and replaced it."""
        return self.data.get("superseded_by", "")

    def to_json(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail,
                "skipped": self.skipped, "superseded_by": self.superseded_by,
                "data": _jsonable(self.data),
                "suggestions": [_rule_json(r) for r in self.suggestions]}


@dataclass
class OracleReport:
    outcomes: list[CheckOutcome] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        # No in-place repair may erase a failed observation.  In particular a
        # policy fitted to this report's traces cannot "supersede" the failure
        # and convert the same evidence into a PASS.
        return bool(self.outcomes) and all(o.ok for o in self.outcomes)

    def get(self, name: str) -> CheckOutcome | None:
        for o in self.outcomes:
            if o.name == name:
                return o
        return None

    def render(self) -> str:
        lines = [f"shimforge oracle: {'PASS' if self.ok else 'FAIL'}"]
        pad = " " * 27
        for o in self.outcomes:
            if o.skipped:
                status = "SKIP"
            else:
                status = "PASS" if o.ok else "FAIL"
            head, *rest = (o.detail or "").splitlines() or [""]
            lines.append(f"  {'[' + status + ']':<8}{o.name:<16} {head}")
            lines.extend(pad + r for r in rest)
            for rule in o.suggestions:
                lines.append(pad + "propose mask " + _rule_text(rule))
        return "\n".join(lines)

    def to_json(self) -> dict:
        return {"schema": ORACLE_REPORT_SCHEMA,
                "ok": self.ok, "evidence": _jsonable(self.evidence),
                "outcomes": [o.to_json() for o in self.outcomes]}


# --------------------------------------------------------------------------
# lazy sibling imports


def _sibling(name: str) -> tuple[Any | None, str]:
    """Import a sibling module, returning (module, reason_if_missing)."""
    pkg = __package__ or "shimforge"
    try:
        return importlib.import_module(f".{name}", pkg), ""
    except Exception as exc:
        logger.debug("sibling %s unavailable", name, exc_info=True)
        return None, (f"module {pkg}.{name} not available "
                      f"({type(exc).__name__}: {exc})")


def _need(*names: str) -> tuple[dict[str, Any], str]:
    mods: dict[str, Any] = {}
    missing: list[str] = []
    for n in names:
        mod, reason = _sibling(n)
        if mod is None:
            missing.append(reason)
        else:
            mods[n] = mod
    return mods, "; ".join(missing)


# --------------------------------------------------------------------------
# run context


class _RunError(RuntimeError):
    pass


def _run_health_problems(label: str, result: RunResult) -> list[str]:
    """Conditions under which a run cannot be evidence for a PASS."""
    problems: list[str] = []
    if result.timed_out:
        problems.append(f"{label} timed out")
    if result.exit_code != 0:
        problems.append(f"{label} exited {result.exit_code}; only exit 0 is "
                        "valid oracle evidence")
    if getattr(result, "output_limit_exceeded", False):
        problems.append(f"{label} exceeded the bounded stdout/stderr capture; "
                        "truncated output cannot be compared")
    capture_errors = getattr(result, "capture_errors", None)
    if capture_errors:
        problems.append(f"{label} output capture failed: "
                        + "; ".join(map(str, capture_errors)))
    filesystem_errors = getattr(result, "filesystem_errors", None)
    if filesystem_errors:
        problems.append(f"{label} filesystem observation failed: "
                        + "; ".join(map(str, filesystem_errors)))
    for stream in ("stdout_raw", "stderr_raw"):
        if not isinstance(getattr(result, stream, None), bytes):
            problems.append(f"{label} has no raw {stream[:-4]} byte capture")
    unreadable = sorted(
        name for name, digest in getattr(result, "output_files", {}).items()
        if isinstance(digest, str) and digest.startswith("<unreadable:"))
    if unreadable:
        problems.append(f"{label} has unreadable watched output(s): "
                        + ", ".join(unreadable[:20]))
    invalid_hashes = sorted(
        name for name, digest in getattr(result, "output_files", {}).items()
        if digest != getattr(runner, "REMOVED", "<removed>")
        and (not isinstance(digest, str)
             or re.fullmatch(r"[0-9a-f]{64}", digest) is None)
        and name not in unreadable)
    if invalid_hashes:
        problems.append(f"{label} has invalid watched-output digest(s): "
                        + ", ".join(invalid_hashes[:20]))
    return problems


def _run_evidence(result: RunResult) -> dict[str, Any]:
    stdout_raw = getattr(result, "stdout_raw", None)
    stderr_raw = getattr(result, "stderr_raw", None)
    return {
        "summary": result.summary(),
        "pid": getattr(result, "pid", None),
        "stdout_sha256": (hashlib.sha256(stdout_raw).hexdigest()
                           if isinstance(stdout_raw, bytes) else None),
        "stderr_sha256": (hashlib.sha256(stderr_raw).hexdigest()
                           if isinstance(stderr_raw, bytes) else None),
        "output_files": dict(getattr(result, "output_files", {})),
    }


class _Ctx:
    """Owns the staged run directories and caches run results.

    Runs are expensive and shared between checks (2 needs the no-tap run, 5
    needs it again), so each one happens at most once per report.
    """

    def __init__(self, cfg: OracleConfig, contract: Contract | None) -> None:
        self.cfg = cfg
        self.contract = contract
        self._notap: RunResult | None = None
        self._passthrough: RunResult | None = None
        self._records: list[tuple[RunResult, Path]] = []

    # -- staging ----------------------------------------------------------

    def _stage(self, name: str, *, use_tap: bool) -> Path:
        cfg = self.cfg
        run_dir = cfg.work_dir / "runs" / name
        work_root = cfg.work_dir.resolve()
        resolved_run = run_dir.resolve()
        if work_root == resolved_run or work_root not in resolved_run.parents:
            raise _RunError(f"run directory escapes configured work_dir: "
                            f"{run_dir} -> {resolved_run}")
        if _is_reparse_point(run_dir):
            raise _RunError(f"refusing to remove reparse-point run directory: "
                            f"{run_dir}")
        if run_dir.parent.exists() and _is_reparse_point(run_dir.parent):
            raise _RunError(f"runs parent is a reparse point: {run_dir.parent}")
        if run_dir.exists():
            # A stale DLL/output left after a best-effort delete can make the
            # next run appear identical without executing the newly staged
            # artifacts.  Deletion is therefore transactional evidence: any
            # error, or any surviving path, aborts the check.
            shutil.rmtree(run_dir)
        if run_dir.exists():
            raise _RunError(f"stale run directory survived removal: {run_dir}")
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir(exist_ok=False)

        def copy_verified(src: Path, dst: Path) -> None:
            before_kind, before = _sha256_artifact(src)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            after_kind, after = _sha256_artifact(src)
            copied_kind, copied = _sha256_artifact(dst)
            if (before_kind != after_kind or before != after
                    or copied_kind != before_kind or copied != before):
                raise _RunError(
                    f"artifact changed or copied non-identically while "
                    f"staging {src} -> {dst}")

        for src in cfg.app_files:
            src = Path(src)
            dst = run_dir / src.name
            copy_verified(src, dst)
        target = run_dir / cfg.target_dll_name
        if use_tap:
            copy_verified(cfg.tap_dll, target)
            real = cfg.real_dll_name or (
                self.contract.real_module if self.contract else "")
            if real and real != cfg.target_dll_name:
                copy_verified(cfg.original_dll, run_dir / real)
            elif real:
                logger.warning("real_dll_name equals the loaded dll name (%s); "
                               "not staging the original alongside the tap", real)
        else:
            copy_verified(cfg.original_dll, target)
        return run_dir

    def _env(self, run_dir: Path, *, trace_path: Path | None = None,
             passthrough: bool = False) -> dict[str, str]:
        # Do not hand an untrusted legacy executable the host's API keys,
        # cloud credentials, user profile or developer-tool configuration.
        # Windows needs only a small base to launch an absolute executable;
        # target-specific additions must be explicit in cfg.env.
        host = {key.casefold(): (key, value)
                for key, value in os.environ.items()}
        env: dict[str, str] = {}
        for wanted in (
                "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "OS",
                "SystemDrive", "PROCESSOR_ARCHITECTURE",
                "PROCESSOR_ARCHITEW6432", "NUMBER_OF_PROCESSORS"):
            item = host.get(wanted.casefold())
            if item is not None:
                env[wanted] = item[1]
        env.update(self.cfg.env)
        controls = {
            "TAP_TRACE", "TAP_LABEL", "TAP_PASSTHROUGH", "TAP_MAXCAP",
            "TAP_SUBJECT_SHA256",
            self.cfg.trace_env, self.cfg.passthrough_env,
        }
        if self.cfg.label_env:
            controls.add(self.cfg.label_env)
        folded = {key.casefold() for key in controls if key}
        # Windows environment names are case-insensitive.  Rebuild instead of
        # dict.pop so `tap_maxcap=0` cannot survive next to `TAP_MAXCAP`.
        env = {key: value for key, value in env.items()
               if key.casefold() not in folded
               and not key.casefold().startswith("tap_")}

        by_fold = {key.casefold(): value for key, value in env.items()}
        system_root = (by_fold.get("systemroot") or by_fold.get("windir")
                       or r"C:\Windows")
        system32 = str(Path(system_root) / "System32")
        env = {key: value for key, value in env.items()
               if key.casefold() not in {"path", "temp", "tmp"}}
        env["PATH"] = os.pathsep.join((str(run_dir), system32))
        private_temp = run_dir / "temp"
        private_temp.mkdir(exist_ok=False)
        env["TEMP"] = str(private_temp)
        env["TMP"] = str(private_temp)
        env["TAP_MAXCAP"] = str(self.cfg.max_capture_bytes)
        real_name = self.cfg.real_dll_name or (
            self.contract.real_module if self.contract else "")
        real_subject = run_dir / real_name if real_name else None
        subject = (real_subject if real_subject is not None
                   and real_subject.is_file()
                   else run_dir / self.cfg.target_dll_name)
        if not subject.is_file():
            raise _RunError(f"staged subject DLL is missing: {subject}")
        subject_kind, subject_sha256 = _sha256_artifact(subject)
        if subject_kind != "file":
            raise _RunError(f"staged subject DLL is not a file: {subject}")
        env["TAP_SUBJECT_SHA256"] = subject_sha256
        if passthrough:
            env[self.cfg.passthrough_env] = "1"
        if trace_path is not None:
            env[self.cfg.trace_env] = str(trace_path)
            if self.cfg.label_env:
                # One shared label for every recording run: it lands in the
                # trace header, and a per-run value would be one more thing
                # the determinism comparison has to be trusted to ignore.
                env[self.cfg.label_env] = "oracle-record"
        return env

    def _normalizers(self, run_dir: Path) -> list[tuple[Any, str]]:
        cfg = self.cfg
        # Run directories differ by construction; without erasing them the
        # passthrough comparison fails on nothing but its own scaffolding.
        forms = {str(run_dir), run_dir.as_posix(), str(run_dir).replace("\\", "\\\\")}
        rules: list[tuple[Any, str]] = [
            (re.compile(re.escape(f), re.IGNORECASE), "<RUNDIR>")
            for f in sorted(forms, key=len, reverse=True)]
        rules += [(re.compile(pat), repl) for pat, repl in cfg.normalizers]
        if cfg.common_normalizers:
            rules += list(runner.COMMON_NORMALIZERS)
        return rules

    def _run(self, run_dir: Path, env: dict[str, str]) -> RunResult:
        cfg = self.cfg
        cmd = [str(c).replace("{run_dir}", str(run_dir)) for c in cfg.scenario]
        staged_leaves = {Path(path).name.casefold() for path in cfg.app_files}
        executable = Path(cmd[0])
        if not executable.is_absolute():
            executable = run_dir / executable
        try:
            resolved_run = run_dir.resolve(strict=True)
            resolved_executable = executable.resolve(strict=True)
        except OSError as exc:
            raise _RunError(f"scenario executable cannot be resolved: "
                            f"{executable}: {exc}") from exc
        if (resolved_executable.parent != resolved_run
                or resolved_executable.name.casefold() not in staged_leaves
                or not resolved_executable.is_file()
                or _is_reparse_point(resolved_executable)):
            raise _RunError(
                "scenario executable is not the verified staged app_file: "
                f"{resolved_executable}")
        cmd[0] = str(resolved_executable)
        try:
            res = runner.run_scenario(
                cmd, run_dir, timeout=cfg.timeout_s, watch_dirs=cfg.watch_dirs,
                env=env, normalizers=self._normalizers(run_dir))
        except OSError as exc:
            raise _RunError(f"could not start {cmd[0]!r} in {run_dir}: {exc}") from exc
        logger.info("run %s: %s", run_dir.name, res.summary())
        return res

    # -- cached runs ------------------------------------------------------

    def notap(self) -> RunResult:
        if self._notap is None:
            run_dir = self._stage("notap", use_tap=False)
            self._notap = self._run(run_dir, self._env(run_dir))
        return self._notap

    def passthrough(self) -> RunResult:
        if self._passthrough is None:
            run_dir = self._stage("passthrough", use_tap=True)
            self._passthrough = self._run(
                run_dir, self._env(run_dir, passthrough=True))
        return self._passthrough

    def records(self, count: int) -> list[tuple[RunResult, Path]]:
        trace_dir = self.cfg.work_dir / "traces"
        work_root = self.cfg.work_dir.resolve()
        resolved_trace_dir = trace_dir.resolve()
        if (work_root == resolved_trace_dir
                or work_root not in resolved_trace_dir.parents):
            raise _RunError(f"trace directory escapes configured work_dir: "
                            f"{trace_dir} -> {resolved_trace_dir}")
        if _is_reparse_point(trace_dir):
            raise _RunError(f"trace directory is a reparse point: {trace_dir}")
        trace_dir.mkdir(parents=True, exist_ok=True)
        while len(self._records) < count:
            i = len(self._records)
            run_dir = self._stage(f"rec{i}", use_tap=True)
            # Traces live outside the run directory so that watch_dirs hashing
            # does not see them: a trace differs every run by design.
            trace_path = trace_dir / f"rec{i}.jsonl"
            if _is_reparse_point(trace_path):
                raise _RunError(f"trace path is a reparse point: {trace_path}")
            if trace_path.exists():
                trace_path.unlink()
            if trace_path.exists() or _is_reparse_point(trace_path):
                raise _RunError(f"stale trace survived removal: {trace_path}")
            res = self._run(
                run_dir, self._env(run_dir, trace_path=trace_path))
            self._records.append((res, trace_path))
        return self._records[:count]


# --------------------------------------------------------------------------
# check 1: structural


def _required_surface(cfg: OracleConfig, contract: Contract | None,
                      pe: Any | None) -> tuple[set[str], set[int], list[str]]:
    """Union of what the contract declares and what the consumers import."""
    names: set[str] = set(cfg.required_names)
    ords: set[int] = set(int(o) for o in cfg.required_ordinals)
    notes: list[str] = []
    if contract is not None:
        for name, sym in contract.symbols.items():
            if not sym.noname:
                names.add(name)
            if sym.ordinal is not None:
                ords.add(int(sym.ordinal))
    if cfg.consumers and pe is None:
        notes.append("consumer surface cannot be inspected: pe_surface is unavailable")
    elif cfg.consumers:
        original_surface: Any | None = None
        scanner = getattr(pe, "scan_dynamic_candidates", None)
        if callable(scanner):
            try:
                original_surface = pe.read_exports(cfg.original_dll)
            except Exception as exc:
                notes.append("dynamic export scan cannot read the original "
                             f"surface: {type(exc).__name__}: {exc}")
        for consumer in cfg.consumers:
            static_names: set[str] = set()
            static_ords: set[int] = set()
            dynamic_names: set[str] = set()
            try:
                n, o = pe.required_surface([str(consumer)],
                                           cfg.target_dll_name)
                static_names = set(n)
                static_ords = {int(x) for x in o}
            except Exception as exc:
                notes.append(f"consumer {consumer} could not be inspected: "
                             f"{type(exc).__name__}: {exc}")
                continue
            if callable(scanner) and original_surface is not None:
                try:
                    dynamic_names = set(scanner(str(consumer), original_surface))
                except Exception as exc:
                    notes.append(f"consumer {consumer} dynamic export scan "
                                 f"failed: {type(exc).__name__}: {exc}")
                    continue
            if not static_names and not static_ords and not dynamic_names:
                # In a permissive inventory this might merely be an optional
                # plugin.  In an approval oracle it is an unproved consumer:
                # accepting it would let a parser/target-name mistake shrink
                # the required surface to zero.
                notes.append(f"consumer {consumer} contains no static, delay, "
                             f"or literal dynamic reference to "
                             f"{cfg.target_dll_name}")
                continue
            names |= static_names | dynamic_names
            ords |= static_ords
    return names, ords, notes


def _compare_surface(pe: Any, tap: Path, original: Path,
                     names: set[str], ords: set[int],
                     contract: Contract | None) -> tuple[list[str], dict]:
    """Call pe_surface.compare_surface, tolerating either argument style.

    The spec leaves the first two parameters unannotated; they read as Surface
    objects but paths are just as plausible. Try the parsed form first and fall
    back, so a reasonable pe_surface implementation works either way.
    """
    data: dict[str, Any] = {}
    surfaces: tuple[Any, Any] | None = None
    contract_problems: list[str] = []
    try:
        tap_s = pe.read_exports(tap)
        orig_s = pe.read_exports(original)
        surfaces = (tap_s, orig_s)
        data["tap_exports"] = len(getattr(tap_s, "exports", {}) or {})
        data["original_exports"] = len(getattr(orig_s, "exports", {}) or {})
        data["tap_arch"] = getattr(tap_s, "arch", "")
        data["original_arch"] = getattr(orig_s, "arch", "")
        validator = getattr(pe, "compare_contract_surface", None)
        if contract is None:
            contract_problems.append(
                "active contract unavailable for original export coverage")
        elif not callable(validator):
            contract_problems.append(
                "exact contract/original export validator is unavailable")
        else:
            try:
                contract_problems.extend(validator(contract, orig_s))
            except Exception as exc:
                contract_problems.append(
                    "exact contract/original export validation failed: "
                    f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        data["read_exports_error"] = f"{type(exc).__name__}: {exc}"
        contract_problems.append(
            "could not parse tap/original exports for exact contract "
            f"coverage: {type(exc).__name__}: {exc}")
    data["contract_surface_problems"] = list(contract_problems)

    attempts = ([surfaces] if surfaces else []) + [(tap, original)]
    last: Exception | None = None
    for a, b in attempts:
        try:
            surface_problems = list(pe.compare_surface(a, b, names, ords))
            return contract_problems + surface_problems, data
        except (TypeError, AttributeError) as exc:
            last = exc
    raise last if last else RuntimeError("compare_surface unusable")


def _check_structural(cfg: OracleConfig, contract: Contract | None) -> CheckOutcome:
    pe, reason = _sibling("pe_surface")
    if pe is None:
        return CheckOutcome("structural", False, reason)
    names, ords, evidence_problems = _required_surface(cfg, contract, pe)
    problems, data = _compare_surface(pe, cfg.tap_dll, cfg.original_dll,
                                      names, ords, contract)
    problems = list(evidence_problems) + problems
    data.update({"required_names": sorted(names),
                 "required_ordinals": sorted(ords),
                 "problems": problems})
    detail_lines = problems
    if problems:
        head = (f"{len(problems)} surface problem(s) against "
                f"{len(names)} required name(s) / {len(ords)} ordinal(s)")
        return CheckOutcome("structural", False,
                            "\n".join([head] + detail_lines), data)
    head = (f"tap surface covers {len(names)} required name(s) and "
            f"{len(ords)} ordinal(s)")
    return CheckOutcome("structural", True, head, data)


# --------------------------------------------------------------------------
# check 2: passthrough


def _check_passthrough(cfg: OracleConfig, ctx: _Ctx) -> CheckOutcome:
    base = ctx.notap()
    tapped = ctx.passthrough()
    recorded, trace_path = ctx.records(1)[0]

    problems = _run_health_problems("no-tap baseline", base)
    problems += _run_health_problems("passthrough tap", tapped)
    problems += _run_health_problems("recording tap", recorded)
    for mode, result in (("passthrough", tapped), ("recording", recorded)):
        problems.extend(
            f"{mode}: {problem}" for problem in runner.compare_runs(
                base, result, ignore_stderr=cfg.ignore_stderr))
    if not trace_path.is_file():
        problems.append(f"recording run produced no trace at {trace_path}")

    # Identical crashed or inert runs prove nothing.  Exit health is always
    # mandatory; targets that are intentionally silent must explicitly opt
    # out of the second condition after providing another coverage oracle.
    if (cfg.require_observable_baseline and not base.stdout.strip()
            and (cfg.ignore_stderr or not base.stderr.strip())
            and not base.output_files):
        problems.append("baseline produced no stdout, stderr, or watched file "
                        "change; an inert comparison cannot prove tap transparency")

    data = {"notap": base.summary(), "passthrough": tapped.summary(),
            "recording": recorded.summary(), "trace": str(trace_path),
            "run_evidence": {
                "notap": _run_evidence(base),
                "passthrough": _run_evidence(tapped),
                "recording": _run_evidence(recorded)},
            "problems": problems}
    if problems:
        head = (f"{len(problems)} run-health or observable difference(s); "
                "both muted and recording-enabled taps must be transparent")
        return CheckOutcome("passthrough", False,
                            "\n".join([head] + problems), data)
    head = (f"muted and recording-enabled taps match the successful no-tap "
            f"baseline, including {len(base.output_files)} output file hash(es)")
    return CheckOutcome("passthrough", True, head, data)


# --------------------------------------------------------------------------
# check 3: determinism


_DETERMINISM_LESSON = (
    "A non-empty A-vs-A diff is NOT a DLL bug: the same DLL ran twice. It "
    "means the normalizer still lets nondeterministic bytes through, and every "
    "later shim diff will be noise stacked on this hole. Refine the contract "
    "or scenario so the value has an explicit, reviewable invariant; arbitrary "
    "masks and --write-policy are forbidden in approval mode.")


def _load_policy(cfg: OracleConfig, policy_mod: Any,
                 contract: Contract) -> Any:
    if cfg.policy and Path(cfg.policy).is_file():
        loaded = policy_mod.Policy.load(cfg.policy)
    else:
        if cfg.policy:
            logger.info("policy %s missing; deriving from the contract", cfg.policy)
        loaded = policy_mod.Policy.derive(contract)
    assert_safe = getattr(loaded, "assert_safe", None)
    if callable(assert_safe):
        # Policy masks can suppress the only evidence of a mismatch.  Newer
        # policy implementations expose a fail-closed validator; never bypass
        # it merely because this module also supports older implementations.
        assert_safe(contract=contract)
    return loaded


def _trace_identity_problems(tr: Any, contract: Contract,
                             *, label: str,
                             max_capture_bytes: int,
                             expected_pid: int | None,
                             expected_subject_sha256: str) -> list[str]:
    problems: list[str] = []
    header = getattr(tr, "header", {}) or {}
    if not header:
        return [f"{label}: trace header is missing"]
    if header.get("v") != getattr(trace_mod, "TRACE_VERSION", 1):
        problems.append(f"{label}: trace version {header.get('v')!r} is not "
                        "supported")
    if str(header.get("module", "")).casefold() != contract.module.casefold():
        problems.append(f"{label}: module {header.get('module')!r} does not "
                        f"match {contract.module!r}")
    if str(header.get("arch", "")).casefold() != contract.arch.casefold():
        problems.append(f"{label}: arch {header.get('arch')!r} does not match "
                        f"{contract.arch!r}")
    expected_contract = contract.fingerprint()
    if header.get("contract") != expected_contract:
        problems.append(f"{label}: contract fingerprint "
                        f"{header.get('contract')!r} does not match active "
                        f"contract {expected_contract!r}")
    if header.get("subject") != expected_subject_sha256:
        problems.append(f"{label}: subject fingerprint "
                        f"{header.get('subject')!r} does not match staged "
                        f"original DLL {expected_subject_sha256!r}")
    for key in ("run", "tap"):
        if not isinstance(header.get(key), str) or not header.get(key):
            problems.append(f"{label}: header {key!r} is missing or empty")
    if type(expected_pid) is not int or expected_pid <= 0:
        problems.append(f"{label}: runner did not record a valid launched PID")
    elif type(header.get("pid")) is not int or header["pid"] != expected_pid:
        problems.append(f"{label}: trace pid {header.get('pid')!r} does not "
                        f"match launched pid {expected_pid}")
    if header.get("label") != "oracle-record":
        problems.append(f"{label}: header label {header.get('label')!r} is not "
                        "the oracle recording label")
    if type(header.get("maxcap")) is not int:
        problems.append(f"{label}: header maxcap is missing or not an integer")
    elif header["maxcap"] != max_capture_bytes:
        problems.append(f"{label}: recorder maxcap {header['maxcap']} does not "
                        f"match configured {max_capture_bytes}")
    seqs = [getattr(rec, "seq", None) for rec in getattr(tr, "records", [])]
    if len(seqs) != len(set(seqs)):
        problems.append(f"{label}: duplicate trace sequence numbers")
    lossy_markers = (
        "truncated", "unknown-extent", "faulted", "not terminated",
        "past tr_max_depth", "clamped", "dropped",
    )
    for note in getattr(tr, "notes", []):
        message = str(getattr(note, "msg", ""))
        if any(marker in message.casefold() for marker in lossy_markers):
            problems.append(f"{label}: recorder reported incomplete evidence: "
                            f"{message}")
    return problems


def _trace_contract_validation_problems(tr: Any, contract: Contract,
                                        *, label: str) -> list[str]:
    validator = getattr(trace_mod, "validate_trace_contract", None)
    if not callable(validator):
        return [f"{label}: trace/contract conformance validator is unavailable"]
    try:
        found = validator(tr, contract)
    except Exception as exc:
        return [f"{label}: trace/contract validation raised "
                f"{type(exc).__name__}: {exc}"]
    if type(found) is not list:
        return [f"{label}: trace/contract validator returned "
                f"{type(found).__name__}, expected list[str]"]
    if any(not isinstance(problem, str) or not problem for problem in found):
        return [f"{label}: trace/contract validator returned malformed problems"]
    return [f"{label}: {problem}" for problem in found]


def _read_bound_trace(path: Path) -> tuple[Any, str]:
    """Read a trace only if its bytes stay stable across the parse."""
    kind, before = _sha256_artifact(path)
    if kind != "file":
        raise OSError(f"trace is not a regular file: {path}")
    trace = trace_mod.read_trace(path)
    _kind, after = _sha256_artifact(path)
    if before != after:
        raise OSError(f"trace changed while it was being parsed: {path}")
    return trace, before


def _check_determinism(cfg: OracleConfig, ctx: _Ctx, contract: Contract,
                       *, name: str = "determinism") -> CheckOutcome:
    mods, missing = _need("policy", "normalize", "tracediff")
    if missing:
        return CheckOutcome(name, False, missing)
    runs = ctx.records(max(2, cfg.determinism_runs))
    unhealthy: list[str] = []
    for i, (res, _path) in enumerate(runs):
        unhealthy += _run_health_problems(f"recording run {i}", res)
    if unhealthy:
        return CheckOutcome(
            name, False,
            "recording run failure makes A-vs-A evidence invalid\n"
            + "\n".join(unhealthy),
            {"runs": [res.summary() for res, _ in runs],
             "problems": unhealthy})
    for res, path in runs:
        if not path.is_file():
            return CheckOutcome(
                name, False,
                f"no trace at {path} (run exited {res.exit_code}).\n"
                f"The tap is told where to write via ${cfg.trace_env}; if the "
                f"generated runtime reads a different variable, set "
                f"\"trace_env\" in the oracle config.",
                {"exit_code": res.exit_code})

    policy = _load_policy(cfg, mods["policy"], contract)
    bound = [_read_bound_trace(p) for _, p in runs]
    traces = [tr for tr, _digest in bound]
    trace_digests = [digest for _tr, digest in bound]
    trace_problems: list[str] = []
    _subject_kind, expected_subject = _sha256_artifact(cfg.original_dll)
    for i, (tr, (run_result, _path)) in enumerate(zip(traces, runs)):
        trace_problems += _trace_identity_problems(
            tr, contract, label=f"recording run {i}",
            max_capture_bytes=cfg.max_capture_bytes,
            expected_pid=getattr(run_result, "pid", None),
            expected_subject_sha256=expected_subject)
        trace_problems += _trace_contract_validation_problems(
            tr, contract, label=f"recording run {i}")
    run_ids = [tr.header.get("run") for tr in traces if tr.header]
    if len(run_ids) != len(set(run_ids)):
        trace_problems.append("recording traces reuse a run id; fresh, "
                              "independent executions were not proved")
    tap_versions = {tr.header.get("tap") for tr in traces if tr.header}
    if len(tap_versions) != 1:
        trace_problems.append("recording traces were produced by different "
                              f"tap versions: {sorted(map(str, tap_versions))}")
    if trace_problems:
        return CheckOutcome(
            name, False,
            "trace identity/integrity checks failed\n"
            + "\n".join(trace_problems),
            {"traces": [str(p) for _, p in runs],
             "problems": trace_problems})
    norms = [mods["normalize"].normalize(t, contract, policy) for t in traces]

    # Run 0 is the reference and every later run is compared against it: some
    # nondeterminism only shows up on the third or fourth repetition, and a
    # single pair would call that clean.
    total = 0
    compared = 0
    first = None
    suggestions: list = []
    seen: set = set()
    for i in range(1, len(norms)):
        # stop_after=0: the determinism pass needs EVERY nondeterministic field
        # in one go, otherwise mask proposals arrive one per run forever.
        result = mods["tracediff"].diff(norms[0], norms[i], policy, stop_after=0)
        compared = max(compared, int(getattr(result, "compared_calls", 0)))
        total += int(getattr(result, "total", 0))
        if getattr(result, "ok", False) and not getattr(result, "total", 0):
            continue
        if first is None:
            first = getattr(result, "first", None)
        try:
            rules = list(mods["tracediff"].suggest_masks(result, contract))
        except Exception as exc:
            logger.warning("suggest_masks failed: %s", exc)
            rules = list(getattr(result, "suggestions", []) or [])
        for rule in rules:
            key = (getattr(rule, "sym", ""), getattr(rule, "path", ""),
                   tuple(tuple(r) for r in (getattr(rule, "byte_ranges", None) or [])))
            if key in seen:
                continue
            seen.add(key)
            # Everything derived from an A-vs-A run is by definition automatic.
            try:
                rule.auto = True
            except Exception:                   # pragma: no cover - defensive
                pass
            suggestions.append(rule)

    data = {"runs": len(runs), "calls": [len(t.calls) for t in traces],
            "traces": [str(p) for _, p in runs],
            "trace_sha256": trace_digests,
            "divergences": total, "compared_calls": compared}
    if total == 0 and compared == 0:
        # An empty diff over an empty comparison is not evidence. Two traces
        # that recorded nothing agree perfectly, and so do two traces whose
        # every symbol the policy ignores -- neither says anything about the
        # normalizer, which is the only thing this check exists to prove.
        recorded = sum(len(t.calls) for t in traces)
        why = ("the traces hold no call records at all"
               if recorded == 0 else
               f"{recorded} call(s) were recorded but none were comparable "
               f"(policy.ignore_symbols?)")
        return CheckOutcome(
            name, False,
            f"A-vs-A compared 0 calls across {len(runs)} runs: {why}. "
            f"A clean diff over nothing does not prove the normalizer is "
            f"complete, so this check cannot pass.", data)
    if total == 0:
        return CheckOutcome(
            name, True,
            f"{compared} call(s) compared A-vs-A across {len(runs)} runs, zero "
            f"residual divergence", data)

    lines = [f"{total} residual divergence(s) after normalization over "
             f"{compared} compared call(s) in {len(runs)} runs",
             _DETERMINISM_LESSON]
    if first is not None:
        lines.append(f"first: {getattr(first, 'kind', '?')} "
                     f"{getattr(first, 'sym', '?')}.{getattr(first, 'path', '?')} "
                     f"a={getattr(first, 'a', None)!r} b={getattr(first, 'b', None)!r}")
    return CheckOutcome(name, False, "\n".join(lines), data, suggestions)


# --------------------------------------------------------------------------
# check 4: coverage


def _is_null(val: Any) -> bool:
    """Val.is_null parses the pointer as hex and throws on a torn trace line.

    getattr(..., default) does not swallow that, only AttributeError, so the
    guard has to be explicit.
    """
    try:
        return bool(val.is_null)
    except (ValueError, TypeError, AttributeError):
        return False


def _val_class(val: Any, arg: Any | None = None,
               contract: Contract | None = None) -> tuple[Any, ...]:
    """Stable, value-sensitive class for one input argument.

    The previous classifier collapsed every non-null pointer to ``"ptr"``
    and every large positive integer to ``"pos"``.  That let an unrelated
    flag produce two whole-call classes while the important buffer was
    identical in every call.  Approval coverage now varies *each* input
    independently and retains exact scalar/string/captured-byte values.

    Raw embedded addresses are removed from a declared struct before hashing:
    address ASLR is not semantic input diversity, while the surrounding
    length/flag/data bytes are.
    """
    kind = getattr(val, "k", "blob")
    if kind == "handle":
        return ("handle", getattr(val, "v", None))
    if kind == "fnptr":
        return ("fnptr", "null" if getattr(val, "v", None) in (None, 0)
                else "nonnull")
    if kind in POINTER_KINDS or val.p is not None:
        if _is_null(val):
            return (kind, "null")
        if kind in ("str", "wstr"):
            return (kind, "value", getattr(val, "v", None))
        payload = getattr(val, "b", None)
        if not isinstance(payload, str):
            return (kind, "uncaptured")
        try:
            raw = bytearray.fromhex(payload)
        except ValueError:
            return (kind, "malformed")
        struct_name = getattr(arg, "struct", None) if arg is not None else None
        struct = (contract.structs.get(struct_name)
                  if contract is not None and struct_name else None)
        if struct is not None:
            for offset, size in struct.pointer_ranges():
                end = min(len(raw), offset + size)
                if 0 <= offset < end:
                    raw[offset:end] = b"\x00" * (end - offset)
        digest = hashlib.sha256(raw).hexdigest()
        return (kind, "bytes", len(raw), digest)
    v = val.v
    return (kind, "value", type(v).__name__, v)


def _arg_class(rec: Any, spec: Any | None = None,
               contract: Contract | None = None) -> tuple:
    args = {arg.name: arg for arg in getattr(spec, "args", ())}
    return tuple((name, _val_class(rec.inn[name], args.get(name), contract))
                 for name in sorted(rec.inn))


def _input_class_evidence(
        records: Sequence[Any], contract: Contract
) -> tuple[dict[str, set[tuple]], dict[str, dict[str, set[tuple[Any, ...]]]]]:
    """Return whole-call and per-input classes for contract records."""
    whole: dict[str, set[tuple]] = {}
    per_arg: dict[str, dict[str, set[tuple[Any, ...]]]] = {}
    for rec in records:
        spec = (contract.symbols.get(rec.sym)
                if getattr(rec, "t", "") == getattr(trace_mod, "REC_CALL", "c")
                else contract.callbacks.get(rec.sym))
        if spec is None:
            continue
        whole.setdefault(rec.sym, set()).add(_arg_class(rec, spec, contract))
        by_name = per_arg.setdefault(rec.sym, {})
        for arg in getattr(spec, "args", ()):
            if not getattr(arg, "is_in", False) or arg.name not in rec.inn:
                continue
            by_name.setdefault(arg.name, set()).add(
                _val_class(rec.inn[arg.name], arg, contract))
    return whole, per_arg


def trace_approval_coverage_problems(
        trace: Any, contract: Contract, *,
        min_calls: int = CREDIT_TARGET_CALLS,
        min_classes: int = CREDIT_TARGET_CLASSES) -> list[str]:
    """Reject a standalone trace that cannot support an approval diff.

    L0 coverage cannot be assumed for arbitrary L2 input files.  Both A and B
    traces must themselves exercise every declared function/callback, contain
    enough calls, vary every input independently, and satisfy the complete
    wire/contract schema.  Otherwise two equally incomplete traces could
    compare clean and incorrectly return exit 0.
    """
    problems: list[str] = []
    if type(min_calls) is not int or min_calls < CREDIT_TARGET_CALLS:
        return [f"approval min_calls must be >= {CREDIT_TARGET_CALLS}"]
    if type(min_classes) is not int or min_classes < CREDIT_TARGET_CLASSES:
        return [f"approval min_classes must be >= {CREDIT_TARGET_CLASSES}"]
    try:
        problems.extend(trace_mod.validate_trace_contract(trace, contract))
    except Exception as exc:
        return [f"trace/contract validation raised {type(exc).__name__}: {exc}"]
    records = list(getattr(trace, "calls", ()) or ())
    counts = trace.symbol_counts() if hasattr(trace, "symbol_counts") else {}
    whole, per_arg = _input_class_evidence(records, contract)
    universe: dict[str, Any] = dict(contract.symbols)
    universe.update(contract.callbacks)
    if not universe:
        problems.append("contract coverage universe is empty")
    for sym, spec in sorted(universe.items()):
        observed_calls = int(counts.get(sym, 0))
        if observed_calls < min_calls:
            problems.append(
                f"{sym}: {observed_calls} call(s), approval requires "
                f"at least {min_calls}")
        input_args = [arg for arg in getattr(spec, "args", ())
                      if getattr(arg, "is_in", False)]
        required = min_classes if input_args else 1
        whole_count = len(whole.get(sym, ()))
        if whole_count < required:
            problems.append(
                f"{sym}: {whole_count} whole-input class(es), approval "
                f"requires {required}")
        for arg in input_args:
            observed = len(per_arg.get(sym, {}).get(arg.name, ()))
            if observed < min_classes:
                problems.append(
                    f"{sym}.{arg.name}: {observed} distinct input value "
                    f"class(es), approval requires {min_classes}")
    return list(dict.fromkeys(problems))


def _credit(calls: int, classes: int, fully_specified: bool,
            *, target_calls: int = CREDIT_TARGET_CALLS,
            target_classes: int = CREDIT_TARGET_CLASSES) -> float:
    if calls == 0:
        return 0.0
    call_credit = min(1.0, calls / target_calls)
    class_credit = min(1.0, classes / target_classes)
    spec_credit = 1.0 if fully_specified else 0.5
    return round(CREDIT_W_CALLS * call_credit
                 + CREDIT_W_CLASSES * class_credit
                 + CREDIT_W_SPEC * spec_credit, 3)


def _capture_extent_pairs(tr: Any) -> tuple[
        list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Return ``(unknown, partial, malformed)`` pointer/string captures.

    ``Val.captured`` only says that ``b`` exists.  It does not prove the
    recorder copied all ``n`` bytes: the runtime deliberately caps large
    captures and a guarded read may stop at a readable prefix.  Treating that
    prefix as complete is a false-PASS path, so compare the declared byte
    count with the actual hex payload and keep malformed metadata separate.
    """
    unknown: set[tuple[str, str]] = set()
    partial: set[tuple[str, str]] = set()
    malformed: set[tuple[str, str]] = set()
    for rec in tr.records:
        if not rec.is_call:
            continue
        for section, values in (("in", rec.inn), ("out", rec.out)):
            for name, val in values.items():
                if val.p is None or _is_null(val):
                    continue
                if val.k in ("handle", "fnptr"):
                    continue
                pair = (rec.sym, f"{section}.{name}")
                if (not isinstance(val.p, str)
                        or re.fullmatch(r"[0-9a-f]+", val.p) is None):
                    malformed.add(pair)
                    continue
                try:
                    int(val.p, 16)
                except (TypeError, ValueError):
                    malformed.add(pair)
                    continue
                if val.k in ("str", "wstr"):
                    if val.v is None:
                        unknown.add(pair)
                    elif not isinstance(val.v, str):
                        malformed.add(pair)
                    continue
                if val.b is None:
                    unknown.add(pair)
                    continue
                if (type(val.n) is not int or val.n < 0
                        or not isinstance(val.b, str)
                        or len(val.b) % 2
                        or re.fullmatch(r"[0-9a-f]*", val.b) is None):
                    malformed.add(pair)
                    continue
                if len(val.b) // 2 != val.n:
                    partial.add(pair)
    return sorted(unknown), sorted(partial), sorted(malformed)


def _unknown_extent_pairs(tr: Any) -> list[tuple[str, str]]:
    """Backward-compatible argument-level unknown-extent measurement."""
    unknown, _partial, _malformed = _capture_extent_pairs(tr)
    return unknown


def _field_extent_pairs(tr: Any, contract: Contract,
                        cfg: OracleConfig) -> list[tuple[str, str]]:
    """Embedded pointer fields that fell outside a truncated capture.

    Only the normalizer can see these: locating a field inside captured bytes
    needs the contract's struct layout, which the raw-trace pass above does
    not apply.  A missing normalizer is an error: an unavailable measurement
    must never be reported as a clean one.
    """
    mods, missing = _need("policy", "normalize")
    if missing:
        raise RuntimeError("field-level extent completeness could not be "
                           f"measured: {missing}")
    try:
        policy = _load_policy(cfg, mods["policy"], contract)
        nt = mods["normalize"].normalize(tr, contract, policy)
    except Exception as exc:
        raise RuntimeError("normalization failed while measuring field-level "
                           f"extent completeness: {type(exc).__name__}: "
                           f"{exc}") from exc
    return sorted({(s, p) for s, p in nt.unknown_extent if p.count(".") >= 2})


def _fully_specified(spec: Any | None) -> bool:
    if spec is None:
        return False
    marker = getattr(spec, "fully_specified", None)
    if marker is not None:
        return bool(marker)
    # CallbackSpec intentionally has no convenience property, but callback
    # arguments cross the same trust boundary and need the same extent proof.
    for arg in getattr(spec, "args", []):
        if (getattr(arg, "kind", "") in (POINTER_KINDS | {"blob"})
                and getattr(arg, "kind", "") not in ("handle", "fnptr")
                and not getattr(arg, "records_bytes", False)):
            return False
    return True


def _check_coverage(cfg: OracleConfig, ctx: _Ctx,
                    contract: Contract) -> CheckOutcome:
    runs = ctx.records(1)
    res, trace_path = runs[0]
    run_problems = _run_health_problems("recording coverage run", res)
    if run_problems:
        return CheckOutcome(
            "coverage", False,
            "recording run is not valid coverage evidence\n"
            + "\n".join(run_problems),
            {"run": res.summary(), "problems": run_problems})
    if not trace_path.is_file():
        return CheckOutcome(
            "coverage", False,
            f"no trace at {trace_path} (run exited {res.exit_code}); "
            f"check ${cfg.trace_env}", {"exit_code": res.exit_code})
    tr, trace_digest = _read_bound_trace(trace_path)
    trace_problems = _trace_identity_problems(
        tr, contract, label="recording coverage run",
        max_capture_bytes=cfg.max_capture_bytes,
        expected_pid=getattr(res, "pid", None),
        expected_subject_sha256=_sha256_artifact(cfg.original_dll)[1])
    trace_problems += _trace_contract_validation_problems(
        tr, contract, label="recording coverage run")
    if trace_problems:
        return CheckOutcome(
            "coverage", False,
            "trace identity/integrity/conformance checks failed\n"
            + "\n".join(trace_problems),
            {"trace": str(trace_path), "problems": trace_problems})

    calls = tr.calls
    if not calls:
        return CheckOutcome(
            "coverage", False,
            f"trace {trace_path} holds no call records -- the scenario never "
            f"crossed the boundary, so nothing downstream is verifying anything",
            {"trace": str(trace_path), "notes": [n.msg for n in tr.notes[:10]]})

    pe, _ = _sibling("pe_surface")
    names, _ords, surface_problems = _required_surface(cfg, contract, pe)
    forwarded = {n for n, s in contract.symbols.items() if s.forward}
    universe = ((names | set(contract.symbols)) - forwarded) \
        | set(contract.callbacks)
    if not universe:
        return CheckOutcome(
            "coverage", False,
            "required coverage universe is empty; a ratio over zero symbols "
            "is not evidence", {"trace": str(trace_path)})

    counts = tr.symbol_counts()
    classes, per_arg_classes = _input_class_evidence(calls, contract)

    arg_holes, partial_holes, malformed_holes = _capture_extent_pairs(tr)
    field_holes = _field_extent_pairs(tr, contract, cfg)
    unknown = sorted(set(arg_holes) | set(field_holes))
    incomplete = sorted(set(unknown) | set(partial_holes)
                        | set(malformed_holes))
    # A symbol whose bytes went uncaptured AT RUNTIME earned no more credit
    # than one whose extent was never declared, so both dampen the same term.
    # Without this a truncated capture reads as full verification.
    holed = {s for s, _ in incomplete}

    per_symbol: dict[str, dict[str, Any]] = {}
    for sym in sorted(universe):
        spec = contract.symbols.get(sym) or contract.callbacks.get(sym)
        n = counts.get(sym, 0)
        k = len(classes.get(sym, ()))
        declared = _fully_specified(spec)
        captured = sym not in holed
        observed = declared and captured
        calls_ok = n >= cfg.min_calls_per_symbol
        input_names = sorted(
            arg.name for arg in getattr(spec, "args", ())
            if getattr(arg, "is_in", False)) if spec is not None else []
        has_input = bool(input_names)
        required_classes = cfg.min_classes_per_symbol if has_input else 1
        arg_counts = {
            name: len(per_arg_classes.get(sym, {}).get(name, ()))
            for name in input_names}
        deficient_args = sorted(
            name for name, count in arg_counts.items()
            if count < required_classes)
        # Whole-call diversity is retained as a sanity check, but it is not
        # enough by itself: every input independently has to vary.  This
        # prevents a harmless flags argument from granting coverage to a
        # never-varied buffer or handle.
        classes_ok = k >= required_classes and not deficient_args
        bytes_ok = observed if cfg.require_bytes_complete else True
        effective = bool(spec is not None and calls_ok and classes_ok and bytes_ok)
        per_symbol[sym] = {
            "calls": n, "arg_classes": k,
            "per_input_classes": arg_counts,
            "insufficient_input_args": deficient_args,
            "fully_specified": declared,
            "capture_complete": captured,
            "bytes_complete": observed,
            "in_contract": spec is not None,
            "calls_ok": calls_ok, "classes_ok": classes_ok,
            "required_arg_classes": required_classes,
            "effective_complete": effective,
            "score": _credit(
                n, k, observed,
                target_calls=cfg.min_calls_per_symbol,
                target_classes=required_classes),
        }
    unexercised = sorted(s for s, v in per_symbol.items() if v["calls"] == 0)
    exercised = len(universe) - len(unexercised)
    call_ratio = exercised / len(universe)
    effective_symbols = sum(
        1 for value in per_symbol.values() if value["effective_complete"])
    ratio = effective_symbols / len(universe)
    mean = (round(sum(v["score"] for v in per_symbol.values()) / len(per_symbol), 3)
            if per_symbol else 0.0)
    insufficient_calls = sorted(
        s for s, value in per_symbol.items() if not value["calls_ok"])
    insufficient_classes = sorted(
        s for s, value in per_symbol.items() if not value["classes_ok"])
    insufficient_input_args = {
        s: list(value["insufficient_input_args"])
        for s, value in per_symbol.items()
        if value["insufficient_input_args"]}
    incomplete_symbols = sorted(
        s for s, value in per_symbol.items() if not value["bytes_complete"])
    unexpected_symbols = sorted((set(counts) - universe) - forwarded)

    data = {"trace": str(trace_path), "trace_sha256": trace_digest,
            "records": len(calls),
            "universe": len(universe), "exercised": exercised,
            "call_ratio": round(call_ratio, 3),
            "effective_symbols": effective_symbols,
            "ratio": round(ratio, 3), "effective_ratio": round(ratio, 3),
            "mean_score": mean,
            "unexercised": unexercised,
            "insufficient_calls": insufficient_calls,
            "insufficient_classes": insufficient_classes,
            "insufficient_input_args": insufficient_input_args,
            "incomplete_symbols": incomplete_symbols,
            "unknown_extent": [list(p) for p in unknown],
            "unknown_extent_args": [list(p) for p in arg_holes],
            "unknown_extent_fields": [list(p) for p in field_holes],
            "partial_extent": [list(p) for p in partial_holes],
            "malformed_extent": [list(p) for p in malformed_holes],
            "unexpected_symbols": unexpected_symbols,
            "forwarded_excluded": sorted(forwarded),
            "per_symbol": per_symbol}

    lines = [f"{len(calls)} call(s), {exercised}/{len(universe)} symbol(s) "
             f"touched, {effective_symbols}/{len(universe)} effectively "
             f"complete (mean credit {mean:.2f})"]
    lines += surface_problems + trace_problems
    if unexercised:
        lines.append("never exercised: " + ", ".join(unexercised[:20])
                     + (" ..." if len(unexercised) > 20 else ""))
    if unknown:
        kinds = []
        if arg_holes:
            kinds.append(f"{len(arg_holes)} arg(s)")
        if field_holes:
            kinds.append(f"{len(field_holes)} truncated field(s)")
        lines.append(f"uncaptured bytes earn no credit ({', '.join(kinds)}): "
                     + ", ".join(f"{s}.{p}" for s, p in unknown[:10])
                     + (" ..." if len(unknown) > 10 else ""))
    if partial_holes:
        lines.append("partial captures: "
                     + ", ".join(f"{s}.{p}" for s, p in partial_holes[:10])
                     + (" ..." if len(partial_holes) > 10 else ""))
    if malformed_holes:
        lines.append("malformed capture metadata: "
                     + ", ".join(f"{s}.{p}" for s, p in malformed_holes[:10])
                     + (" ..." if len(malformed_holes) > 10 else ""))
    if insufficient_calls:
        lines.append(f"fewer than {cfg.min_calls_per_symbol} call(s): "
                     + ", ".join(insufficient_calls[:20]))
    if insufficient_classes:
        items: list[str] = []
        for sym in insufficient_classes[:20]:
            value = per_symbol[sym]
            detail = ",".join(
                f"{name}={value['per_input_classes'].get(name, 0)}"
                for name in value["insufficient_input_args"])
            items.append(
                f"{sym}(whole={value['arg_classes']}/"
                f"{value['required_arg_classes']}"
                + (f", inputs:{detail}" if detail else "") + ")")
        lines.append("insufficient per-input argument classes: "
                     + ", ".join(items))
    if incomplete_symbols and cfg.require_bytes_complete:
        lines.append("contract/capture bytes incomplete: "
                     + ", ".join(incomplete_symbols[:20]))
    if unexpected_symbols:
        lines.append("trace contains symbols outside the contract/required "
                     "surface: " + ", ".join(unexpected_symbols[:20]))

    failures: list[str] = list(surface_problems) + trace_problems
    if unexpected_symbols:
        failures.append("unexpected trace symbols")
    if ratio < cfg.min_coverage:
        failures.append(
            f"effective coverage {ratio:.2f} < required {cfg.min_coverage:.2f}")
        lines.append(failures[-1])
    if mean < cfg.min_mean_credit:
        failures.append(
            f"mean credit {mean:.2f} < required {cfg.min_mean_credit:.2f}")
        lines.append(failures[-1])
    if cfg.require_bytes_complete and incomplete:
        failures.append("unknown, partial, or malformed extents remain")
    ok = not failures
    return CheckOutcome("coverage", ok, "\n".join(lines), data)


# --------------------------------------------------------------------------
# check 5: noninterference


def _check_noninterference(cfg: OracleConfig, ctx: _Ctx) -> CheckOutcome:
    base = ctx.notap()
    # The recording tap is the configuration that will actually be used.  A
    # passthrough fallback would measure a cheaper, different system and could
    # turn a broken recorder into a PASS.
    tapped, _ = ctx.records(1)[0]
    mode = "recording"

    problems = _run_health_problems("no-tap baseline", base)
    problems += _run_health_problems("recording tap", tapped)
    notes: list[str] = []
    for label, result in (("no-tap baseline", base),
                          ("recording tap", tapped)):
        samples = getattr(result, "resource_samples", None)
        if type(samples) is not int or samples < 2:
            problems.append(f"{label} has {samples!r} resource sample(s); "
                            "at least 2 are required for trustworthy peaks")
    forward_ratio = ((tapped.duration_s / base.duration_s)
                     if base.duration_s > 0 else float("inf"))
    reverse_ratio = ((base.duration_s / tapped.duration_s)
                     if tapped.duration_s > 0 else float("inf"))
    # A recorder making the run implausibly *faster* is also interference: it
    # can mean work was skipped.  Use a symmetric ratio instead of accepting
    # every negative overhead.
    ratio = max(forward_ratio, reverse_ratio)
    if not math.isfinite(ratio):
        problems.append("wall time ratio is not finite")
    if base.duration_s < cfg.min_measurable_s:
        message = (f"baseline {base.duration_s:.3f}s is below "
                   f"{cfg.min_measurable_s:.3f}s; overhead is not reliably "
                   "measurable")
        (problems if cfg.require_measurable_time else notes).append(message)
    if ratio > cfg.time_ratio_max:
        problems.append(f"wall time ratio {ratio:.2f} > {cfg.time_ratio_max:.2f} "
                        f"({base.duration_s:.3f}s -> {tapped.duration_s:.3f}s)")

    handle_delta: int | None = None
    if base.peak_handles is None or tapped.peak_handles is None:
        message = "handle counts unavailable"
        (problems if cfg.require_resource_metrics else notes).append(message)
    else:
        handle_delta = tapped.peak_handles - base.peak_handles
        if abs(handle_delta) > cfg.handle_delta_max:
            problems.append(f"absolute peak handle delta "
                            f"{abs(handle_delta)} > {cfg.handle_delta_max} "
                            f"(signed {handle_delta:+d})")

    byte_delta: int | None = None
    if base.peak_bytes is None or tapped.peak_bytes is None:
        message = "memory counters unavailable"
        (problems if cfg.require_resource_metrics else notes).append(message)
    else:
        byte_delta = tapped.peak_bytes - base.peak_bytes
        if abs(byte_delta) > cfg.bytes_delta_max:
            problems.append(f"absolute peak working set delta "
                            f"{abs(byte_delta)} bytes > {cfg.bytes_delta_max} "
                            f"(signed {byte_delta:+d})")

    data = {"mode": mode, "time_ratio": round(ratio, 3),
            "forward_time_ratio": round(forward_ratio, 3),
            "reverse_time_ratio": round(reverse_ratio, 3),
            "base": base.summary(), "tapped": tapped.summary(),
            "run_evidence": {
                "base": _run_evidence(base),
                "tapped": _run_evidence(tapped)},
            "resource_samples": {
                "base": getattr(base, "resource_samples", None),
                "tapped": getattr(tapped, "resource_samples", None)},
            "handle_delta": handle_delta, "byte_delta": byte_delta,
            "problems": problems, "notes": notes}
    head = (f"{mode} tap: time x{ratio:.2f}, handles "
            f"{f'{handle_delta:+d}' if handle_delta is not None else 'n/a'}, "
            f"peak bytes "
            f"{f'{byte_delta:+d}' if byte_delta is not None else 'n/a'}")
    return CheckOutcome("noninterference", not problems,
                        "\n".join([head] + problems + notes), data)


# --------------------------------------------------------------------------
# driver


def _sha256_artifact(path: Path) -> tuple[str, str]:
    """Return ``(kind, sha256)`` for a file or deterministic directory tree."""
    h = hashlib.sha256()
    if _is_reparse_point(path):
        raise OSError(f"reparse-point artifacts are not stable evidence: {path}")

    def absorb_file(file_path: Path, rel: str) -> None:
        encoded = rel.encode("utf-8", "surrogatepass")
        h.update(b"F")
        h.update(len(encoded).to_bytes(8, "little"))
        h.update(encoded)
        with file_path.open("rb") as stream:
            while True:
                block = stream.read(1 << 20)
                if not block:
                    break
                h.update(block)

    if path.is_file():
        with path.open("rb") as stream:
            while True:
                block = stream.read(1 << 20)
                if not block:
                    break
                h.update(block)
        return "file", h.hexdigest()
    if path.is_dir():
        entries = sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix())
        for entry in entries:
            rel = entry.relative_to(path).as_posix()
            if _is_reparse_point(entry):
                raise OSError(
                    f"reparse-point artifact entries are not allowed: {entry}")
            if entry.is_dir():
                encoded = rel.encode("utf-8", "surrogatepass")
                h.update(b"D")
                h.update(len(encoded).to_bytes(8, "little"))
                h.update(encoded)
            elif entry.is_file():
                absorb_file(entry, rel)
            else:
                raise OSError(f"unsupported artifact entry: {entry}")
        return "directory", h.hexdigest()
    raise OSError(f"artifact is neither a file nor a directory: {path}")


def _evidence_manifest(cfg: OracleConfig) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []

    def add(role: str, path: Path) -> None:
        kind, digest = _sha256_artifact(path)
        artifacts.append({"role": role, "path": str(path.resolve()),
                          "kind": kind, "sha256": digest})

    add("contract", cfg.contract)
    add("original_dll", cfg.original_dll)
    add("tap_dll", cfg.tap_dll)
    if cfg.policy and cfg.policy.is_file():
        add("policy", cfg.policy)
    for i, path in enumerate(cfg.app_files):
        add(f"app_files[{i}]", path)
    for i, path in enumerate(cfg.consumers):
        add(f"consumers[{i}]", path)
    # A later L2 run must not reuse a PASS produced by an older, more
    # permissive verifier.  Bind the attestation to the exact implementation
    # modules that made the L0 decision, and re-hash them again at the end.
    package_dir = Path(__file__).resolve().parent
    for name in (
            "oracle_check.py", "runner.py", "model.py", "trace.py",
            "normalize.py", "tracediff.py", "policy.py", "pe_surface.py"):
        add(f"verifier:{name}", package_dir / name)

    config_view = _jsonable(dataclasses.asdict(cfg))
    config_json = json.dumps(config_view, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False)
    manifest: dict[str, Any] = {
        "artifacts": artifacts,
        "config_sha256": hashlib.sha256(config_json.encode("utf-8")).hexdigest(),
        "scenario": list(cfg.scenario),
        "policy_source": (str(cfg.policy.resolve()) if cfg.policy else
                          "derived-from-contract"),
    }
    encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False)
    manifest["manifest_sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return manifest


def _guard(name: str, fn: Callable[[], CheckOutcome]) -> CheckOutcome:
    """One failing check must never take the others down with it."""
    try:
        return fn()
    except Exception as exc:
        logger.exception("check %s raised", name)
        return CheckOutcome(name, False,
                            f"check raised {type(exc).__name__}: {exc}")


def _skipped(name: str, why: str) -> CheckOutcome:
    return CheckOutcome(name, False, f"skipped: {why}", {"status": "skipped"})


def check_oracle(cfg: OracleConfig, *,
                 write_policy: bool | None = None) -> OracleReport:
    """Run the five L0 checks.

    `write_policy` overrides `cfg.write_policy` when given, so both the config
    file and the legacy `--write-policy` flag are rejected by the fail-closed
    config gate.  Candidate masks must be reviewed outside an approval run.
    """
    if write_policy is not None:
        cfg.write_policy = write_policy
    report = OracleReport()
    problems = cfg.problems()
    if problems:
        for name in CHECK_ORDER:
            report.outcomes.append(_skipped(name, "; ".join(problems)))
        return report

    try:
        report.evidence = _evidence_manifest(cfg)
    except (OSError, ValueError, TypeError) as exc:
        why = (f"could not bind report to immutable artifact evidence: "
               f"{type(exc).__name__}: {exc}")
        for name in CHECK_ORDER:
            report.outcomes.append(_skipped(name, why))
        return report

    cfg.work_dir.mkdir(parents=True, exist_ok=True)
    try:
        contract = Contract.load(cfg.contract)
    except (ContractError, OSError, ValueError) as exc:
        for name in CHECK_ORDER:
            report.outcomes.append(
                _skipped(name, f"contract {cfg.contract} unusable: {exc}"))
        return report

    staging_problems: list[str] = []
    for label, value in (("contract.module", contract.module),
                         ("contract.real_module", contract.real_module)):
        problem = _leaf_problem(value, label, allow_empty=(label.endswith(
            "real_module")))
        if problem:
            staging_problems.append(problem)
    real_name = cfg.real_dll_name or contract.real_module
    if real_name and real_name.casefold() == cfg.target_dll_name.casefold():
        staging_problems.append(
            "the renamed original DLL must differ from the application-loaded "
            "DLL name")
    if staging_problems:
        for name in CHECK_ORDER:
            report.outcomes.append(_skipped(name, "; ".join(staging_problems)))
        return report

    ctx = _Ctx(cfg, contract)
    structural = _guard("structural", lambda: _check_structural(cfg, contract))
    report.outcomes.append(structural)
    report.outcomes.append(
        _guard("passthrough", lambda: _check_passthrough(cfg, ctx)))

    if not structural.ok:
        why = "structural check failed; a tap with the wrong surface is not " \
              "the thing under test"
        for name in ("determinism", "coverage", "noninterference"):
            report.outcomes.append(_skipped(name, why))
        return report

    determinism = _guard("determinism",
                         lambda: _check_determinism(cfg, ctx, contract))
    report.outcomes.append(determinism)
    report.outcomes.append(
        _guard("coverage", lambda: _check_coverage(cfg, ctx, contract)))
    report.outcomes.append(
        _guard("noninterference", lambda: _check_noninterference(cfg, ctx)))

    if cfg.write_policy:
        recheck = _guard("determinism-recheck",
                         lambda: _write_policy_and_recheck(cfg, ctx, contract,
                                                           determinism))
        report.outcomes.append(recheck)
    if report.ok:
        try:
            after = _evidence_manifest(cfg)
            if after.get("manifest_sha256") != report.evidence.get(
                    "manifest_sha256"):
                report.outcomes.append(CheckOutcome(
                    "artifact-integrity", False,
                    "an input artifact or effective config changed while the "
                    "oracle was running; the observations are not bound to a "
                    "single immutable input set",
                    {"before": report.evidence, "after": after}))
            else:
                report.evidence["verified_unchanged_after_run"] = True
        except Exception as exc:
            report.outcomes.append(CheckOutcome(
                "artifact-integrity", False,
                f"could not re-hash evidence after the run: "
                f"{type(exc).__name__}: {exc}"))
    return report


def _write_policy_and_recheck(cfg: OracleConfig, ctx: _Ctx, contract: Contract,
                              determinism: CheckOutcome) -> CheckOutcome:
    name = "determinism-recheck"
    if determinism.ok:
        return CheckOutcome(
            name, True,
            "this fresh run was already deterministic; no policy changes "
            "were fitted to its traces")
    if not determinism.suggestions:
        return CheckOutcome(
            name, False,
            "determinism failed but produced no mask proposals: the residual "
            "diff is structural (missing or extra calls), which masking cannot "
            "fix")
    policy_mod, reason = _sibling("policy")
    if policy_mod is None:
        return CheckOutcome(name, False, reason)

    base = _load_policy(cfg, policy_mod, contract)
    merged = base.merged_with(list(determinism.suggestions))
    out_path = Path(cfg.policy) if cfg.policy else cfg.work_dir / "policy.auto.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged.save(out_path)
    cfg.policy = out_path
    logger.info("merged %d auto mask(s) into %s",
                len(determinism.suggestions), out_path)
    # Never score a mask on the traces that selected it.  That is training-set
    # evaluation and guarantees an apparently clean re-diff even when the mask
    # erased meaningful behaviour.  Persist the candidate, keep this report
    # failed, and require a new process/invocation to generate holdout runs.
    return CheckOutcome(
        name, False,
        f"wrote {len(determinism.suggestions)} candidate mask(s) to "
        f"{out_path}, but did not re-use the fitting traces. This report "
        "remains FAIL; review the policy and run the oracle again to validate "
        "it on fresh holdout executions.",
        {"policy": str(out_path),
         "merged_masks": len(determinism.suggestions),
         "requires_fresh_invocation": True})


# --------------------------------------------------------------------------
# serialization helpers


def _rule_json(rule: Any) -> dict:
    if dataclasses.is_dataclass(rule) and not isinstance(rule, type):
        return dataclasses.asdict(rule)
    try:
        return {k: v for k, v in vars(rule).items() if not k.startswith("_")}
    except TypeError:
        return {"repr": repr(rule)}


def _rule_text(rule: Any) -> str:
    d = _rule_json(rule)
    ranges = d.get("byte_ranges")
    where = f"{d.get('sym', '*')}.{d.get('path', '*')}"
    span = "whole value" if not ranges else ", ".join(
        f"[{o}:{o + n}]" for o, n in ranges)
    why = d.get("why") or "nondeterministic in A-vs-A run"
    return f"{where} {span} -- {why}"


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return repr(obj)


# --------------------------------------------------------------------------
# CLI


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="shimforge oracle",
        description="L0 oracle self-verification (five checks)")
    ap.add_argument("--config", required=True, help="oracle.json")
    ap.add_argument("--write-policy", action="store_true",
                    help="legacy candidate-mask mode (rejected by the "
                         "fail-closed approval gate)")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="emit the machine readable report")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    try:
        cfg = OracleConfig.load(args.config)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # TypeError: a config whose top level is a list or a scalar indexes
        # with a str and would otherwise escape as a traceback.
        print(f"cannot load {args.config}: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2
    if args.write_policy:
        cfg.write_policy = True
    report = check_oracle(cfg)
    if args.as_json:
        print(json.dumps(report.to_json(), indent=2, ensure_ascii=False))
    else:
        print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":                      # pragma: no cover
    raise SystemExit(main())
