from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class ImportedFunction:
    name: str | None
    ordinal: int | None


@dataclass
class ImportedDll:
    name: str
    functions: list[ImportedFunction] = field(default_factory=list)


@dataclass
class LoadPrediction:
    dll_name: str
    resolved_path: Path | None
    resolved_by: str
    is_system: bool


@dataclass
class VulnFinding:
    dll_name: str
    resolved_path: Path
    detected_version: str | None
    cve_id: str
    fixed_version: str | None
    detection_method: str
    matched_functions: list[str]
    reason: str
    severity: str | None
    advice: str
    is_potential: bool = False


Decision = Literal[
    "no_risk",           # findings 없음 -> 물어볼 필요 없이 resume
    "allowed",           # findings 있음, 실행이 허용됨(주체는 decided_by가 따로 밝힘) -> resume
    "aborted",           # findings 있음, 실행이 거부됨(주체는 decided_by가 따로 밝힘) -> terminate
    "blocked_on_error",  # 판정(_analyze/_ask) 중 예외 + FAIL_OPEN_ON_ERROR=False(기본) -> terminate
    "allowed_on_error",  # 판정(_analyze/_ask) 중 예외 + FAIL_OPEN_ON_ERROR=True -> resume
]

# "누가/무엇이 이 결정을 내렸는가" — decision과 분리된 감사 축.
# no_risk는 물어볼 필요가 없었으므로 None.
DecidedBy = Literal["user", "default", "fail_open"]


@dataclass
class PreflightResult:
    exe_path: Path
    predictions: list[LoadPrediction] = field(default_factory=list)
    findings: list[VulnFinding] = field(default_factory=list)
    decision: Decision | None = None      # run()이 반환하기 전까지만 None. "pending" 문자열은 폐지.
    decided_by: DecidedBy | None = None   # "user"=실제 입력 / "default"=정책 기본값 / "fail_open"=예외 fail-safe
    exit_code: int | None = None          # resume 경로에서만 채워짐(대상 프로세스의 실제 종료코드)
