from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from .models import VulnFinding
from .version_scan import normalize_version

_CSV_SPLIT_RE = re.compile(r"\s*,\s*")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in _CSV_SPLIT_RE.split(value) if v and v.strip()]


def connect(db_path: Path) -> sqlite3.Connection:
    """읽기 전용 연결. 스키마는 branch2 소유이므로 생성/수정하지 않는다."""
    db_path = Path(db_path)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _upper_bound_vulnerable(detected: str | None, fixed: str | None) -> bool:
    """detected < fixed → True(취약). 판정 불가(버전 미상/fixed 없음)면 False."""
    if not detected or not fixed:
        return False
    return normalize_version(detected) < normalize_version(fixed)


def judge(
    conn: sqlite3.Connection,
    dll_name: str,
    resolved_path: Path,
    detected_version: str | None,
    imported_functions: list[str],
) -> VulnFinding | None:
    """(로드될 DLL, 실제 버전, exe가 import한 함수 목록)로 취약 여부 판정."""
    dll_lower = dll_name.lower()
    rows = conn.execute(
        "SELECT cve_id, dll_names, fixed_version, severity, detection_method, description "
        "FROM vulnerabilities"
    ).fetchall()

    matched_rows = [
        row for row in rows if dll_lower in {n.lower() for n in _split_csv(row["dll_names"])}
    ]
    if not matched_rows:
        return None

    imported_lower = {f.lower() for f in imported_functions if f}
    potential: VulnFinding | None = None

    for row in matched_rows:
        cve_id = row["cve_id"]
        fixed_version = row["fixed_version"]
        method = row["detection_method"] or "version_only"
        severity = row["severity"]
        advice = row["description"] or ""

        if detected_version is None:
            if potential is None:
                potential = VulnFinding(
                    dll_name=dll_name,
                    resolved_path=resolved_path,
                    detected_version=None,
                    cve_id=cve_id,
                    fixed_version=fixed_version,
                    detection_method=method,
                    matched_functions=[],
                    reason=f"버전 미상 — 실제 버전을 확인할 수 없어 잠재 취약으로 표기 (fixed={fixed_version})",
                    severity=severity,
                    advice=advice,
                    is_potential=True,
                )
            continue

        if not _upper_bound_vulnerable(detected_version, fixed_version):
            continue

        matched_functions: list[str] = []
        if method == "import_function":
            func_rows = conn.execute(
                "SELECT function_name FROM vulnerable_functions WHERE cve_id=? AND is_public_api=1",
                (cve_id,),
            ).fetchall()
            public_funcs = {r["function_name"].lower() for r in func_rows}
            matched_functions = sorted(imported_lower & public_funcs)
            if matched_functions:
                reason = (
                    f"버전 {detected_version} < {fixed_version}(fixed) + "
                    f"import 함수 교차검증: {', '.join(matched_functions)}"
                )
            else:
                reason = f"버전 {detected_version} < {fixed_version}(fixed), 단 취약 함수 미탐지(위험도 낮음)"
        else:
            reason = f"버전 {detected_version} < {fixed_version}(fixed)"

        return VulnFinding(
            dll_name=dll_name,
            resolved_path=resolved_path,
            detected_version=detected_version,
            cve_id=cve_id,
            fixed_version=fixed_version,
            detection_method=method,
            matched_functions=matched_functions,
            reason=reason,
            severity=severity,
            advice=advice,
            is_potential=False,
        )

    return potential
