from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_SEGMENT_RE = re.compile(r"^(\d+)([a-zA-Z]*)$")


def read_version(dll_path: Path) -> str | None:
    """PE의 VS_VERSION_INFO(FileVersion/ProductVersion) 읽어 버전 문자열 반환.
    리소스 없으면 None(미상)."""
    dll_path = Path(dll_path)
    if not dll_path.exists():
        return None

    try:
        import pefile
    except Exception:
        return None

    try:
        pe = pefile.PE(str(dll_path))
        file_info = getattr(pe, "FileInfo", []) or []
        for info in file_info:
            for nested in info:
                if getattr(nested, "name", b"") in (b"StringFileInfo",):
                    for table in getattr(nested, "StringTable", []):
                        for key, value in getattr(table, "entries", {}).items():
                            if isinstance(key, bytes):
                                key = key.decode("ascii", errors="ignore")
                            if isinstance(value, bytes):
                                value = value.decode("ascii", errors="ignore")
                            if str(key).lower() in {"fileversion", "productversion"}:
                                return str(value).strip() if value else None
    except Exception:
        logger.exception("버전 추출 실패: %s", dll_path)
        return None
    return None


def normalize_version(v: str) -> tuple:
    """'1.2.11.0', '1.0.1g' 같은 문자열을 비교 가능한 튜플로 정규화.
    각 세그먼트를 (숫자, 접미사) 쌍으로 통일해 타입 불일치 비교 오류를 피한다."""
    segments: list[tuple[int, str]] = []
    for part in re.split(r"[.\-]", v.strip()):
        if not part:
            continue
        m = _SEGMENT_RE.match(part)
        if m:
            num = int(m.group(1))
            suffix = m.group(2).lower()
        else:
            digits = re.sub(r"\D", "", part)
            num = int(digits) if digits else 0
            suffix = re.sub(r"\d", "", part).lower()
        segments.append((num, suffix))
    return tuple(segments)
