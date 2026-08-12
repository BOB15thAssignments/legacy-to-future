from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .models import ImportedDll, ImportedFunction


logger = logging.getLogger(__name__)


def _parse_import_function(func: Any) -> ImportedFunction:
    if getattr(func, "name", None):
        try:
            name = func.name.decode("ascii", errors="ignore")
        except Exception:
            name = str(func.name)
        return ImportedFunction(name=name, ordinal=None)
    if getattr(func, "ordinal", None) is not None:
        return ImportedFunction(name=None, ordinal=int(func.ordinal))
    return ImportedFunction(name=None, ordinal=None)


def extract_imports(exe_path: Path) -> list[ImportedDll]:
    """PE import 디렉터리에서 imported dll과 함수를 추출한다."""
    exe_path = Path(exe_path)
    if not exe_path.exists():
        logger.warning("EXE not found: %s", exe_path)
        return []

    try:
        import pefile
    except Exception:
        logger.warning("pefile이 설치되어 있지 않습니다. import 추출을 건너뜁니다.")
        return []

    try:
        pe = pefile.PE(str(exe_path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        logger.exception("Invalid or unsupported PE: %s", exe_path)
        return []

    imports: dict[str, ImportedDll] = {}
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not entries:
        return []

    for entry in entries:
        dll_name = None
        if getattr(entry, "dll", None):
            try:
                dll_name = entry.dll.decode("ascii", errors="ignore")
            except Exception:
                dll_name = str(entry.dll)
        if not dll_name:
            continue
        dll_name = dll_name.strip().rstrip("\x00")
        if not dll_name:
            continue

        dll = imports.setdefault(dll_name, ImportedDll(name=dll_name))
        seen: set[str] = {f"{f.name}:{f.ordinal}" for f in dll.functions}
        for func in getattr(entry, "imports", []) or []:
            parsed = _parse_import_function(func)
            key = f"{parsed.name}:{parsed.ordinal}"
            if key in seen:
                continue
            seen.add(key)
            dll.functions.append(parsed)

    return list(imports.values())


def get_arch(pe_path: Path) -> str:
    """PE의 machine 필드로 아키텍처를 반환."""
    pe_path = Path(pe_path)
    if not pe_path.exists():
        return "unknown"

    try:
        import pefile
    except Exception:
        return "unknown"

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14C:
            return "x86"
        if machine == 0x8664:
            return "x64"
        return "unknown"
    except Exception:
        logger.exception("아키텍처 판별 실패: %s", pe_path)
        return "unknown"
