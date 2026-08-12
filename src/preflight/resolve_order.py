from __future__ import annotations

import logging
import os
from pathlib import Path

from .models import LoadPrediction

logger = logging.getLogger(__name__)


def load_known_dlls(config) -> set[str]:
    """HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs 를 읽어
    KnownDLLs 집합을 구성한다. 비-Windows 환경에서는 winreg가 없어 빈 집합을 반환한다."""
    try:
        import winreg
    except ImportError:
        logger.warning("winreg 사용 불가(비-Windows 환경). KnownDLLs 조회를 건너뜁니다.")
        return set()

    known: set[str] = set()
    for subkey_name in ("KnownDLLs", "KnownDLLs32"):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager" + "\\" + subkey_name,
            )
        except OSError:
            continue
        i = 0
        while True:
            try:
                _, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            if isinstance(value, str) and value.lower().endswith(".dll"):
                known.add(value.lower())
            i += 1
        winreg.CloseKey(key)
    return known


def _resolve_sxs(manifest_path: Path, dll_name: str, config) -> Path | None:
    """외부 매니페스트의 assemblyIdentity로 WinSxS에서 근사 매칭.
    ※ 근사치: WinSxS 폴더명의 publicKeyToken/hash 접미사는 재현 불가하므로 glob 패턴으로 추정."""
    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(manifest_path)
    except Exception:
        return None

    winsxs = config.WINDIR / "WinSxS"
    if not winsxs.exists():
        return None

    for identity in tree.getroot().iter():
        if not identity.tag.endswith("assemblyIdentity"):
            continue
        name = identity.get("name")
        version = identity.get("version")
        arch = identity.get("processorArchitecture") or "*"
        if not name or not version:
            continue
        for match_dir in winsxs.glob(f"{arch}_{name}_*_{version}_*"):
            dll_path = match_dir / dll_name
            if dll_path.exists():
                return dll_path
    return None


def resolve(dll_name: str, exe_path: Path, exe_arch: str, config) -> LoadPrediction:
    """로더 검색순서를 재현해 '로드될 파일'을 예측한다.
    KnownDLLs → .local/SxS → app_dir → System(arch별) → Windows → CWD → PATH."""
    exe_path = Path(exe_path)
    name_lower = dll_name.lower()

    if name_lower in load_known_dlls(config):
        return LoadPrediction(dll_name=dll_name, resolved_path=None, resolved_by="KnownDLLs", is_system=True)

    dotlocal_candidate = exe_path.parent / f"{exe_path.name}.local" / dll_name
    if dotlocal_candidate.exists():
        return LoadPrediction(dll_name=dll_name, resolved_path=dotlocal_candidate, resolved_by="dotlocal", is_system=False)

    manifest_path = exe_path.parent / f"{exe_path.name}.manifest"
    if manifest_path.exists():
        sxs_path = _resolve_sxs(manifest_path, dll_name, config)
        if sxs_path is not None:
            return LoadPrediction(dll_name=dll_name, resolved_path=sxs_path, resolved_by="sxs", is_system=False)

    app_candidate = exe_path.parent / dll_name
    if app_candidate.exists():
        return LoadPrediction(dll_name=dll_name, resolved_path=app_candidate, resolved_by="app_dir", is_system=False)

    system_dir = config.SYSWOW64 if exe_arch == "x86" else config.SYSTEM32
    system_candidate = system_dir / dll_name
    if system_candidate.exists():
        return LoadPrediction(dll_name=dll_name, resolved_path=system_candidate, resolved_by="system32", is_system=True)

    windir_candidate = config.WINDIR / dll_name
    if windir_candidate.exists():
        return LoadPrediction(dll_name=dll_name, resolved_path=windir_candidate, resolved_by="system32", is_system=True)

    cwd_candidate = Path.cwd() / dll_name
    if cwd_candidate.exists():
        return LoadPrediction(dll_name=dll_name, resolved_path=cwd_candidate, resolved_by="cwd", is_system=False)

    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        path_candidate = Path(entry) / dll_name
        if path_candidate.exists():
            return LoadPrediction(dll_name=dll_name, resolved_path=path_candidate, resolved_by="path", is_system=False)

    return LoadPrediction(dll_name=dll_name, resolved_path=None, resolved_by="not_found", is_system=False)
