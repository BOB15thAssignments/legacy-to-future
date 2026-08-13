from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_SEGMENT_RE = re.compile(r"^(\d+)([a-zA-Z]*)$")

# 2단계(임베드 문자열 스캔)에서 아주 큰 DLL을 통째로 정규식 훑지 않기 위한 상한.
# 버전 문자열은 보통 파일 초반(.rdata) 아니면 후반(리소스 근처)에 있으므로
# 앞/뒤 청크만 보면 충분하다 — 중간 스트리밍 같은 복잡한 처리는 하지 않는다.
_SCAN_CHUNK_BYTES = 2 * 1024 * 1024  # 2MB

# 2단계 화이트리스트: "쉽게 뽑히는" 라이브러리만 등록한다(라이브러리명 -> 정규식,
# 캡처 그룹 1이 버전 문자열). 리소스가 없을 때만 시도되며, 여기 없는 라이브러리는
# 의도적으로 포기(None)한다 — vuln_db.judge의 "버전 미상 -> 잠재 취약" 경로에 맡긴다.
# 패턴은 각 라이브러리 소스코드가 실제로 바이너리에 박아 넣는 표준 버전 문자열이다:
#   zlib    : deflate()가 내보내는 "deflate 1.2.11 Copyright ..." (ZLIB_VERSION)
#   openssl : OPENSSL_VERSION_TEXT "OpenSSL 1.1.1k  25 Mar 2021"
#   libpng  : PNG_LIBPNG_VER_STRING "libpng version 1.6.37 - April 14, 2019"
_EMBEDDED_VERSION_PATTERNS: dict[str, re.Pattern] = {
    "zlib": re.compile(rb"deflate\s+(\d+\.\d+\.\d+(?:\.\d+)?)\s+Copyright"),
    "openssl": re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)\s"),
    "libpng": re.compile(rb"libpng version\s+(\d+\.\d+\.\d+)"),
}


def _resource_name(node) -> str:
    """pefile 버전에 따라 nested.name이 str/bytes 둘 다일 수 있어 통일한다."""
    name = getattr(node, "name", "")
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="ignore")
    return name


def _read_resource_version(pe) -> str | None:
    """VS_VERSION_INFO 리소스에서 버전을 뽑는다. DLL 종류와 무관한 공통 파서.
    StringFileInfo의 FileVersion/ProductVersion을 우선 보고, 그마저 없으면
    VS_FIXEDFILEINFO의 숫자 버전(dwFileVersionMS/LS)으로 폴백한다."""
    for info in getattr(pe, "FileInfo", []) or []:
        for nested in info:
            if _resource_name(nested) != "StringFileInfo":
                continue
            for table in getattr(nested, "StringTable", []):
                entries = getattr(table, "entries", {}) or {}
                decoded: dict[str, str] = {}
                for key, value in entries.items():
                    if isinstance(key, bytes):
                        key = key.decode("ascii", errors="ignore")
                    if isinstance(value, bytes):
                        value = value.decode("ascii", errors="ignore")
                    if value:
                        decoded[str(key).lower()] = str(value).strip()
                for preferred in ("fileversion", "productversion"):
                    if decoded.get(preferred):
                        return decoded[preferred]

    for fixed in getattr(pe, "VS_FIXEDFILEINFO", []) or []:
        ms = getattr(fixed, "FileVersionMS", None)
        ls = getattr(fixed, "FileVersionLS", None)
        if ms is None or ls is None:
            continue
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    return None


def _read_scan_bytes(dll_path: Path) -> bytes:
    """2단계 스캔용 바이트를 읽는다. 파일이 상한보다 크면 앞/뒤 청크만 읽는다."""
    size = dll_path.stat().st_size
    with dll_path.open("rb") as f:
        if size <= _SCAN_CHUNK_BYTES * 2:
            return f.read()
        head = f.read(_SCAN_CHUNK_BYTES)
        f.seek(-_SCAN_CHUNK_BYTES, 2)
        tail = f.read(_SCAN_CHUNK_BYTES)
        return head + tail


def scan_embedded_version(data: bytes) -> str | None:
    """바이트에서 화이트리스트에 등록된 라이브러리의 버전 문자열을 찾는다.
    첫 매칭에서 종료. 정규식 캡처 그룹이 이미 순수 버전 문자열이므로
    별도 정규화 로직 없이 그대로(strip만) 반환 — normalize_version()과
    비교 단계는 vuln_db.judge가 담당한다."""
    for pattern in _EMBEDDED_VERSION_PATTERNS.values():
        match = pattern.search(data)
        if match:
            return match.group(1).decode("ascii", errors="ignore").strip()
    return None


def read_version(dll_path: Path) -> str | None:
    """1) VS_VERSION_INFO 리소스 파싱 -> 2) (리소스 없을 때만) 임베드 버전 문자열
    스캔 순으로 시도한다. 둘 다 실패하면 None(미상) — vuln_db.judge가
    "버전 미상 -> 잠재 취약"으로 받는다."""
    dll_path = Path(dll_path)
    if not dll_path.exists():
        return None

    try:
        import pefile
    except Exception:
        return None

    try:
        pe = pefile.PE(str(dll_path))
    except Exception:
        logger.exception("PE 파싱 실패: %s", dll_path)
        return None

    try:
        version = _read_resource_version(pe)
        if version:
            return version
    except Exception:
        logger.exception("버전 리소스 파싱 실패: %s", dll_path)

    try:
        data = _read_scan_bytes(dll_path)
    except OSError:
        logger.exception("버전 문자열 스캔용 읽기 실패: %s", dll_path)
        return None
    return scan_embedded_version(data)


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
