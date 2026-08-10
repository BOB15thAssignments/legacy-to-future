#!/usr/bin/env python3
"""
pe_extract.py — [1단계] PE 파싱: exe/dll이 의존하는 라이브러리·함수·버전 추출

전체 흐름 (아래 함수들이 이 순서로 정의되어 있음):
    extract_pe_info()           ← 진입점. 아래 것들을 순서대로 호출해 결과 하나로 합침
      ├ read_file_type()        파일이 EXE인지 DLL인지
      ├ read_architecture()     32비트인지 64비트인지
      ├ read_version()          제품명·버전 문자열 (취약 여부 판단의 핵심 재료)
      ├ read_imported_dlls()    이 파일이 '빌려 쓰는' DLL과 함수들 (exe→DLL→함수)
      └ read_exported_funcs()   이 DLL이 '제공하는' 함수들 (DLL일 때만)

출력: 파이썬 dict. --json 옵션을 준 경우에만 JSON 파일로도 저장한다.

사용법:
    python3 pe_extract.py <파일경로>                  # 화면에 요약 출력
    python3 pe_extract.py <파일경로> --json out.json  # JSON으로도 저장
"""
import sys
import json
import argparse
import pefile

# PE 헤더에서 쓰는 상수 (매직넘버에 이름을 붙여둔 것)
FLAG_IS_DLL = 0x2000          # Characteristics에 이 비트가 켜져 있으면 DLL
ARCHITECTURES = {
    0x014c: "x86",
    0x8664: "x64",
    0xaa64: "arm64",
}


# ================================================================= 진입점

def extract_pe_info(path):
    """PE 파일 하나를 읽어 정보를 dict로 반환한다."""
    pe = pefile.PE(path)

    info = {
        "file": path,
        "type": read_file_type(pe),
        "arch": read_architecture(pe),
        "version": read_version(pe),
        "imports": read_imported_dlls(pe),
    }
    if info["type"] == "DLL":
        info["exports"] = read_exported_funcs(pe)

    pe.close()
    return info


# ====================================================== 1) 파일 종류·아키텍처

def read_file_type(pe):
    """'EXE' 또는 'DLL'을 반환."""
    is_dll = bool(pe.FILE_HEADER.Characteristics & FLAG_IS_DLL)
    return "DLL" if is_dll else "EXE"


def read_architecture(pe):
    """'x86' / 'x64' / 'arm64'를 반환. 대체 DLL 매칭 시 이게 다르면 무조건 실패."""
    machine_code = pe.FILE_HEADER.Machine
    return ARCHITECTURES.get(machine_code, f"unknown({hex(machine_code)})")


# =============================================================== 2) 버전 정보

def read_version(pe):
    """VS_VERSION_INFO 리소스에서 버전 정보를 dict로 추출.

    버전이 두 군데에 나뉘어 있어서 둘 다 읽는다:
      - 숫자 버전 : VS_FIXEDFILEINFO  예) 14.40.33810.0
      - 문자열들  : StringFileInfo    예) ProductName, CompanyName
    리소스가 아예 없는 파일도 흔하다 → 그 경우 빈 dict 반환 (에러 아님).
    """
    version = {}

    if getattr(pe, "VS_FIXEDFILEINFO", None):
        fixed = pe.VS_FIXEDFILEINFO[0]
        high, low = fixed.FileVersionMS, fixed.FileVersionLS
        # 32비트 값 2개에 네 자리 버전이 16비트씩 나뉘어 담겨 있어 쪼개서 조립한다
        version["FileVersion_numeric"] = (
            f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"
        )

    version.update(read_version_strings(pe))
    return version


def read_version_strings(pe):
    """StringFileInfo 안의 문자열 항목(ProductName 등)만 뽑아내는 보조 함수."""
    strings = {}
    for entry_group in getattr(pe, "FileInfo", []):
        for entry in entry_group:
            if entry.Key.decode(errors="replace") != "StringFileInfo":
                continue
            for table in entry.StringTable:
                for key, value in table.entries.items():
                    strings[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return strings


# ========================================================== 3) import 테이블

def read_imported_dlls(pe):
    """이 파일이 쓰는 DLL과 함수를 {DLL이름: [함수명, ...]} 형태로 반환.

    주의: import 테이블은 '무엇을 쓰는지'만 알려주고 '버전'은 알려주지 않는다.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return {}

    imported = {}
    for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll_entry.dll.decode("utf-8", "replace")
        imported[dll_name] = [read_function_name(f) for f in dll_entry.imports]
    return imported


def read_function_name(imported_func):
    """함수 하나의 이름을 반환. 이름 없이 번호로만 import된 경우 'ordinal#N' 형태.

    (ordinal 방식은 대체 DLL이 같은 번호에 같은 함수를 뒀다는 보장이 없어서
     호환성 판정 때 '확인 불가'로 따로 표시해야 하는 케이스다.)
    """
    if imported_func.name:
        return imported_func.name.decode("utf-8", "replace")
    return f"ordinal#{imported_func.ordinal}"


# ========================================================== 4) export 테이블

def read_exported_funcs(pe):
    """이 DLL이 외부에 제공하는 함수를 [{name, ordinal}, ...] 형태로 반환.

    대체 DLL이 원본을 대신할 수 있는지 판정할 때 이 목록과 비교한다.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []

    exported = []
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exported.append({
            "name": symbol.name.decode("utf-8", "replace") if symbol.name else None,
            "ordinal": symbol.ordinal,
        })
    return exported


# =============================================================== 화면 출력용

def print_summary(info):
    """추출 결과를 사람이 읽기 좋게 출력."""
    print(f"\n[ {info['file']} ]  {info['type']} / {info['arch']}")
    print(f"  버전: {format_version(info['version'])}")

    print(f"  쓰는 DLL {len(info['imports'])}개:")
    for dll_name, functions in info["imports"].items():
        print(f"    - {dll_name} ({len(functions)}개)  {preview_list(functions)}")

    if "exports" in info:
        print(f"  제공하는 함수(export): {len(info['exports'])}개")


def format_version(version):
    """버전 dict를 '제품명 버전' 한 줄로. 정보가 없으면 그 사실을 알려준다."""
    if not version:
        return "(VS_VERSION_INFO 없음 — 정적 링크거나 버전 미기재)"
    name = version.get("ProductName") or version.get("InternalName") or "(제품명 없음)"
    number = version.get("FileVersion") or version.get("FileVersion_numeric") or "(버전 없음)"
    return f"{name}  {number}"


def preview_list(items, limit=5):
    """긴 목록을 앞 몇 개만 보여주고 나머지는 개수로 요약."""
    shown = ", ".join(items[:limit])
    remaining = len(items) - limit
    return shown + (f" ... 외 {remaining}개" if remaining > 0 else "")


# ==================================================================== CLI

def main():
    parser = argparse.ArgumentParser(description="PE 파일에서 DLL/함수/버전 정보 추출")
    parser.add_argument("path", help="분석할 exe 또는 dll 경로")
    parser.add_argument("--json", metavar="OUT", help="결과를 JSON 파일로 저장")
    args = parser.parse_args()

    try:
        info = extract_pe_info(args.path)
    except pefile.PEFormatError as error:
        print(f"PE 파일이 아니거나 손상됨: {error}", file=sys.stderr)
        sys.exit(1)

    print_summary(info)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
        print(f"\n→ JSON 저장: {args.json}")


if __name__ == "__main__":
    main()

