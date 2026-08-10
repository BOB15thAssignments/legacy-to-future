#!/usr/bin/env python3
"""
detect_driver_signal.py — [부가] 드라이버 통신 신호 탐지

pe_extract.py가 이미 뽑아둔 import 목록을 재사용해서,
'이 파일이 드라이버/장치와 통신할 가능성이 있는가'만 판정한다. (파싱을 다시 하지 않음)

판정 기준:
    HIGH  DeviceIoControl류가 있음 → 드라이버에 직접 명령을 보냄
    LOW   CreateFile류만 있음      → 일반 파일 접근일 수도 있어 단정 불가
    NONE  둘 다 없음

한계: 정적 신호일 뿐 확정 증거가 아니다. 실제로 어떤 장치를 여는지 알려면
      문자열 섹션에서 '\\\\.\\장치이름' 패턴을 찾는 분석이 추가로 필요하다.

사용법:
    python3 pe_extract.py 대상.dll --json out.json
    python3 detect_driver_signal.py out.json
"""
import sys
import json

# 드라이버에 명령(IOCTL)을 보내는 함수 — 있으면 드라이버 통신이 거의 확실
STRONG_SIGNAL_FUNCS = {
    "DeviceIoControl",
    "NtDeviceIoControlFile",
    "IoCreateDevice",
}

# 장치 경로를 여는 데도 쓰이지만 일반 파일에도 쓰임 — 단독으로는 근거가 약함
WEAK_SIGNAL_FUNCS = {
    "CreateFileW",
    "CreateFileA",
}


def detect_driver_signal(imports):
    """import 목록을 받아 판정 결과를 dict로 반환.

    imports: {DLL이름: [함수명, ...]}  ← pe_extract.py의 'imports' 값을 그대로 넣으면 된다
    """
    used_funcs = collect_all_function_names(imports)

    strong = sorted(used_funcs & STRONG_SIGNAL_FUNCS)
    weak = sorted(used_funcs & WEAK_SIGNAL_FUNCS)

    return {
        "level": decide_level(strong, weak),
        "strong_signals": strong,
        "weak_signals": weak,
    }


def collect_all_function_names(imports):
    """DLL별로 나뉘어 있는 함수 목록을 하나의 집합으로 합친다."""
    all_names = set()
    for function_names in imports.values():
        all_names.update(function_names)
    return all_names


def decide_level(strong, weak):
    """찾아낸 신호를 보고 HIGH / LOW / NONE 중 하나를 고른다."""
    if strong:
        return "HIGH"
    if weak:
        return "LOW"
    return "NONE"


# =============================================================== 화면 출력용

LEVEL_DESCRIPTIONS = {
    "HIGH": "드라이버 통신 가능성 높음 (DeviceIoControl류 존재)",
    "LOW": "판단 보류 (CreateFile류만 존재 — 일반 파일 접근일 수 있음)",
    "NONE": "장치 통신 신호 없음",
}


def print_result(file_path, result):
    print(f"[{file_path}]")
    print(f"  {result['level']} — {LEVEL_DESCRIPTIONS[result['level']]}")
    if result["strong_signals"]:
        print("  강한 신호:", ", ".join(result["strong_signals"]))
    if result["weak_signals"]:
        print("  약한 신호:", ", ".join(result["weak_signals"]))


def main():
    if len(sys.argv) != 2:
        print("사용법: python3 detect_driver_signal.py <pe_extract 결과.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        pe_info = json.load(f)

    result = detect_driver_signal(pe_info["imports"])
    print_result(pe_info["file"], result)


if __name__ == "__main__":
    main()

