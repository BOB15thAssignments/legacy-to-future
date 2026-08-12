from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config
from .models import PreflightResult
from .pipeline import run


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    if "--" in argv:
        idx = argv.index("--")
        own_args, target_args = argv[:idx], argv[idx + 1 :]
    else:
        own_args, target_args = argv, []

    parser = argparse.ArgumentParser(description="DLL 프리플라이트 게이트 - 분석기")
    parser.add_argument("exe", type=Path, help="분석 대상 exe 경로")
    parser.add_argument("--json", type=Path, default=None, help="JSON 리포트 출력 경로")
    ns = parser.parse_args(own_args)
    return ns, target_args


def _print_report(result: PreflightResult) -> None:
    print(f"exe: {result.exe_path}")
    if not result.findings:
        print("취약 DLL 없음 (예측 기준)")
        return
    print(f"{result.exe_path.name} 실행 시 다음이 로드될 것으로 예측됨:")
    for f in result.findings:
        tag = "잠재 취약" if f.is_potential else "취약"
        ver = f.detected_version or "미상"
        print(f"  - {f.dll_name}  <- {f.resolved_path}  버전 {ver}  [{f.cve_id}]  ({tag})")
        print(f"    조언: {f.advice}")
        print(f"    근거: {f.reason}")


def prompt_user(result: PreflightResult, config) -> tuple[bool, str]:
    """취약 findings를 사람이 읽게 출력하고 실행 여부를 묻는다. pipeline.run()에 콜백으로
    전달되어 실제 resume/terminate 분기로 이어진다. 반환값은 (허용여부, 결정 주체) —
    비대화형(stdin이 tty 아님)이면 input()을 호출하지 않고 config.DEFAULT_WHEN_NONINTERACTIVE를
    그대로 쓰며 via="default", 실제로 y/N를 입력받았으면 via="user"."""
    _print_report(result)
    if not sys.stdin.isatty():
        return config.DEFAULT_WHEN_NONINTERACTIVE, "default"
    answer = input("그래도 실행하시겠습니까? [y/N] ").strip().lower()
    return answer == "y", "user"


def write_json(result: PreflightResult, path: Path) -> None:
    data = {
        "exe_path": str(result.exe_path),
        "decision": result.decision,
        "decided_by": result.decided_by,
        "exit_code": result.exit_code,
        "predictions": [
            {
                "dll_name": p.dll_name,
                "resolved_path": str(p.resolved_path) if p.resolved_path else None,
                "resolved_by": p.resolved_by,
                "is_system": p.is_system,
            }
            for p in result.predictions
        ],
        "findings": [
            {
                "dll_name": f.dll_name,
                "resolved_path": str(f.resolved_path),
                "detected_version": f.detected_version,
                "cve_id": f.cve_id,
                "fixed_version": f.fixed_version,
                "detection_method": f.detection_method,
                "matched_functions": f.matched_functions,
                "reason": f.reason,
                "severity": f.severity,
                "advice": f.advice,
                "is_potential": f.is_potential,
            }
            for f in result.findings
        ],
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# 대상이 아예 돌지 않은 경우(aborted/blocked_on_error) 우리가 붙이는 종료코드.
# 대상 프로세스의 실제 종료코드와 겹히지 않는다는 보장은 없지만, 설계 §4.6이 정한
# "실행 안 함"을 나타내는 관례값이다.
_NOT_RUN_EXIT_CODE = 2

# resume까지 이어진 decision만 대상이 실제로 돌았으므로 그 종료코드를 그대로 전달한다.
# pipeline._RESUMED_DECISIONS와 반드시 같은 집합을 가리켜야 한다(이름이 또 바뀌면 여기도 같이).
_RESUMED_DECISIONS = {"no_risk", "allowed", "allowed_on_error"}


def _process_exit_code(result: PreflightResult) -> int:
    """decision -> 우리 프로세스의 종료코드. resume된 경로(no_risk/allowed/allowed_on_error)는
    대상의 실제 종료코드를 그대로 전달하고, 그 외(aborted/blocked_on_error)는
    '실행 안 함'을 나타내는 고정값을 돌려준다."""
    if result.decision in _RESUMED_DECISIONS:
        return result.exit_code if result.exit_code is not None else _NOT_RUN_EXIT_CODE
    return _NOT_RUN_EXIT_CODE


def main() -> None:
    ns, target_args = _parse_args(sys.argv[1:])
    result = run(ns.exe, target_args, prompt=prompt_user, policy=config)

    _print_report(result)
    if ns.json:
        write_json(result, ns.json)

    sys.exit(_process_exit_code(result))


if __name__ == "__main__":
    main()
