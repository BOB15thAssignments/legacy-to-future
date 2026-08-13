"""JS <-> Python 브릿지. pywebview가 window.pywebview.api.<method>로 노출하는 객체.

흐름 요약:
  1) 드롭/파일선택으로 exe 경로를 얻으면 _analyze()를 별도 스레드에서 돌린다
     (pipeline.run이 대상 프로세스를 정지시킨 채 블로킹하므로, GUI 이벤트 루프가 있는
     메인 스레드를 막지 않기 위함).
  2) pipeline.run()은 findings가 있을 때만 self._prompt를 부른다. 여기서 JS에 결과를
     밀어넣고(evaluate_js) submit_decision()이 불릴 때까지 스레드를 그대로 블로킹한다 —
     __main__.prompt_user가 input()으로 블로킹하는 것과 동일한 자리를 차지할 뿐이다.
  3) 창이 닫히는 등 결정을 영영 못 받는 상황은 fail-safe로 차단(거부) 처리한다
     (config.FAIL_OPEN_ON_ERROR 기본값 False와 같은 방향).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import webview

from preflight import config
from preflight.models import PreflightResult
from preflight.pipeline import run


def _result_to_dict(result: PreflightResult) -> dict:
    return {
        "exePath": str(result.exe_path),
        "decision": result.decision,
        "decidedBy": result.decided_by,
        "exitCode": result.exit_code,
        "findings": [
            {
                "dllName": f.dll_name,
                "resolvedPath": str(f.resolved_path),
                "detectedVersion": f.detected_version,
                "cveId": f.cve_id,
                "fixedVersion": f.fixed_version,
                "reason": f.reason,
                "severity": f.severity,
                "advice": f.advice,
                "isPotential": f.is_potential,
            }
            for f in result.findings
        ],
    }


class Api:
    """js_api=Api()로 window에 붙는 브릿지. window 참조는 start 이후에만 얻을 수 있어
    set_window()로 뒤늦게 주입한다(생성자 시점엔 아직 window가 없음)."""

    def __init__(self) -> None:
        self._window: webview.Window | None = None
        self._decision_event = threading.Event()
        self._decision: bool = False

    def set_window(self, window: webview.Window) -> None:
        self._window = window

    # ---- JS가 직접 호출하는 진입점 ----

    def pick_file(self) -> None:
        """네이티브 파일 선택 대화상자. 드래그앤드롭이 여의치 않을 때의 대안 경로."""
        assert self._window is not None
        paths = self._window.create_file_dialog(
            webview.FileDialog.OPEN,
            file_types=("실행 파일 (*.exe)", "모든 파일 (*.*)"),
        )
        if paths:
            self.start_analysis(paths[0])

    def submit_decision(self, allowed: bool) -> None:
        """findings 확인 모달에서 사용자가 실행/차단 버튼을 눌렀을 때 JS가 호출."""
        self._decision = bool(allowed)
        self._decision_event.set()

    def on_closing(self) -> None:
        """창이 닫힐 때 아직 결정 대기 중인 판정이 있으면 거부로 마무리해
        정지된 프로세스가 좀비로 영영 남는 것을 막는다(fail-safe, deny)."""
        if not self._decision_event.is_set():
            self._decision = False
            self._decision_event.set()

    # ---- 드롭 핸들러(app.py)에서도 호출하는 공용 경로 ----

    def start_analysis(self, exe_path: str) -> None:
        threading.Thread(target=self._analyze, args=(exe_path,), daemon=True).start()

    # ---- 내부 ----

    def _js(self, call: str, payload: object) -> None:
        assert self._window is not None
        self._window.evaluate_js(f"{call}({json.dumps(payload, ensure_ascii=False)})")

    def _analyze(self, exe_path: str) -> None:
        self._js("onAnalyzing", exe_path)
        try:
            result = run(Path(exe_path), [], prompt=self._prompt, policy=config)
        except Exception as exc:  # 분석 자체가 못 돈 경우(파일 아님 등) — 사용자에게 그대로 보여줌
            self._js("onError", str(exc))
            return
        self._js("onResult", _result_to_dict(result))

    def _prompt(self, result: PreflightResult, policy) -> tuple[bool, str]:
        self._decision_event.clear()
        self._js("onFindings", _result_to_dict(result))
        self._decision_event.wait()
        return self._decision, "user"
