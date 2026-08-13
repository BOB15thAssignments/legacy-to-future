"""GUI 부트스트랩. 창을 띄우고, 드래그앤드롭 시 실제 절대경로(pywebviewFullPath)를
받기 위한 DOM 이벤트 핸들러를 등록한다 — 일반 브라우저 File API는 보안상 전체 경로를
숨기지만, pywebview는 webview.dom.DOMEventHandler를 통해 이를 우회 없이 공식 제공한다."""
from __future__ import annotations

from pathlib import Path

import webview
from webview.dom import DOMEventHandler

from .api import Api

_INDEX_HTML = Path(__file__).parent / "index.html"


def _make_drop_handler(api: Api):
    def on_drop(event: dict) -> None:
        files = event.get("dataTransfer", {}).get("files") or []
        if not files:
            return
        path = files[0].get("pywebviewFullPath")
        if path:
            api.start_analysis(path)

    return on_drop


def _bind(window: webview.Window, api: Api) -> None:
    window.events.loaded.wait()  # DOM 이벤트 등록은 페이지 로드 후에만 유효하므로 명시적으로 대기
    api.set_window(window)
    window.events.closing += api.on_closing
    window.dom.document.events.dragover += DOMEventHandler(
        lambda e: None, prevent_default=True
    )
    window.dom.document.events.drop += DOMEventHandler(
        _make_drop_handler(api), prevent_default=True, stop_propagation=True
    )


def main() -> None:
    api = Api()
    window = webview.create_window(
        "DLL 프리플라이트 게이트",
        str(_INDEX_HTML),
        js_api=api,
        width=760,
        height=640,
        min_size=(560, 480),
    )
    webview.start(_bind, (window, api))


if __name__ == "__main__":
    main()
