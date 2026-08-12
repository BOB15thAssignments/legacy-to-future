from __future__ import annotations

from pathlib import Path
from typing import Callable, Literal

from . import config
from . import pe_inspect, resolve_order, version_scan, vuln_db
from .launcher import Launcher, WinLauncher
from .models import LoadPrediction, PreflightResult, VulnFinding

# resume으로 이어진 decision만 대상 프로세스가 실제로 돌았으므로 종료코드를 회수한다.
_RESUMED_DECISIONS = {"no_risk", "allowed", "allowed_on_error"}

_Via = Literal["user", "default"]
PromptFn = Callable[[PreflightResult, object], "tuple[bool, _Via]"]


def _analyze(target: Path, policy) -> tuple[list[LoadPrediction], list[VulnFinding]]:
    """§4.7의 [1..4]: PE 파싱 -> resolve_order -> version_scan -> vuln_db.judge."""
    imports = pe_inspect.extract_imports(target)
    arch = pe_inspect.get_arch(target)
    funcs_by_dll = {
        d.name.lower(): [f.name for f in d.functions if f.name] for d in imports
    }

    predictions = [resolve_order.resolve(d.name, target, arch, policy) for d in imports]

    findings: list[VulnFinding] = []
    conn = vuln_db.connect(policy.DB_PATH)
    try:
        for prediction in predictions:
            if prediction.is_system or prediction.resolved_path is None:
                continue
            detected_version = version_scan.read_version(prediction.resolved_path)
            imported_functions = funcs_by_dll.get(prediction.dll_name.lower(), [])
            finding = vuln_db.judge(
                conn, prediction.dll_name, prediction.resolved_path, detected_version, imported_functions
            )
            if finding:
                findings.append(finding)
    finally:
        conn.close()

    return predictions, findings


def _ask(prompt: PromptFn | None, result: PreflightResult, policy) -> tuple[bool, _Via]:
    """findings가 있을 때 실행 여부를 묻는다. 반환값은 (허용여부, 어디서 온 결정인지).
    콜백이 없으면 이 함수 스스로 정책 기본값을 쓴다(via="default") — stdin/tty는 모른다,
    그건 콜백(__main__.prompt_user)의 책임이라 pipeline이 CLI I/O와 분리된다.
    콜백이 있으면 그대로 위임한다 — 콜백은 실제 사용자 입력을 받았으면 via="user",
    스스로 비대화형이라 판단해 기본값을 썼으면 via="default"를 돌려줘야 한다(계약)."""
    if prompt is None:
        return policy.DEFAULT_WHEN_NONINTERACTIVE, "default"
    return prompt(result, policy)


def run(
    target: Path,
    argv: list[str],
    *,
    prompt: PromptFn | None = None,
    launcher: Launcher | None = None,
    policy=config,
) -> PreflightResult:
    """L1(spawn_suspended) -> [1..4] 판정 -> findings 없으면 resume, 있으면 prompt로 확인 후
    resume/terminate. try/finally의 disposed 플래그로 "정지된 채 미처분" 상태를 항상 막는다.
    _analyze *와* _ask(프롬프트 콜백) 중 발생한 예외 모두 fail-safe로 포섭:
    policy.FAIL_OPEN_ON_ERROR(기본 False)에 따라 terminate/resume."""
    launcher = launcher or WinLauncher()  # 지연 생성 — import 시점에 WinLauncher를 만들지 않는다.
    target = Path(target)
    result = PreflightResult(exe_path=target)
    proc = launcher.spawn_suspended(target, argv)
    disposed = False

    try:
        try:
            result.predictions, result.findings = _analyze(target, policy)
            needs_prompt = bool(result.findings)
            if needs_prompt:
                allowed, via = _ask(prompt, result, policy)
        except Exception:
            # _analyze든 _ask(프롬프트 콜백)든, 판정 단계 어디서 터졌든 동일하게 fail-safe.
            if policy.FAIL_OPEN_ON_ERROR:
                launcher.resume(proc)
                disposed = True
                result.decision = "allowed_on_error"
            else:
                launcher.terminate(proc)
                disposed = True
                result.decision = "blocked_on_error"
            result.decided_by = "fail_open"
        else:
            if not needs_prompt:
                launcher.resume(proc)
                disposed = True
                result.decision = "no_risk"  # 물어볼 필요가 없었으므로 decided_by는 None 그대로.
            elif allowed:
                launcher.resume(proc)
                disposed = True
                result.decision = "allowed"
                result.decided_by = via
            else:
                launcher.terminate(proc)
                disposed = True
                result.decision = "aborted"
                result.decided_by = via
    finally:
        if not disposed:
            launcher.terminate(proc)

    if result.decision in _RESUMED_DECISIONS:
        result.exit_code = launcher.wait_and_get_exit_code(proc)
    return result
