"""정지 생성/재개/종료 — 정상 Win32 API만 사용, 후킹·주입 없음.

★ Windows 전용. CreateProcessW/ResumeThread/TerminateProcess/WaitForSingleObject/
GetExitCodeProcess는 전부 kernel32 API라 이 모듈의 실제 동작은 Windows에서만 가능하다.
비-Windows에서는 import 자체는 죽지 않도록 kernel32 로드를 함수 호출 시점까지 미루고,
호출 시에는 그대로 예외가 난다(가드하지 않음 — 애초에 이 환경에서 쓸 일이 없다).
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from subprocess import list2cmdline
from typing import Protocol

CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


@dataclass
class ProcHandle:
    hProcess: int
    hThread: int


# 핸들 소유권/정리 책임 (리뷰 메모 — 로직 변경 아님, Linux에서 실행 검증 불가하므로 문서화로 대체):
#   resume()은 CloseHandle을 하지 않는다 — 핸들 정리 책임을 뒤로 미룬다.
#   terminate()는 즉시 hThread/hProcess 둘 다 CloseHandle한다(§terminate 참고).
#   wait_and_get_exit_code()도 완료 후 hThread/hProcess 둘 다 CloseHandle한다(§wait_and_get_exit_code 참고).
#   호출자(pipeline.run)는 정지된 proc마다 resume/terminate 중 정확히 하나만 부르고,
#   resume을 불렀을 때만 이어서 wait_and_get_exit_code를 부른다(둘 다 부르는 경로 없음) —
#   따라서 어떤 proc이든 CloseHandle 경로가 정확히 한 번만 실행되고, 두 번 닫히거나
#   전혀 안 닫히는 경우가 없다.


@lru_cache(maxsize=1)
def _kernel32():
    """kernel32 함수를 지연 로드하고 argtypes/restype를 1회만 설정해 캐시한다(64비트 포인터
    잘림 방지). lru_cache라 이후 호출은 재설정 없이 캐시된 객체를 그대로 돌려준다."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    k32.CreateProcessW.restype = wintypes.BOOL

    k32.ResumeThread.argtypes = [wintypes.HANDLE]
    k32.ResumeThread.restype = wintypes.DWORD

    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL

    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD

    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL

    return k32


def spawn_suspended(exe_path: Path, args: list[str]) -> ProcHandle:
    """CreateProcessW(..., CREATE_SUSPENDED)로 대상을 정지 상태로 생성한다.
    ResumeThread 전까지 대상의 사용자 코드는 한 줄도 실행되지 않는다."""
    k32 = _kernel32()
    exe_path = Path(exe_path)

    # lpApplicationName=None + 전체 커맨드라인을 list2cmdline으로 조립(표준 인용 처리 재사용).
    cmdline = list2cmdline([str(exe_path), *args])
    cmdline_buf = ctypes.create_unicode_buffer(cmdline)  # CreateProcessW가 버퍼를 수정할 수 있어 mutable 버퍼 필요

    startup_info = _STARTUPINFOW()
    startup_info.cb = ctypes.sizeof(_STARTUPINFOW)
    proc_info = _PROCESS_INFORMATION()

    ok = k32.CreateProcessW(
        None, cmdline_buf, None, None, False, CREATE_SUSPENDED, None, None,
        ctypes.byref(startup_info), ctypes.byref(proc_info),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    return ProcHandle(hProcess=proc_info.hProcess, hThread=proc_info.hThread)


def resume(proc: ProcHandle) -> None:
    """ResumeThread — 사용자가 실행을 허용했을 때만 호출. 여기서 비로소 실제 로드·실행이 시작된다.
    CloseHandle은 여기서 하지 않는다 — 호출자가 이어서 wait_and_get_exit_code를 불러 정리한다
    (핸들 소유권 계약은 ProcHandle 옆 주석 참고)."""
    k32 = _kernel32()
    if k32.ResumeThread(proc.hThread) == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())


def terminate(proc: ProcHandle) -> None:
    """TerminateProcess — 사용자가 거부했거나 판정 중 예외 발생(fail-safe).
    성공/실패와 무관하게 두 핸들 모두 CloseHandle로 정리한다(핸들 누수 방지)."""
    k32 = _kernel32()
    try:
        if not k32.TerminateProcess(proc.hProcess, 1):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(proc.hThread)
        k32.CloseHandle(proc.hProcess)


def wait_and_get_exit_code(proc: ProcHandle) -> int:
    """resume() 이후에만 호출하는 동기 래퍼: 대상이 끝날 때까지 블로킹 대기 후
    종료코드를 그대로 얻는다. 완료 후 두 핸들을 CloseHandle로 정리한다."""
    k32 = _kernel32()
    try:
        result = k32.WaitForSingleObject(proc.hProcess, INFINITE)
        if result != WAIT_OBJECT_0:
            raise ctypes.WinError(ctypes.get_last_error())
        exit_code = wintypes.DWORD()
        if not k32.GetExitCodeProcess(proc.hProcess, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return exit_code.value
    finally:
        k32.CloseHandle(proc.hThread)
        k32.CloseHandle(proc.hProcess)


class Launcher(Protocol):
    """spawn_suspended/resume/terminate/wait_and_get_exit_code 4개로 구성된 프로토콜.
    pipeline은 이 프로토콜에만 의존한다 — Windows 없이 FakeLauncher로 게이트 로직을
    테스트하기 위한 경계."""

    def spawn_suspended(self, exe_path: Path, args: list[str]) -> ProcHandle: ...

    def resume(self, proc: ProcHandle) -> None: ...

    def terminate(self, proc: ProcHandle) -> None: ...

    def wait_and_get_exit_code(self, proc: ProcHandle) -> int: ...


class WinLauncher:
    """Launcher 프로토콜의 실제 구현. 이 파일의 기존 Win32 함수를 그대로 위임만 한다
    (내부 로직은 변경하지 않음 — 감싸기만)."""

    def spawn_suspended(self, exe_path: Path, args: list[str]) -> ProcHandle:
        return spawn_suspended(exe_path, args)

    def resume(self, proc: ProcHandle) -> None:
        resume(proc)

    def terminate(self, proc: ProcHandle) -> None:
        terminate(proc)

    def wait_and_get_exit_code(self, proc: ProcHandle) -> int:
        return wait_and_get_exit_code(proc)
