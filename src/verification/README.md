# 검증

교체 전 DLL과 호환 shim이 같은 동작을 보이는지 확인하는 코드를 관리한다. 현재 검증 도구는 `shimforge/`에 있다.

## 구성

- `shimforge/`: 계약, trace 정규화, 비교 및 명령행 도구
- `shimforge/runtime/`: 호출 기록과 replay 실행에 사용하는 C runtime
- `shimforge/selftest/`: 정상 shim과 결함을 심은 shim을 이용한 회귀 테스트
- `shimforge/SPEC.md`: 계약과 trace 형식의 내부 명세

## 실행 환경

Windows 환경을 기준으로 하며 Python, pytest, LIEF, clang이 필요하다. 네이티브 테스트는 x86과 x64 DLL을 직접 빌드한다.

저장소 루트에서 다음과 같이 실행한다.

```powershell
cd src/verification
python -m shimforge --help
python -m pytest shimforge/selftest -q
python shimforge/selftest/run_selftest.py
```

## 검증 흐름

1. 원본 DLL의 export와 계약을 대조한다.
2. 계약으로 recording tap을 생성한다.
3. tap의 구조, 투명성, 결정성, coverage와 실행 비용을 검사한다.
4. 원본 DLL과 shim의 trace를 비교한다.

PASS는 준비한 계약과 시나리오에서 필요한 증거가 모두 수집되고 차이가 없다는 뜻이다. 실행하지 않은 입력까지 호환된다는 의미는 아니므로 정상·경계·오류 경로를 시나리오에 포함해야 한다.

상세한 명령과 판정 규칙은 `shimforge/README.md`를 참고한다.
