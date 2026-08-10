# shimforge

shimforge는 구형 Windows DLL과 호환 shim의 관찰 가능한 동작을 비교하는 검증 도구다. 가장 중요한 원칙은 **증거가 불완전하거나 모호하면 통과시키지 않는다**는 것이다.

이 도구의 PASS는 “설정한 시나리오와 계약이 관찰한 범위에서 모든 엄격한 검사를 통과했다”는 뜻이다. 실행하지 않은 입력이나 환경까지 두 DLL이 수학적으로 동일하다는 뜻은 아니다. 따라서 실제 승인용 시나리오는 지원하려는 입력, 오류 경로, 콜백, 동시성 조건을 모두 포함해야 한다.

## 검증 단계

L0는 측정 장치인 tap 자체를 먼저 검증한다.

1. `structural`: 원본과 tap의 PE machine, export 이름, ordinal, NONAME, code/data, forwarder를 정확히 비교한다.
2. `passthrough`: tap 없이 실행한 원본, 기록을 끈 tap, 기록을 켠 tap의 exit code, stdout/stderr 원시 바이트, 출력 파일을 비교한다.
3. `determinism`: 원본을 두 번 이상 기록하고, 계약으로 허용된 포인터 바이트 외에는 모든 값을 비교한다.
4. `coverage`: 계약의 모든 함수와 콜백, 필요한 호출 수와 입력 분류, 모든 in/out/return/last-error, 캡처 바이트의 완전성을 확인한다.
5. `noninterference`: 시간, 핸들, 메모리 측정이 존재하고 정해진 상한을 넘지 않는지 확인한다.

L2는 L0를 통과한 장치로 원본 DLL(A)과 shim(B)의 trace를 비교한다. L2의 A trace는 L0가 coverage와 결정성을 검사한 바로 그 파일이어야 한다. 두 trace는 서로 다른 실행파일 SHA-256에 묶여 있어야 하며, 계약·아키텍처·모듈·recorder 버전이 일치해야 한다.

## Fail-closed 규칙

다음 중 하나라도 발생하면 PASS가 아니다.

- 프로세스 timeout, 비정상 종료, stdout/stderr 제한 초과, 파일 관찰 오류
- trace의 잘린 JSON, 중복 키·순번, 누락되거나 중간에 나온 header/footer
- recorder runtime note, 부분 캡처, `n`과 실제 캡처 길이 불일치
- 계약에 선언된 인자, 반환값, last-error, 콜백 또는 필드 누락
- trace의 계약 SHA-256, 실행 대상 SHA-256, PID, `TAP_MAXCAP` 불일치
- 호출 또는 실제 비교 항목이 0개인 결과
- 두 L2 trace가 같은 실행 대상에 묶인 경우
- L2의 A trace·tap·계약·원본이 지정한 L0 PASS report와 정확히 묶이지 않은 경우
- 임의 마스크, 심볼 무시, 부동소수점 오차, 비교 개수 제한, 출력 정규화
- replay에서 호출·콜백 누락, 건너뜀, mismatch 또는 recorder 비활성

정상 trace는 recorder `0.3` 형식이며 마지막 줄에 payload 수, 그 앞의 정확한 byte 수, SHA-256을 가진 integrity footer가 있어야 한다. 이 footer는 정상적이고 quiescent한 종료에서만 기록된다.

```json
{"t":"end","records":40,"bytes":16384,"sha256":"<64 lowercase hex>"}
```

Recorder는 같은 디렉터리의 `.partial` 파일에 먼저 기록한다. 모든 write·flush·disk commit·close가 성공하고 어떤 기록 손실도 없을 때만 최종 경로로 원자적으로 승격한다.

## 사용법

저장소의 `src/verification` 디렉터리에서 실행한다.

```powershell
python -m shimforge oracle `
  --config shimforge/selftest/oracle.json `
  --report-out l0-report.json
```

L2 비교에는 trace뿐 아니라 실제로 실행한 두 DLL도 필요하다.

```powershell
python -m shimforge diff `
  --a old.jsonl --b shim.jsonl `
  --a-binary old.dll --b-binary shim.dll `
  --tap-binary tap.dll --l0-report l0-report.json `
  --contract contract.json
```

`old.jsonl`은 `l0-report.json`의 coverage 및 determinism trace SHA-256과 정확히 같아야 한다. Report가 묶은 verifier 소스, 계약, 원본, tap, 실행 앱 중 하나라도 바뀌면 L2는 시작하지 않는다. 양쪽 L2 trace도 계약의 모든 함수·콜백을 최소 횟수만큼 호출하고 각 입력 인자를 독립적으로 변화시켜야 한다.

Tap 생성에는 계약뿐 아니라 원본의 전체 PE export surface가 필요하다.

```powershell
python -m shimforge gentap `
  --contract contract.json --original-dll old.dll --out build/tap
```

기본 정책 파일은 계약에서 생성할 수 있다.

```powershell
python -m shimforge policy --contract contract.json --out policy.json
```

정책이 허용하는 자동 마스크는 구조체 안에 선언된 포인터 값 자체의 바이트뿐이다. 임의 범위 마스크, padding 마스크, ignored symbol, non-zero float epsilon은 승인 모드에서 거부한다. 기존 `oracle --write-policy` 옵션은 명령행 호환을 위해 남아 있지만 엄격 검증에서는 거부된다.

## 계약 작성 원칙

- 모든 export와 callback의 calling convention, 인자 방향, 타입, 반환값, last-error를 선언한다.
- pointer/blob은 null이 아닌 경우 캡처 길이를 항상 결정할 수 있어야 한다.
- 구조체의 크기, 필드 offset/size/type은 겹치지 않게 정확히 선언한다.
- `volatile` 필드와 unknown extent는 승인 계약에서 사용할 수 없다.
- 현재 bit-exact wire가 없는 `f32`/`f64`, data export, 원본 forwarder, pure-forward 계약은 승인할 수 없다.
- 원본의 named/NONAME export 전체가 계약에 이름·ordinal까지 정확히 포함되어야 한다.
- 정상, 경계, 오류 입력을 시나리오에 넣고 각 계약 심볼을 충분히 반복 호출한다.

예제는 `selftest/contract.json`과 `selftest/oracle.json`을 참고한다.

## 자체 검증

```powershell
python shimforge/selftest/run_selftest.py
python -m pytest shimforge/selftest/test_fail_closed.py -q
```

셀프테스트는 기본적으로 필수 toolchain이나 검사가 빠지면 실패한다. 제한적인 개발 환경에서만 `--allow-skip`을 사용할 수 있으며, 이 결과를 승인 증거로 사용하면 안 된다.

## 보안 경계

runner는 Windows Job Object, 단일 프로세스·메모리·출력 상한, 전용 TEMP/TMP, 제한된 환경과 PATH를 사용한다. 실행 파일은 반드시 `app_files`에 선언되어 SHA-256 검증 후 run directory에 복사된 파일이어야 한다. 하지만 이것은 완전한 보안 샌드박스가 아니며 네트워크와 임의 파일 접근을 차단하지 않는다. 출처를 신뢰할 수 없는 구형 실행파일은 네트워크와 중요 데이터가 분리된 일회용 VM 또는 Windows Sandbox 안에서 실행한다. Tap binary는 검증기의 신뢰 컴퓨팅 기반이므로 검토된 생성기/runtime에서 빌드한 것을 사용한다.
