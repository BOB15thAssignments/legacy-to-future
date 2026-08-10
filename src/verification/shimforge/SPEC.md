# shimforge 내부 인터페이스 명세

이 문서는 `tools/shimforge` 모듈 사이의 승인용 계약이다. 구현의 기본 원칙은 fail-closed다. 입력, 실행, 기록, 비교의 완전성을 증명하지 못하면 결과는 FAIL 또는 INCONCLUSIVE이며 PASS가 아니다.

## 1. 계약 모델 (`model.py`)

`Contract.load()`는 JSON 계약을 읽고 다음을 검증한다.

- module, arch, export name/ordinal/NONAME, calling convention의 유효성
- 구조체의 양수 크기, 고유 필드명, 범위, 비중첩, type별 자연 크기
- 함수 및 콜백 인자의 고유 이름, 방향, kind, extent 참조
- 모든 struct/callback/size-field 참조의 존재와 type 호환성
- pointer/blob의 결정 가능한 고정·인자·필드 기반 extent
- by-value 인자의 올바른 방향, fnptr의 callback 계약
- high-confidence 계약만 승인

Unknown extent와 volatile field는 거부한다. JSON은 모든 계층에서 중복 키, 알 수 없는 키, non-finite number, 타입 coercion을 거부한다. Raw IEEE bit 보존이 완성되지 않은 `f32`/`f64`도 거부한다. `Contract.fingerprint()`는 canonical JSON의 SHA-256을 반환한다.

## 2. 정책 (`policy.py`)

승인 정책의 고정값은 다음과 같다.

- `thread_mode = "global"`
- `float_eps = 0.0`
- `symbolize_pointers = true`
- `ignore_symbols = []`
- 비교 개수·callback depth 제한 없음

`Policy.derive(contract)`가 만들 수 있는 mask는 구조체 안에 명시된 포인터 필드의 raw address 바이트뿐이다. 임의 마스크와 padding/field 전체 마스크는 거부한다. `Policy.assert_safe(strict=True, contract=contract)`를 normalize나 diff 전에 호출해야 한다.

## 3. Trace 형식 (`trace.py`)

파일은 UTF-8 JSONL이다. JSON duplicate key, 잘린 줄, 비 UTF-8, 알 수 없는 key/type은 허용하지 않는다.

첫 줄 header의 허용 필드는 정확히 다음과 같다.

```json
{"t":"hdr","v":1,"module":"oldlib.dll","arch":"x64","pid":123,"run":"id","tap":"0.3","label":"case","maxcap":1048576,"contract":"<64 lowercase hex>","subject":"<64 lowercase hex>"}
```

- `tap`은 정확히 `0.3`이다.
- `contract`는 현재 `Contract.fingerprint()`와 같아야 한다.
- `subject`는 실제 실행 DLL의 SHA-256과 같아야 한다.
- `maxcap`은 verifier가 설정한 값과 같아야 한다.
- Oracle에서는 header PID가 실제 child PID와 같아야 한다.

호출은 `t="c"`, callback은 `t="k"`다. 순번은 유일하고 parent/depth/thread 관계가 유효해야 한다. 계약에 선언된 모든 in/out/ret/lasterr path와 kind가 정확히 존재해야 한다. 포인터 캡처는 null이 아닌 경우 `n == len(b)/2 == 계약으로 계산한 extent`여야 한다.

`t="n"` runtime note는 진단 정보이면서 승인 실패다. 정상 trace는 payload 뒤에 정확히 한 번, 파일의 마지막 줄로 다음 footer를 가져야 한다.

```json
{"t":"end","records":17,"bytes":4096,"sha256":"<64 lowercase hex>"}
```

- `records`는 header를 제외한 앞선 `c`/`k`/`n` 줄 수다.
- `bytes`는 footer 이전 원시 JSONL byte 수다.
- `sha256`은 footer 이전 원시 bytes 전체의 SHA-256이다. 각 원래 줄바꿈도 포함한다.
- footer 뒤에는 빈 줄을 포함한 어떤 byte도 올 수 없다.

Reader는 세 값을 원시 bytes에서 다시 계산한다. 본문 변경·삭제·순서 변경, 마지막 record 삭제, 잘못된 count/byte 수/hash는 모두 trace를 무효화한다.

`read_trace()`는 진단을 모으기 위해 format defect를 `Trace.validation_errors`에 보존한다. 소비자는 `Trace.valid`를 확인해야 하며, invalid trace를 normalize하여 PASS로 만들면 안 된다.

## 4. 정규화와 비교 (`normalize.py`, `tracediff.py`)

정규화 전에 계약 conformance와 strict policy를 검증한다. 주소 자체만 symbolic pointer로 바꾸며 캡처한 실제 바이트는 계약이 허용한 pointer-address 범위 외에 모두 비교한다.

`diff()`의 PASS 조건:

- 양쪽 trace가 완전하고 유효함
- header의 module, arch, contract, tap 등 comparable provenance가 같음
- L2에서는 subject hash가 서로 다름
- 호출 및 실제 비교 필드가 1개 이상임
- global 순서, callback parent/depth, symbol, 모든 값이 같음
- 비교 제한에 도달하지 않음

한 항목이라도 증명할 수 없으면 `ok=False`, `conclusive=False`다.

## 5. 실행기 (`runner.py`)

`run_once()`는 다음 증거를 보존한다.

- exit code, timeout, PID, wall time
- stdout/stderr 원시 bytes와 표시용 decode
- 출력 제한 초과 및 pipe capture 오류
- 관찰 디렉터리의 전후 파일 hash와 관찰 오류
- Windows resource sample 수, peak handles/private bytes

stdout/stderr 비교는 decoded 문자열이 아니라 원시 bytes로 한다. 각 stream은 유한 상한을 갖고 초과하면 실패한다. symlink, junction, reparse point가 관찰 범위에 있으면 실패한다.

Windows에서는 kill-on-close, active-process 1, job-memory 상한, UI 제한을 둔 Job Object에 child를 넣는다. 현재 sampler가 주 프로세스만 측정하므로 자식 프로세스로 작업·자원을 옮기는 우회를 허용하지 않는다. Job 할당 실패도 실행 실패다.

## 6. L0 Oracle (`oracle_check.py`)

Oracle은 모든 staged 입력을 copy 전·후와 destination에서 SHA-256으로 검증한다. 각 run은 별도 디렉터리와 TEMP/TMP를 사용하며, recorder 제어 환경변수는 상속하지 않고 verifier가 직접 설정한다.

필수 gate:

1. structural exact PE surface
2. no-tap baseline 대 passthrough tap 의미적 투명성
3. no-tap baseline 대 recording-enabled tap 의미적 투명성
4. 2회 이상의 healthy trace 결정성
5. trace/header/contract/capture 완전성
6. 계약의 모든 함수·callback에 대한 100% coverage, 최소 호출 수, 각 입력 인자별 독립적인 exact-value/captured-byte class
7. 측정 가능한 resource noninterference

Unknown config key, 출력 normalizer, 완화 threshold, 정책 자동 확장, 누락된 resource evidence는 거부한다. Scenario executable은 `app_files`에서 검증 복사한 단일 staged leaf여야 한다. PASS report schema는 `shimforge-oracle/2`이며 계약·원본·tap·실행 앱·정책·verifier 구현 파일과 설정 manifest의 SHA-256을 포함한다. 반환 직전에 다시 hash해 중간 변경을 탐지한다.

## 7. Tap runtime (`runtime/tr_record.*`, `gen_tap.py`)

생성 코드는 다음 초기화 형태를 사용한다.

```c
int tr_init(const wchar_t *path, const char *module, const char *arch,
            const char *label, const char *contract_hash);
```

고정 recorder 제어:

- `TAP_TRACE`
- `TAP_LABEL`
- `TAP_PASSTHROUGH=1`
- `TAP_MAXCAP`
- `TAP_SUBJECT_SHA256`

환경변수는 동적 wide string으로 읽고 길이·형식을 검증한다. subject는 정확한 64자리 hex만 허용한다. 실제 DLL은 tap과 같은 디렉터리의 계약된 sibling 경로에서만 안전한 `LoadLibraryExW` 옵션으로 로드한다. bare-name search fallback은 금지한다.

Recorder는 authoritative 경로와 같은 디렉터리의 고유 `.partial`에 기록한다. allocation, TLS, serialization, capture, write, flush, commit, close 중 하나라도 실패하면 sticky fault가 되고 integrity footer를 쓸 수 없다. 정상 process detach에서 quiescent하고 footer/flush/disk commit/close가 모두 성공한 파일만 원자적으로 최종 경로로 승격한다.

## 8. Replay (`gen_replay.py`, `runtime/replay_main.c`)

Replay는 계약과 trace를 모두 소비한다. 다음은 non-zero exit다.

- 호출 또는 callback을 재생하지 못함
- skip/drop/mismatch
- recorder 비활성 또는 trace 불완전

불완전 replay를 성공으로 바꾸는 환경변수 opt-out은 없다. Replay exit 0은 계획된 호출 실행이 완결됐다는 뜻일 뿐 동등성 PASS가 아니며, 생성 trace를 위의 strict L2 절차로 비교해야 한다.

## 9. CLI와 exit code

- `python -m shimforge oracle --config ...`: 모든 gate PASS일 때만 0
- `python -m shimforge diff --a ... --b ... --a-binary ... --b-binary ... --tap-binary ... --l0-report ... --contract ...`: L0가 승인한 정확한 A trace이고 양쪽 full coverage가 완전하며 차이가 없을 때만 0
- invalid configuration/policy/evidence, INCONCLUSIVE, divergence는 모두 non-zero

L2는 `shimforge-oracle/2` PASS report의 canonical manifest와 모든 artifact를 다시 hash한다. 계약·원본·tap이 CLI 파일과 같고 A trace hash가 L0 coverage 및 determinism 결과에 포함될 때만 비교한다. 이 결합은 L0를 건너뛰거나 다른 시나리오의 깨끗한 trace를 재사용하는 것을 막는다.

## 10. 보안 한계

Job Object는 자원·하위 프로세스 제어이지 완전한 sandbox가 아니다. verifier는 네트워크와 시스템 전체 파일 접근을 보안 경계로 차단하지 않는다. 신뢰할 수 없는 legacy binary는 격리된 일회용 Windows VM에서 실행해야 한다.
