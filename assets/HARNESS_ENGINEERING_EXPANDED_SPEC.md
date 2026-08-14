# Legacy-to-Future 검증 하네스 구현 명세

> 이 문서는 Windows 레거시 EXE와 DLL을 정적으로 분석하고, 로컬 취약점 규칙에 근거해 판정하며, 제한된 검증 시나리오를 재현 가능하게 실행하는 도구의 구현 범위를 정의한다.
>
> 목표는 **판정 근거가 명확하고 테스트로 확인되는 완성형 도구**다.

---

## 0. 구현 원칙

AI 구현자는 현재 저장소를 먼저 조사한 뒤 기존 코드를 최대한 재사용한다.

1. 현재 브랜치의 사용자 파일과 기존 구현을 삭제하거나 되돌리지 않는다.
2. 실제로 동작하는 코드와 테스트만 추가한다.
3. `TODO`, 빈 함수, 단순 `pass`, 사용되지 않는 추상화, 중복 모듈을 만들지 않는다.
4. 실행하지 않은 검사를 PASS로 표시하지 않는다.
5. 불완전한 증거는 `UNKNOWN` 또는 `REJECTED`로 처리한다.
6. 정적 분석 결과와 실행 검증 결과를 구분한다.
7. 외부 바이너리를 자동 다운로드하거나 실행하지 않는다.
8. shell 문자열 조합 대신 구조화된 argv를 사용한다.
9. 테스트용 EXE와 DLL은 합성 fixture로 만들고 해시를 고정한다.
10. 네트워크나 관리자 권한이 필요한 기능은 구현 범위에 넣지 않는다.
11. 새 파일은 담당 기능과 테스트가 분명할 때만 만든다.
12. 하나의 모듈로 충분한 기능을 의미 없이 여러 파일로 분할하지 않는다.

---

## 1. 프로젝트 목표

도구 이름은 `legacy-future-harness`로 한다.

Windows EXE를 입력받아 다음 질문에 답해야 한다.

1. 입력 파일이 유효한 PE인가?
2. 어떤 DLL과 함수를 import하는가?
3. delay import와 ordinal import가 존재하는가?
4. 실행 파일과 같은 폴더에 어떤 DLL 후보가 존재하는가?
5. DLL의 아키텍처·버전·SHA-256은 무엇인가?
6. 로컬 SQLite DB의 취약 버전 및 함수 조건과 일치하는가?
7. 판정에 사용된 근거와 불확실성은 무엇인가?
8. 기본 정책에서 실행을 차단해야 하는가?
9. 원본 DLL과 비교 DLL의 export surface가 호환되는가?
10. 허용된 benign 시나리오가 두 번 동일하게 실행되는가?

---

## 2. 이번 구현 범위



- PE32/PE32+ 파싱
- x86/x64 아키텍처 판별
- regular/delay/ordinal import 분석
- export/forwarder/NONAME export 분석
- DLL 버전 리소스 및 해시 확인
- 제한된 DLL 탐색 순서 모델
- SQLite schema, migration, seed, validation
- DLL alias 및 취약 버전 범위 대조
- 함수 조건 ANY/ALL/NONE 판정
- 판정 신뢰도와 실행 결정
- JSON/CSV/HTML/SARIF 보고서
- strict/consumer-compatible surface 검사
- allowlist 기반 smoke 반복 실행
- 결과 결정성 비교
- contract/trace의 fail-closed 형식 검사
- 간단한 Tkinter GUI와 import smoke
- unit/integration/E2E/negative/regression 테스트
- 합성 PE/DLL fixture 생성 도구




## 3. 판정 모델

도구는 다음 상태를 사용한다.

- `VULNERABLE`: 지원 DB의 영향 버전 범위와 필수 함수 증거가 모두 일치
- `POTENTIALLY_VULNERABLE`: 일부 증거만 일치하거나 실행 경로 증거가 부족
- `NOT_AFFECTED`: 지원 규칙의 영향 범위 밖임이 확인됨
- `UNKNOWN`: 버전·DLL·DB·파싱 증거가 부족
- `SURFACE_READY`: 요청한 정적 surface 조건 통과
- `SMOKE_READY`: 허용된 benign 시나리오의 반복 실행이 동일
- `ORACLE_PASS`: 필요한 contract와 trace gate가 모두 충족된 경우에만 사용
- `REJECTED`: 입력 위변조, 정책 위반, timeout, trace 손상 등으로 검사 거부

상태의 의미를 확대 해석하지 않는다.

- `SURFACE_READY`는 취약점이 해결됐다는 뜻이 아니다.
- `SMOKE_READY`는 특정 입력의 반복 실행이 동일했다는 뜻이다.
- `NOT_AFFECTED`는 지원 DB 범위 안에서만 유효하다.
- `UNKNOWN`을 안전으로 표시하지 않는다.

기본 실행 결정은 다음과 같다.

| 판정 | 기본 결정 |
|---|---|
| VULNERABLE | BLOCK |
| POTENTIALLY_VULNERABLE | CONFIRM |
| UNKNOWN | BLOCK |
| NOT_AFFECTED | ALLOW |

---

## 4. 권장 구조

현재 저장소 구조를 우선하며, 필요한 경우 다음 정도의 src-layout을 사용한다.

```text
src/legacy_future_harness/
  __init__.py
  __main__.py
  cli.py
  config.py
  constants.py
  errors.py
  hashing.py
  models.py
  paths.py
  signatures.py
  versioning.py
  pe/
  database/
  detection/
  verification/
  scenarios/
  reporting/
  gui/

tests/
  conftest.py
  unit/
  integration/
  e2e/
  negative/
  regression/
  fixtures/

configs/
data/
tools/
```

파일 이름보다 책임 분리가 중요하다. 관련 코드가 작으면 같은 모듈에 유지한다.

---

## 5. PE 분석

### 5.1 기본 정보

EXE와 DLL에서 다음 정보를 수집한다.

- 절대 경로
- 파일 크기
- SHA-256
- PE32/PE32+
- machine과 x86/x64
- subsystem
- image base
- entry point RVA
- section 이름·RVA·크기·권한
- timestamp(신뢰 가능한 빌드 시각으로 간주하지 않음)
- ASLR, DEP/NX, CFG, high-entropy VA
- debug directory 존재 여부
- 서명 테이블 존재 여부
- 버전 리소스 문자열

Authenticode 체인 전체 검증을 구현하지 않았다면 `VALID`로 표시하지 않는다.

### 5.2 import

- regular IAT import
- delay-load import
- 함수명 import
- ordinal import
- 원본 순서와 중복 제거 결과
- DLL 이름 정규화
- `LoadLibrary`, `LoadLibraryEx`, `GetProcAddress` 문자열 힌트

문자열 힌트는 실제 동적 호출 증거가 아니므로 낮은 신뢰도로 분리한다.

### 5.3 export

- name
- ordinal
- RVA
- forwarder
- NONAME
- code/data 구분이 가능한 경우 그 근거

손상된 RVA나 export directory는 빈 결과로 숨기지 말고 명시적인 파싱 오류로 처리한다.

### 5.4 DLL 후보 탐색

기본 탐색 모델은 다음 순서를 사용한다.

1. EXE가 위치한 디렉터리
2. 명시적으로 허용한 추가 디렉터리
3. System32

각 후보에 대해 존재 여부와 선택 이유를 기록한다. 실제 Windows loader를 완전히 모사한다고 주장하지 않는다.

---

## 6. 취약점 데이터베이스

SQLite DB에 최소한 다음 개념을 표현한다.

- schema version
- product
- DLL alias
- vulnerability/CVE
- affected version range
- ABI branch별 first fixed version
- function condition
- reference URL
- scan history

### 6.1 migration

- 빈 DB에서 최신 schema 생성
- 기존 legacy schema upgrade
- migration 재실행 idempotency
- transaction 실패 시 rollback
- schema version 기록

### 6.2 버전 범위

단일 `fixed_version` 문자열만으로 모든 ABI branch를 처리하지 않는다.

- introduced version
- last affected version
- first fixed version
- 포함/제외 경계
- 1.2.x, 1.6.x와 같은 branch
- Windows 4-part version
- 접미사 버전 비교

### 6.3 함수 조건

- `ANY`: 하나 이상 일치
- `ALL`: 모두 일치
- `NONE`: 지정 함수가 없어야 함
- regular import와 delay import 구분
- ordinal 조건 지원
- dynamic hint는 정적 import와 동일한 증거로 취급하지 않음

### 6.4 DB validation

다음을 오류로 처리한다.

- 중복 alias 충돌
- 잘못된 버전 범위
- branch와 맞지 않는 fixed version
- 존재하지 않는 CVE 참조
- 비어 있는 함수 조건
- schema version 불일치

---

## 7. 탐지와 의사결정

finding에는 다음 근거를 포함한다.

- EXE 경로와 SHA-256
- 선택 DLL 경로와 SHA-256
- DLL 버전과 버전 출처
- rule ID와 CVE ID
- 일치한 alias
- 일치한 함수
- import 종류
- 버전 비교 결과
- confidence
- 오탐 가능성 설명
- 권장 최소 안전 버전

판정 우선순위:

1. PE 파싱 실패 → `UNKNOWN`
2. 필요한 DLL 부재 → `UNKNOWN`
3. 아키텍처 불일치 → `REJECTED`
4. 영향 버전과 필수 함수 증거 일치 → `VULNERABLE`
5. 버전 또는 함수 증거 일부 부족 → `POTENTIALLY_VULNERABLE`
6. 지원 규칙에서 영향 범위 밖 → `NOT_AFFECTED`

정적 import는 실제 취약 호출 경로 실행을 증명하지 않는다는 설명을 항상 포함한다.

---

## 8. Surface 검사

원본 DLL, 비교 DLL, consumer EXE를 입력으로 받는다.

비교 항목:

- architecture
- named export
- ordinal export
- NONAME export
- forwarder
- consumer가 실제 요구하는 import subset
- 추가·누락·변경 export

모드:

- `strict`: 전체 export surface 비교
- `consumer-compatible`: consumer가 요구하는 surface 중심
- `report-only`: 차이를 기록하되 준비 상태로 승격하지 않음

결과에는 비교 대상 해시와 모든 차이를 포함한다.

---

## 9. 제한된 Smoke 실행

smoke는 임의 명령 실행기가 아니다.

JSON manifest 필수 항목:

- scenario ID
- EXE 상대 경로와 SHA-256
- 필요한 DLL 상대 경로와 SHA-256
- fixture 상대 경로와 SHA-256
- argv 배열
- timeout
- 최대 stdout/stderr 크기
- 허용 output 파일
- 예상 exit code
- 반복 횟수

보안 규칙:

- shell 문자열 금지
- 절대 경로와 `..` traversal 거부
- symlink/junction/reparse point 거부
- allowlist에 없는 scenario ID 거부
- 실행마다 빈 임시 디렉터리 사용
- 제한된 환경 변수만 전달
- timeout 시 프로세스 트리 종료
- capture 오류는 실패

결정성 비교:

- exit code
- stdout bytes
- stderr bytes
- output 파일 목록
- output SHA-256
- timeout/output-limit 상태

PID, 임시 경로처럼 명백한 변동값은 명시적 normalizer가 있을 때만 정규화한다.

---

## 10. Contract와 Trace 형식 검사

이번 단계에서는 Python 기반 fail-closed 검사를 구현한다.

- JSON duplicate key 거부
- 알 수 없는 contract field 거부
- module/architecture 확인
- export name/ordinal 확인
- calling convention과 지원 type 확인
- trace header/footer 확인
- contract fingerprint 확인
- subject SHA-256 확인
- record count와 byte count 확인
- footer 누락·부분 기록·손상 trace 거부
- 필요한 evidence가 없으면 `ORACLE_PASS` 금지

native shim을 생성·컴파일하거나 전체 export driver를 만드는 기능은 포함하지 않는다.

---

## 11. 보고서

### Console

- 입력 파일
- DLL
- CVE
- verdict
- decision
- 주요 근거
- 경고와 제한사항

### JSON

- schema version
- tool version
- 시작/종료 시각
- config fingerprint
- PE 결과
- DLL 후보
- finding과 evidence
- partial/errors/warnings

### CSV

finding 한 개를 한 행으로 표현한다.

### HTML

- 외부 CDN 없는 단일 파일
- 판정 요약
- EXE/DLL/CVE 표
- 근거와 제한사항
- print CSS

### SARIF

CI 연동을 직접 구현하지 않더라도 SARIF 2.1.0 호환 최소 결과를 생성한다.

---

## 12. CLI

최소 명령:

```text
legacy-future-harness scan <exe>
legacy-future-harness scan-dir <directory>
legacy-future-harness batch --manifest <json>
legacy-future-harness resolve <exe>
legacy-future-harness surface --original <dll> --dll <dll> --consumers <exe...>
legacy-future-harness smoke --scenario <json>
legacy-future-harness oracle --config <json>
legacy-future-harness diff --a <trace> --b <trace>
legacy-future-harness db validate
legacy-future-harness db migrate
legacy-future-harness db list
legacy-future-harness report --input <json> --format <format>
legacy-future-harness gui
legacy-future-harness doctor
legacy-future-harness version
```

공통 옵션:

- `--config`
- `--db`
- `--output`
- `--format console|json|csv|html|sarif`
- `--strict`
- `--offline`
- `--verbose`
- `--no-color`

모든 하위 명령은 `--help`에서 종료 코드 0을 반환해야 한다.

---

## 13. GUI

표준 Tkinter로 간단한 인터페이스를 제공한다.

- EXE 선택
- 폴더 스캔
- 진행 상태
- DLL/CVE 결과
- verdict와 decision
- JSON/CSV/HTML 내보내기
- 로그 표시
- 설정 경로 저장

GUI는 선택한 레거시 EXE를 자동 실행하지 않는다. 자동화 테스트 범위는 import와 기본 객체 생성 smoke까지로 제한한다.

---

## 14. 설정과 경로 안전성

설정은 JSON으로 관리한다.

- DB 경로
- DLL 탐색 디렉터리
- fail-closed 여부
- output 디렉터리
- timeout
- 최대 출력 크기
- 최대 메모리
- 반복 횟수
- surface 모드
- allowlisted scenario ID

요구사항:

- 알 수 없는 key 거부
- duplicate key 거부
- 타입과 범위 검증
- config fingerprint 생성
- 경로 traversal 거부
- 사용자 입력 경로를 shell에 연결하지 않음

---

## 15. 테스트

테스트는 기능별로 작성하고 fixture에 의존하는 조건을 명시한다.

### Unit

- 버전 비교와 branch 구분
- hash streaming
- 안전한 상대 경로
- 설정 duplicate/unknown key
- DB migration/idempotency/rollback
- alias 충돌
- 함수 ANY/ALL/NONE
- verdict와 exit code
- report schema
- normalizer
- PE32/PE32+ 및 x86/x64
- delay/ordinal import
- forwarder/NONAME export
- 손상 PE와 잘못된 RVA
- 한글과 공백이 포함된 경로

### Integration

- EXE → DLL 후보 → DB → finding → JSON
- 영향 버전 fixture
- 안전 버전 fixture
- 아키텍처 불일치
- strict/consumer-compatible surface
- allowlisted smoke 2회
- timeout과 output limit

### E2E

- CLI `--help`
- `version`
- `doctor`
- 모든 subcommand help
- fixture scan과 JSON 출력
- HTML 보고서
- GUI import smoke

### Negative

- EXE/DLL/fixture hash 불일치
- traversal
- allowlist 위반
- timeout
- output flood
- 비결정적 출력
- 손상 contract/trace
- footer 누락
- evidence 없는 Oracle PASS 거부

### Regression

- 파일 버전 문자열이 인접하지 않은 경우 ProductVersion fallback
- 발견된 버전/경로/파서 회귀는 최소 fixture로 고정

테스트는 네트워크와 관리자 권한 없이 실행돼야 한다.

---

## 16. Fixture

테스트용 PE/DLL은 재현 가능한 도구로 생성한다.

필요 fixture:

- x64 sample EXE
- x86 sample EXE
- delay import EXE
- vulnerable-version zlib DLL
- compatible comparison DLL
- deterministic benign EXE
- timeout EXE
- output flood EXE
- nondeterministic EXE
- unexpected-output EXE

fixture는 외부 프로그램을 복제하지 않고 테스트에 필요한 최소 PE 구조만 포함한다.

---

## 17. 생성할 실행 증거

구현 후 다음 artifact를 남긴다.

- sample scan JSON
- surface JSON
- smoke JSON
- HTML report sample
- pytest cache 또는 명시적 테스트 결과 요약

artifact에는 실제 실행 결과만 기록한다. 샘플 값을 미리 작성하거나 PASS를 하드코딩하지 않는다.

---

## 18. 완료 조건

- [ ] 기존 코드 조사 및 재사용
- [ ] src-layout import 성공
- [ ] PE32/PE32+와 x86/x64 분석
- [ ] regular/delay/ordinal import 분석
- [ ] export/forwarder/NONAME 분석
- [ ] DLL SHA-256과 버전 분석
- [ ] SQLite migration과 validation
- [ ] branch-aware 버전 비교
- [ ] ANY/ALL/NONE 함수 조건
- [ ] 취약 fixture `VULNERABLE/BLOCK`
- [ ] 안전 fixture `NOT_AFFECTED`
- [ ] unknown 입력 fail-closed
- [ ] JSON/CSV/HTML/SARIF 보고서
- [ ] strict/consumer-compatible surface
- [ ] allowlisted smoke 2회 결정성
- [ ] timeout/output flood/hash tampering 거부
- [ ] contract/trace fail-closed 검사
- [ ] CLI help/version/doctor
- [ ] GUI import smoke
- [ ] unit/integration/E2E/negative/regression 테스트
- [ ] 실행 artifact 생성
- [ ] 미검증 기능을 PASS로 표시하지 않음

---

## 19. 구현 순서

1. 저장소와 기존 브랜치 조사
2. 공통 모델·오류·경로·해시·버전
3. PE 파서와 fixture 생성
4. DB schema·migration·repository
5. 탐지·근거·의사결정
6. CLI scan/resolve/db
7. 보고서
8. surface
9. smoke와 결정성
10. contract/trace fail-closed 검사
11. GUI import 가능한 최소 구현
12. 테스트와 오류 수정
13. artifact와 최종 결과 정리

각 단계는 관련 테스트가 통과한 뒤 다음 단계로 진행한다.

---

## 20. 최종 보고 형식

작업 종료 시 다음을 간결하게 보고한다.

```text
구현된 기능
실행한 명령
테스트 기록
생성된 artifact
확인된 취약 fixture 결과
surface/smoke 결과
실행하지 않은 항목
현재 제한사항
```

판정 근거, 재현 가능한 실행 결과, fail-closed 동작, 테스트 추적 가능성을 완료 기준으로 한다.
