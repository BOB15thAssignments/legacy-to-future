# 개요

본 디렉토리는 취약한 dll(혹은 sys)와 함수 정보를 추출하여 DB를 구축하는 로직을 구현한 디렉토리입니다.

* **취약점 추적 자동화:** 알려진 취약점(CVE)과 연관된 모듈 및 내부 함수(Offset) 매핑 정보 제공
* **분석 효율성 증대:** 바이너리 분석 및 익스플로잇(Exploit) 연구 시, 타겟 모듈의 취약 함수 존재 여부를 즉각적으로 식별할 수 있는 참조 데이터 제공
* **보안 검증:** 시스템 환경 내 구버전 및 취약 모듈 식별을 위한 기반 데이터 활용

## DB 구조 및 스키마

### 1) DB 구조 (Architecture)

본 데이터베이스는 관계형 데이터베이스(RDBMS)를 기반으로 구축되었으며, 모듈(DLL/SYS)의 메타데이터를 저장하는 테이블과 해당 모듈 내 존재하는 취약 함수 정보를 담은 테이블이 **1:N 관계**로 매핑되어 있습니다.

### 2) DB 스키마 및 인스턴스 설명

#### Table 1. `vulnerable_modules` (취약 모듈 정보)

취약점이 발견된 대상 모듈(DLL/SYS)의 식별 정보와 버전, 관련 취약점(CVE) 정보를 관리합니다.

| Column | Type | PK/FK | Null | Description | Example Instance |
| --- | --- | --- | --- | --- | --- |
| `module_id` | INT | PK | N | 모듈 고유 식별자 (Auto Increment) | `1` |
| `module_name` | VARCHAR | - | N | 파일명 (확장자 포함) | `ntdll.dll` |
| `module_type` | VARCHAR | - | N | 모듈 타입 (`DLL` or `SYS`) | `DLL` |
| `version` | VARCHAR | - | Y | 취약점이 존재하는 파일 버전 | `10.0.19041.1` |
| `cve_id` | VARCHAR | - | Y | 연관된 CVE 번호 | `CVE-2026-XXXX` |

#### Table 2. `vulnerable_functions` (취약 함수 정보)

각 모듈 내에 존재하는 실제 취약한 함수의 이름, 오프셋(Offset) 및 취약성 설명을 관리합니다.

| Column | Type | PK/FK | Null | Description | Example Instance |
| --- | --- | --- | --- | --- | --- |
| `func_id` | INT | PK | N | 함수 고유 식별자 (Auto Increment) | `101` |
| `module_id` | INT | FK | N | 참조하는 모듈의 ID | `1` |
| `func_name` | VARCHAR | - | N | 취약점이 존재하는 함수명 | `RtlCopyMemory` |
| `offset` | VARCHAR | - | Y | 함수의 메모리 오프셋 주소 | `0x1A2B3C` |
| `description` | TEXT | - | Y | 버퍼 오버플로우 등 취약점 상세 설명 | `Buffer overflow in memcopy...` |

## 실행 방법 및 결과

### 1) 실행 방법 (How to Run)

본 로직은 Python 3 환경에서 작성되었으며, 대상 디렉토리를 인자로 전달하여 데이터베이스를 빌드합니다. 환경 구성 후 아래 명령어를 터미널에 입력하여 실행합니다.

```bash
# 1. 필요 패키지 설치
$ pip install -r requirements.txt

# 2. DB 구축 스크립트 실행 (예: ./samples 폴더 내 파일 분석)
$ python build_db.py --target ./samples --db_name vuln_info.db

```

### 2) 실행 결과 (Execution Results)

스크립트가 정상적으로 실행되면, 콘솔에 파싱 및 DB 삽입(Insert) 로그가 출력되며 `../DB` 경로에 `[vuln_info.db]` 파일이 생성됩니다.

```text
[+] Parsing DLL/SYS files from ./samples...
[INFO] Found 15 potential vulnerable modules.
[INFO] Extracting function headers and calculating offsets...
[+] Successfully inserted 15 modules into 'vulnerable_modules'.
[+] Successfully inserted 42 functions into 'vulnerable_functions'.
[+] DB Construction Completed: vuln_info.db

```

---

# 🇬🇧 English Summary

## Overview

This directory contains the logic for extracting information from vulnerable DLLs (or SYS files) and functions to construct a vulnerability database.

## Purpose of Database

Designed to systematically track and manage vulnerable dynamic link libraries and system drivers. It provides mapping between vulnerable modules and their functions (offsets) to enhance the efficiency of binary analysis and vulnerability research.

## DB Structure & Schema

A relational database architecture connecting modules (1) to their vulnerable functions (N).

* `vulnerable_modules`: Stores module metadata (e.g., `module_name`, `version`, `cve_id`).
* `vulnerable_functions`: Stores specific function data mapped to modules (e.g., `func_name`, `offset`, `description`).

## How to Run & Results

```bash
$ pip install -r requirements.txt
$ python build_db.py --target ./samples

```

**Result:** Parses the target binaries, outputs extraction logs to the console, and successfully generates a structured database file (`.db`) containing the parsed records.
