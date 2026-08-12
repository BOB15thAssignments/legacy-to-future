"""
build_vuln_db.py
--------------------
정적 취약점 DB 구축 스크립트.
- import_function: 공개 API 함수 (IAT 매칭 가능)
- version_only: 내부 구현 함수 (DLL 파일 버전 비교로만 판정)
"""

import sqlite3
from pathlib import Path

# 현재 파일 위치(src/database/)를 기준으로 최상위 프로젝트 폴더를 찾고, 'DB/vuln_functions.db' 경로 지정
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DB_DIR = ROOT_DIR / "DB"
DB_DIR.mkdir(parents=True, exist_ok=True)  # DB 폴더가 없으면 자동 생성
DB_PATH = DB_DIR / "vuln_functions.db"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id           TEXT PRIMARY KEY,
    library_name     TEXT NOT NULL,
    dll_names        TEXT,
    severity         TEXT,
    cvss_score       REAL,
    fixed_version    TEXT,
    description      TEXT,
    reference_url    TEXT,
    kev_listed       INTEGER DEFAULT 0,
    source           TEXT DEFAULT 'OSV',
    detection_method TEXT DEFAULT 'import_function',
        -- import_function : 공개 API 함수. IAT에서 함수명으로 직접 매칭 가능
        -- version_only    : 내부 구현 함수. IAT 매칭 불가 -> DLL 파일버전으로만 판정
    added_at         TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vulnerable_functions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    function_name   TEXT NOT NULL,
    is_public_api   INTEGER DEFAULT 1,  -- 0이면 내부함수(참고용으로만 저장, 매칭엔 안 씀)
    confidence      TEXT DEFAULT 'verified',
    FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    UNIQUE(cve_id, function_name)
);

CREATE INDEX IF NOT EXISTS idx_function_name ON vulnerable_functions(function_name);
CREATE INDEX IF NOT EXISTS idx_library_name  ON vulnerabilities(library_name);
CREATE INDEX IF NOT EXISTS idx_detection      ON vulnerabilities(detection_method);
"""

# 검증된 시드 데이터
VULNERABILITIES = [
    (
        "CVE-2022-37434", "zlib", "zlib1.dll,zlib.dll,libz.dll", "CRITICAL", 9.8,
        "1.2.12",
        "gzip 헤더 extra field 처리 중 inflateGetHeader() 사용 시 inflate()에서 힙 버퍼 오버플로우.",
        "https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1",
        0, "OSV+GitHub Commit", "import_function",
    ),
    (
        "CVE-2015-8126", "libpng", "libpng16.dll,libpng15.dll,libpng14.dll,libpng12.dll", "HIGH", 7.8,
        "1.6.19",
        "낮은 bit-depth 값의 IHDR 청크 처리 시 png_set_PLTE/png_get_PLTE의 팔레트 크기 계산 오류로 버퍼 오버플로우.",
        "https://bugzilla.redhat.com/show_bug.cgi?id=1281756",
        0, "OSV+RedHat", "import_function",
    ),
    (
        "CVE-2018-14618", "curl", "libcurl.dll", "CRITICAL", 9.8,
        "7.61.1",
        "NTLM 인증 중 Curl_ntlm_core_mk_nt_hash의 정수 오버플로우(32비트 size_t)로 힙 버퍼 오버플로우. 내부 함수라 export 안 됨.",
        "https://curl.se/docs/CVE-2018-14618.html",
        0, "OSV+Vendor Advisory", "version_only",
    ),
    (
        "CVE-2022-40303", "libxml2", "libxml2.dll", "HIGH", 7.5,
        "2.10.3",
        "XML_PARSE_HUGE 옵션 사용 시 xmlParseNameComplex 등에서 정수 오버플로우로 배열 음수 오프셋 접근. 내부 파서 함수.",
        "https://gitlab.gnome.org/GNOME/libxml2/-/commit/c846986356fc149915a74972bf198abc266bc2c0",
        0, "OSV+GitLab Commit", "version_only",
    ),
    (
        "CVE-2020-15999", "FreeType", "freetype.dll,freetype6.dll", "HIGH", 6.5,
        "2.10.4",
        "TTF/OTF 내 임베디드 PNG(sbix) 처리 중 Load_SBit_Png의 16비트 정수 절단으로 힙 버퍼 오버플로우. 실사용 익스플로잇 확인됨. 내부 함수.",
        "https://bugzilla.redhat.com/show_bug.cgi?id=1890210",
        1, "OSV+CISA KEV", "version_only",
    ),
    (
        "CVE-2014-0160", "OpenSSL", "ssleay32.dll,libeay32.dll,libssl-1_1.dll,libcrypto-1_1.dll", "CRITICAL", 7.5,
        "1.0.1g",
        "TLS/DTLS Heartbeat 확장의 payload 길이 필드 검증 누락으로 프로세스 메모리 유출(Heartbleed). tls1_process_heartbeat는 내부 함수.",
        "https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160",
        1, "OSV+CISA KEV", "version_only",
    ),
    (
        "CVE-2023-4863", "libwebp", "libwebp.dll,libwebpdecoder.dll", "CRITICAL", 10.0,
        "1.3.2",
        "WebP 무손실 디코딩 중 ReadHuffmanCodes/BuildHuffmanTable의 15비트 코드 처리 누락으로 힙 오버라이트. 실익스플로잇 확인됨. 내부 함수.",
        "https://github.com/advisories/GHSA-j7hp-h8jx-5ppr",
        1, "OSV+CISA KEV", "version_only",
    ),
    (
        "CVE-2022-23852", "expat", "libexpat.dll,libexpat-1.dll,expat.dll", "CRITICAL", 9.8,
        "2.4.4",
        "nonzero XML_CONTEXT_BYTES 설정 시 XML_GetBuffer에서 signed integer overflow. XML_GetBuffer는 expat.h에 선언된 공개 API.",
        "https://github.com/libexpat/libexpat/blob/master/expat/Changes",
        0, "libexpat official Changes", "import_function",
    ),
    (
        "CVE-2022-23990", "expat", "libexpat.dll,libexpat-1.dll,expat.dll", "CRITICAL", 9.8,
        "2.4.4",
        "doProlog의 정수 오버플로우로 인한 힙 버퍼 오버플로우/RCE 가능. 내부 함수(xmlparse.c).",
        "https://github.com/libexpat/libexpat/blob/master/expat/Changes",
        0, "libexpat official Changes", "version_only",
    ),
    (
        "CVE-2021-45960", "expat", "libexpat.dll,libexpat-1.dll,expat.dll", "HIGH", 7.5,
        "2.4.3",
        "storeAtts에서 29비트 이상 left shift로 realloc 오동작(할당 부족/과다 free). 내부 함수(xmlparse.c).",
        "https://github.com/libexpat/libexpat/blob/master/expat/Changes",
        0, "libexpat official Changes", "version_only",
    ),
    (
        "CVE-2022-25315", "expat", "libexpat.dll,libexpat-1.dll,expat.dll", "CRITICAL", 9.8,
        "2.4.5",
        "storeRawNames에서 m_buffer 확장 로직 악용으로 INT_MAX 근접 할당 및 힙 아웃오브바운드 쓰기. 내부 함수(xmlparse.c).",
        "https://explore.alas.aws.amazon.com/CVE-2022-25315.html",
        0, "libexpat official Changes", "version_only",
    ),
]

VULNERABLE_FUNCTIONS = [
    ("CVE-2014-0160", "tls1_process_heartbeat", 0, "verified"),
    ("CVE-2014-0160", "dtls1_process_heartbeat", 0, "verified"),
    ("CVE-2022-37434", "inflate", 1, "verified"),
    ("CVE-2022-37434", "inflateGetHeader", 1, "verified"),
    ("CVE-2015-8126", "png_set_PLTE", 1, "verified"),
    ("CVE-2015-8126", "png_get_PLTE", 1, "verified"),
    ("CVE-2018-14618", "Curl_ntlm_core_mk_nt_hash", 0, "verified"),
    ("CVE-2022-40303", "xmlParseNameComplex", 0, "verified"),
    ("CVE-2020-15999", "Load_SBit_Png", 0, "verified"),
    ("CVE-2023-4863", "BuildHuffmanTable", 0, "verified"),
    ("CVE-2023-4863", "ReadHuffmanCodes", 0, "verified"),
    ("CVE-2022-23852", "XML_GetBuffer", 1, "verified"),
    ("CVE-2022-23990", "doProlog", 0, "verified"),
    ("CVE-2021-45960", "storeAtts", 0, "verified"),
    ("CVE-2022-25315", "storeRawNames", 0, "verified"),
]


def build_db(db_path: Path = DB_PATH, reset: bool = True):
    if reset and db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    with conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO vulnerabilities
                (cve_id, library_name, dll_names, severity, cvss_score, fixed_version,
                 description, reference_url, kev_listed, source, detection_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            VULNERABILITIES,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO vulnerable_functions (cve_id, function_name, is_public_api, confidence)
            VALUES (?, ?, ?, ?)
            """,
            VULNERABLE_FUNCTIONS,
        )

    conn.close()
    print(f"[+] Database successfully built: {db_path}")


def sanity_report(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    print("\n=== import_function (IAT Matching Available) ===")
    for r in conn.execute(
        "SELECT v.cve_id, v.library_name, f.function_name FROM vulnerabilities v "
        "JOIN vulnerable_functions f ON f.cve_id=v.cve_id "
        "WHERE v.detection_method='import_function'"
    ):
        print(f"  {r['cve_id']:<20} {r['library_name']:<10} {r['function_name']}")

    print("\n=== version_only (DLL Version Comparison Only) ===")
    for r in conn.execute(
        "SELECT DISTINCT cve_id, library_name, fixed_version FROM vulnerabilities "
        "WHERE detection_method='version_only'"
    ):
        print(f"  {r['cve_id']:<20} {r['library_name']:<10} fixed >= {r['fixed_version']}")

    conn.close()


if __name__ == "__main__":
    build_db()
    sanity_report()
