#!/usr/bin/env python3
"""
check_driver_loldrivers.py — [부가] 드라이버(.sys)를 알려진 취약 드라이버 DB와 대조

파일 내용을 파싱하는 게 아니라 '지문(SHA256 해시)'으로 대조한다.
loldrivers.io는 악용 사례가 알려진 드라이버를 해시와 함께 정리해두는 공개 DB.

전체 흐름:
    check_driver()
      ├ calculate_sha256()      대상 .sys 파일의 해시 계산
      ├ load_driver_database()  DB 로드 (처음 한 번만 다운로드, 이후 캐시 재사용)
      └ find_matching_entry()   해시가 DB에 있는지 탐색

사용법:
    python3 check_driver_loldrivers.py /경로/대상.sys
"""
import os
import sys
import json
import hashlib
import urllib.request

DATABASE_URL = "https://www.loldrivers.io/api/drivers.json"
CACHE_FILE = "loldrivers_cache.json"
CHUNK_SIZE = 1024 * 1024   # 해시 계산 시 1MB씩 읽는다 (큰 파일도 메모리 부담 없이)


# ================================================================= 진입점

def check_driver(path):
    """드라이버 파일 하나를 DB와 대조한 결과를 dict로 반환."""
    file_hash = calculate_sha256(path)
    database = load_driver_database()

    matched = find_matching_entry(database, file_hash)
    if matched is None:
        return {"found": False, "sha256": file_hash}

    return {
        "found": True,
        "sha256": file_hash,
        "category": matched.get("Category"),      # vulnerable / malicious
        "tags": matched.get("Tags"),              # 알려진 파일명 등
        "resources": matched.get("Resources"),    # 근거 자료 링크
    }


# =============================================================== 해시 계산

def calculate_sha256(path):
    """파일을 조각내어 읽으며 SHA256 해시를 계산한다."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# ================================================================ DB 로드

def load_driver_database():
    """DB를 반환. 캐시가 있으면 그걸 쓰고, 없으면 받아서 캐시로 저장한다.

    (API 응답이 커서 매 실행마다 받으면 느리다 → 캐싱이 필수)
    """
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)

    print("드라이버 DB를 처음 내려받는 중… (다음 실행부터는 캐시 사용)", file=sys.stderr)
    with urllib.request.urlopen(DATABASE_URL) as response:
        database = json.load(response)

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(database, f)
    return database


# ================================================================ 해시 탐색

def find_matching_entry(database, file_hash):
    """해시가 일치하는 DB 항목을 찾아 반환. 없으면 None.

    DB 구조: 드라이버 항목 하나에 여러 개의 알려진 샘플(버전별 파일)이 들어있다.
    """
    target = file_hash.lower()
    for entry in database:
        for sample in entry.get("KnownVulnerableSamples", []):
            if sample.get("SHA256", "").lower() == target:
                return entry
    return None


# =============================================================== 화면 출력용

def print_result(result):
    if not result["found"]:
        print(f"일치 없음 — 알려진 취약 드라이버 목록에 없습니다")
        print(f"  SHA256: {result['sha256']}")
        return

    print(f"⚠ 일치 — 알려진 {result['category']} 드라이버입니다")
    print(f"  SHA256: {result['sha256']}")
    print(f"  태그  : {result['tags']}")
    print(f"  근거  : {result['resources']}")


def main():
    if len(sys.argv) != 2:
        print("사용법: python3 check_driver_loldrivers.py <드라이버.sys>", file=sys.stderr)
        sys.exit(1)

    print_result(check_driver(sys.argv[1]))


if __name__ == "__main__":
    main()

