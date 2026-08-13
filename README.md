# legacy-to-future

Windows 환경에서 실행 파일(PE)이 로드할 DLL/드라이버(SYS)를 실제 실행 전에 미리 예측하고, 알려진 CVE와 매칭된 취약 모듈·함수 DB(`DB/vuln_functions.db`)와 대조하여 취약한 버전이 로드될 것으로 판단되면 사용자에게 경고 후 실행 여부를 확인하는 "프리플라이트 게이트" 프로젝트입니다. `src/parse`가 PE 파일에서 DLL/함수/버전 정보를 추출하고, `src/database`가 이를 바탕으로 취약 모듈·함수 DB를 구축하며, `src/preflight`가 대상 exe의 의존성 로드 순서를 예측해 DB와 대조한 뒤 위험이 없으면 대상 프로세스를 그대로 실행(resume)하고 위험이 있으면 경고와 함께 차단 여부를 사용자에게 묻는 역할을 담당합니다.

## 빠른 실습

0. uv 설치방법
다음 [링크](https://docs.astral.sh/uv/getting-started/installation/#__tabbed_1_2) 참고

1. 의존성 설치 (uv 사용)

   ```powershell
   uv sync
   ```

2. 대상 exe에 대해 프리플라이트 검사 실행

   ```powershell
   uv run python -m preflight "C:\Windows\System32\notepad.exe"
   ```

   - 취약 DLL이 예측되지 않으면 "취약 DLL 없음" 메시지 후 대상 프로세스가 그대로 실행됩니다.
   - 취약 DLL이 예측되면 대상 DLL/CVE/근거/조언이 출력되고, 터미널이 대화형(tty)이면 `[y/N]`로 실행 여부를 물어봅니다.

3. 결과를 JSON으로 저장하고 싶다면

   ```powershell
   uv run python -m preflight "C:\Windows\System32\notepad.exe" --json report.json
   ```

4. (선택) 대상 프로그램에 인자를 함께 전달하려면 `--` 뒤에 붙입니다.

   ```powershell
   uv run python -m preflight "C:\path\to\target.exe" -- --target-arg value
   ```

5. gui 기능을 사용하기 위해서는

   ```powershell
   uv run preflight-gui
   ```