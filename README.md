# legacy-to-future
이 프로젝트는 위험한 legacy DLL을 사용하는 실행파일을, 패치된 DLL을 통해 실행가능하도록 자동화 매핑 하네스를 개발합니다.

```sh
legacy-to-future/
├── README.md
└── src/                // 소스코드
    ├── database/       // 2. 취약한 DLL DB취합
    │   └── README.md
    ├── parse/          // 1. PE(EXE)파일 파싱
    │   └── README.md
    ├── patch/          // 3. DLL 매핑 래핑(혹은 다른 방식)
    │   └── README.md
    └── verification/   // 4. 로직 검증
        └── README.md
```
