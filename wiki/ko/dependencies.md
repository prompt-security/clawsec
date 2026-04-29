<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../dependencies.md
Review status: draft
-->

# 통화

## 빌드 및 실행 시간
| 층 | 차종별 | 왜 존재 |
인포메이션
| 프론트엔드 런타임 | `react`, `react-dom`, `react-router-dom`, `lucide-react` | UI 렌더링, 라우팅, 상징. ·
인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 인포메이션 ·
| 툴링 구축 | `vite`, `@vitejs/plugin-react`, `typescript` | 빠른 TS/TSX 번들링 및 생산 빌드. ·
| Python 유틸리티 | stdlib + `ruff`/`bandit` 정책 `pyproject.toml` | 유효성 검사 및 정적 검사를 실행합니다. ·
· 쉘 오토메이션 | `bash`, `jq`, `curl`, `openssl`, `sha256sum`/`shasum` | 펌핑, 서명, 체크섬 생성, 릴리즈 체크. ·

## Dependency 세부사항
| 포장 | 버전 제약 | 범위 |
인포메이션
| `react` / `react-dom` | `^19.2.4` | 프론트엔드런타임 |
| `react-router-dom` | `^7.13.1` | 프론트 라우팅 |
| `lucide-react` | `^0.575.0` | UI 아이콘 세트 |
| `vite` | `^7.3.1` | 개발자 서버 + 빌드 |
| `typescript` | `~5.8.2` | 유형 검사 |
| `eslint` | `^9.39.2` | JS/TS 라이팅 |
| `@typescript-eslint/*` | `^8.55.0` / `^8.56.0` | TS lint 파서/루즈 |
| `fast-check` | `^4.5.3` | 속성/후자 스타일 테스트 |

| Override | Pinned Version | 직업 |
인포메이션
| `ajv` | `6.14.0` | 보안 및 호환성 안정화 ·
| `balanced-match` | `4.0.3` | 교통 취약점 제어 ·
| `brace-expansion` | `5.0.2` | 변속성 경화 ·
| `minimatch` | `10.2.1` | 세터미니즘 의존성 행동 ·

## 외부 서비스
| 서비스 | 이용 | 기능 |
인포메이션
| NVD API (`services.nvd.nist.gov`) | `poll-nvd-cves` 워크플로우 + 로컬 피드 스크립트 | 키워드/날짜 창에서 CVE를 풀 수 있습니다. ·
| GitHub API | Deploy/release 워크플로우 | 릴리스, 다운로드 자산, 게시 출력. ·
| GitHub Pages | 배포 워크플로우 | 정적 사이트와 미러링 아트ifacts. ·
| ClawHub CLI/registry | 스크립트 설치 + 옵션 게시 작업 | 설치 및 출판 기술. ·
| 옵션 로컬 SMTP/sendmail | `openclaw-audit-watchdog` 스크립트 | 이메일에 의한 감사보고서 전달 ·

## 개발 도구
인포메이션 | 인포메이션 | 커버리지 |
인포메이션
| ESLint | `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0` | 프론트엔드・스크립팅 ·
| TypeScript | `npx tsc --noEmit` | 실시간 TS 계약 확인 ·
| Ruff | `ruff check utils/` | 파이썬 스타일과 버그 패턴 체크. ·
| Bandit | `bandit -r utils/ -ll` | Python 보안 검사 ·
| Trivy | 워크플로우+옵션 로컬런 | FS/config 취약점 검사 ·
| 깁스 | `scripts/prepare-to-push.sh` 옵션 로컬 실행 | 푸시 하기 전에 비밀 누출 검출. ·

## 예제 Snippets
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.2.4",
    "react-router-dom": "^7.13.1"
  }
}
```

```toml
[tool.ruff]
target-version = "py310"
line-length = 120

[tool.bandit]
exclude_dirs = ["__pycache__", ".venv"]
skips = ["B101"]
```

## 호환성 주
- `date` 및 `stat` 사용의 Linux 차이를 위한 로컬 스크립트 계정.
- 일부 워크플로우/script는 OpenSSL 기능이 Ed25519 및 `pkeyutl -rawin`와 함께 사용됩니다.
- Windows 지원은 노드 기반 툴링에 가장 강합니다. POSIX 쉘 경로는 WSL/Git Bash가 필요할 수 있습니다.
- 급식 소비자는 마이그레이션 단계에 대한 호환성 우회를 포함, 그러나 서명된 형태는 예정된 꾸준한 국가입니다.

## 버전 노트
- 기술 출시 태그는 `<skill>-v<semver>`를 따르고 CI/deploy 자동화에 의해 파싱됩니다.
- PR 검증은 `skill.json`와 `SKILL.md` frontmatter 사이의 버전 패리티를 실행합니다.
- - - 공공 기술 지수는 UI 디스플레이에 대한 기술 당 최신 발견 된 버전을 유지합니다.
- 서명된 artifact는 (`checksums.json`) 방출 당 버전되고 파일 해시와 URL을 포함합니다.

## 소스 참조
- 패키지.json
- 패키지-lock.json
프로젝트
- eslint.config.js에
- tsconfig.json의
- 스크립트/prepare-to-push.sh
- 스크립트/populate-local-feed.sh
- 스크립트/populate-local-skills.sh
- .github/workflows/ci.yml의 경우
- .github/workflows/codeql.yml의
- .github/workflows/scorecard.yml의 경우
- .github/workflows/poll-nvd-cves.yml의 경우
- .github/workflows/deploy-pages.yml의 경우
- .github/workflows/skill-release.yml의 경우
