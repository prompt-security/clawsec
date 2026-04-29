# Configuration (한국어)

## 범위
- Configuration은 프런트엔드 빌드 설정, 런타임 피드 경로, 워크플로우 트리거, 스킬 메타데이터 계약을 포함합니다.
- 런타임에 민감한 대부분의 제어는 `CLAWSEC_` 또는 `OPENCLAW_` 접두사를 가진 환경 변수를 사용합니다.
- 경로 정규화는 보안 민감 영역이며, 해석되지 않은 home-token literal을 의도적으로 거부합니다.

## 핵심 런타임 변수
| 변하기 쉬운 | 기본 | 이용 |
인포메이션
| `CLAWSEC_FEED_URL` | Hosted advisory URL | Suite hook 및 guarded installer의 피드 로딩 |
| `CLAWSEC_FEED_SIG_URL` | `<feed>.sig` | Detached signature 소스 |
| `CLAWSEC_FEED_CHECKSUMS_URL` | `checksums.json` near feed URL | 선택적 checksum-manifest 소스 |
| `CLAWSEC_FEED_PUBLIC_KEY` | Suite-local PEM file | 피드 서명 검증 |
| `CLAWSEC_ALLOW_UNSIGNED_FEED` | `0` | 임시 마이그레이션 bypass 플래그 |
| `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` | `1` | checksum-manifest 검증 활성화 |
| `CLAWSEC_HOOK_INTERVAL_SECONDS` | `300` | advisory hook 스캔 스로틀 |

## 경로 해석 규칙
| 규칙 | 행동 | 시행 위치 |
인포메이션
| `~` expansion | 감지된 홈 디렉터리로 해석 | suite/watchdog 스크립트의 공용 path 유틸리티 |
| `$HOME` / `${HOME}` expansion | 이스케이프되지 않은 경우 해석 | 동일 유틸리티 |
| Windows home tokens | `%USERPROFILE%`, `$env:USERPROFILE` 정규화 | 동일 유틸리티 |
| Escaped tokens (`\$HOME`) | 명시적 에러와 함께 거부 | 실수로 literal 디렉터리 생성 방지 |
| Invalid explicit path | 경고 후 기본 경로로 fallback 가능 | `resolveConfiguredPath` helpers |

## 프런트엔드 및 빌드 설정
- `vite.config.ts`는 포트(`3000`), 호스트(`0.0.0.0`), path alias(`@`)를 정의합니다.
- `index.html`은 Tailwind runtime config, 커스텀 폰트, 기본 색상 토큰을 제공합니다.
- `tsconfig.json`은 bundler 모듈 해석, `noEmit`, JSX runtime 설정을 사용합니다.
- `eslint.config.js`는 TS/React/hooks 및 스크립트 전용 lint 규칙을 적용합니다.

## 스킬 메타데이터 설정
| 필드 그룹 | 위치 | 기능 |
인포메이션
| Core skill identity | `skills/*/skill.json` | 이름/버전/작성자/라이선스/설명 메타데이터 |
| SBOM file list | `skill.json -> sbom.files` | 릴리스 필수 아티팩트 선언 |
| Platform metadata | `openclaw` or `nanoclaw` blocks | CLI 요구사항, 트리거, 플랫폼 capability 힌트 |
| Suite catalog metadata | `skills/clawsec-suite/skill.json -> catalog` | suite 멤버의 통합/기본/동의 동작 |

## 워크플로우 설정
- 스케줄 설정은 워크플로우의 `cron` 항목(`poll-nvd-cves`, `codeql`, `scorecard`)에 존재합니다.
- 릴리스 워크플로우는 `<skill>-v<semver>` 태그 패턴을 기대합니다.
- 배포 워크플로우는 성공한 CI/release `workflow_run` 이벤트와 수동 실행으로 트리거됩니다.
- composite signing action은 private key 입력이 필요하며, 서명 직후 검증을 수행합니다.

## 예시 스니펫
```bash
# run guarded install with explicit local signed feed paths
CLAWSEC_LOCAL_FEED="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json" \
CLAWSEC_LOCAL_FEED_SIG="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json.sig" \
CLAWSEC_FEED_PUBLIC_KEY="$HOME/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem" \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill clawtributor --dry-run
```

```json
{
  "name": "example-skill",
  "version": "1.2.3",
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Install docs" }
    ]
  }
}
```

## 운영 노트
- signing key는 리포지토리에 두지 말고 GitHub Secrets로만 주입하세요.
- 로컬 환경 변수 override에는 절대 경로나 이스케이프되지 않은 home 표현식을 권장합니다.
- unsigned feed 모드는 정상 운영이 아닌 임시 마이그레이션 지원으로 취급하세요.
- `SKILL.md` URL을 수정하면 broken artifact reference 방지를 위해 release-link validation을 재실행하세요.

## 소스 참조
- `vite.config.ts`
- `index.html`
- `tsconfig.json`
- `eslint.config.js`
- `skills/clawsec-suite/skill.json`
- `skills/clawsec-nanoclaw/skill.json`
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs`
- `skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `scripts/validate-release-links.sh`
- `.github/workflows/poll-nvd-cves.yml`
- `.github/workflows/skill-release.yml`
- `.github/actions/sign-and-verify/action.yml`
