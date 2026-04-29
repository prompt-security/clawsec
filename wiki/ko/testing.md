<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../testing.md
Review status: draft
-->

# 테스트

## 테스트 전략
- - - 저장소는 단일 루트 `npm test` 명령보다 오히려 계층화 된 검증을 사용합니다.
- 핵심 신뢰는 lint/type/build 문 플러스 기술 지방에서 옵니다 노드 테스트 스위트.
- Python 및 shell 툴링은 전용 lint/security 체크를 통해 검증됩니다.
- Workflow 파이프라인은 로컬 pre-push 자동화에서 사용되는 동일한 명령 클래스를 실행합니다.

## 검증 레이어
| 층 | 명령 | 범위 |
인포메이션
| 프론트엔드/정제 체크 | ESLint + `tsc --noEmit` + `npm run build` | TS/TSX 정정 및 구조의 viability. ·
| 스킬 유닛 테스트 | `node skills/<skill>/test/*.test.mjs` | 시그니처, 매칭, 억제, 설치 계약. ·
| Python 품질 | `ruff check utils/`, `bandit -r utils/ -ll` | 실용신안 및 보안 패턴 ·
| Shell/script 품질 | ShellCheck + 수동 스크립트 연기 실행 | 스크립트 위생 및 명령 견고함. ·
| CI 보안 검사 | Trivy, npm Audit, CodeQL, Scorecard | Dependency, config 및 공급망 보안 자세. ·
| Local pre-push security scan | `gitleaks detect`를 선택하여 `scripts/prepare-to-push.sh` | 푸시하기 전에 비밀 누출 검출. ·

## 기술 테스트 매트릭스
| 스킬 | 테스트 파일 | 1차 초점 |
인포메이션
| `clawsec-suite` | `feed_verification`, `guarded_install`, `path_resolution`, fuzz 테스트 | 시그니처 체크, 자문, 경로 안전, 매칭 내구성. ·
| `openclaw-audit-watchdog` | 억제 구성 및 렌더링 테스트 | Config 패싱, 억제 행동, 보고 포맷. ·
| `clawsec-clawhub-checker` | `reputation_check.test.mjs` | 입력 유효성 및 평판조절 행동 ·

## CI 워크 플로우 적용
| 워크 플로우 | 트리거 | 키 보조 ·
인포메이션
| `ci.yml` | `main` PR/push | Lint/type/build, Python 검사, 보안 검사, 기술 테스트. ·
| `codeql.yml` | PR/push/schedule | JS/TS 정적 보안 분석 ·
| `scorecard.yml` | 시간표/푸시 | 공급망 보고 및 SARIF 업로드. ·
| `skill-release.yml` | 태그 + PR | 버전 패리티 및 릴리스 artifact 검증. ·

## 로컬 테스트 명령
```bash
# baseline frontend + config checks
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

```bash
# representative skill tests
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
```

## 실패 패턴
- 시그니처/테스트 정착물은 예상된 파일이 불행히도 재화될 때 열쇠/payload mismatch에서 실패할 수 있습니다.
- Path-resolution 테스트 의도적으로 탈출 된 홈 토큰에 실패; 이 행동은 예상되고 보안 위험.
- `openclaw` 또는 `clawhub` binaries에 의존하는 로컬 스크립트는 해당 CLI가 복종되는 환경에서 실패할 수 있습니다.
- Deploy/release logic은 비밀이나 워크플로우 권한이 다를 경우 CI에서 실패하면서 로컬로 전달할 수 있습니다.

## 건의된 시험 순서
1. 가득 차있는 국부적으로 문을 위한 `./scripts/prepare-to-push.sh`를 실행하십시오.
2. 명세 직접 기술 로컬 테스트에 영향을 미칩니다.
3. 명세 피드 / 서명 변경을 위해, 스위트 검증 테스트를 실행 (`feed_verification`, `guarded_install`).
4. 명세 워크플로우 또는 릴리즈 변경을 위해 `scripts/validate-release-links.sh` 및 키 일관성 스크립트를 실행합니다.

## 업데이트 노트
- 2026-02-26 : `wiki/platform-verification.md` 체크리스트에 업데이트 된 소스 참조.

## 소스 참조
- 아젠츠.md
- 스크립트/prepare-to-push.sh
- 스크립트/validate-release-links.sh
- .github/workflows/ci.yml의 경우
- .github/workflows/codeql.yml의
- .github/workflows/scorecard.yml의 경우
- .github/workflows/skill-release.yml의 경우
- 기술/하프스위트/테스트/feed_verification.test.mjs
- 기술/클래스/테스트/guarded_install.test.mjs
- 기술/클래스/테스트/path_resolution.test.mjs
- 기술/openclaw-audit-watchdog/test/suppression_config.test.mjs
- 기술/클로슈-클로브 검사기/테스트/reputation_check.test.mjs
- 위키/platform-verification.md
