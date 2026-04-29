<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../workflow.md
Review status: draft
-->

# 작업 흐름

## 엔드 투 엔드 라이프 사이클
- 개발은 로컬 코딩 + 실시간 UI 미리보기를 위한 로컬 데이터 인구로 시작합니다.
- PR CI는 품질/보안 및 기술 테스트 제품군을 검증합니다.
- PR Pages-verify는 출판하지 않고 생산 빌드 / 서명 동작을 검증합니다.
- Tag-driven release 워크플로우 패키지 및 표지 기술 artifacts.
- 페이지 배치 작업 흐름 미러 출시 / 자문 artifacts 및 정적 사이트 게시.
- Wiki-sync 워크플로우는 `wiki/` docs를 `main`에 게시합니다.
- 지속적으로 Enrich 자문 피드 및 공급망 가시성을 계획했습니다.

## 일류 지도
| 워크 플로우 | 트리거 | 메인 스테이지 |
인포메이션
| CI | PR/push to `main` | Lint, typecheck, build, Python checks, 보안 검사, 기술 테스트. ·
· 페이지 Verify | PR to `main` | 페이지 작성 및 유효성 표시 출력 (포토 없음). ·
| Poll NVD CVEs | 일일 크론 + 수동 파견 | Fetch CVE, transform/dedupe, update feed, sign artifact, PR changes. ·
| Process Community Advisory | 이슈 라벨 `advisory-approved` | 파스 이슈 양식, 자문, 서명 피드, 열린 PR, 코멘트 발행. ·
| 기술 자료 | 기술 태그 + 메타데이터 PR 변경 | PR: version-parity + Dry-run checks; 태그: 패키지/sign/publish release Asset. ·
| 배포 페이지 | 성공적인 CI/리엘리스 또는 수동 파견 | 출시, 미러 자산, 서명 공개 자문/체크섬, 배포 사이트. ·
| Sync Wiki | `main` 터치 `wiki/**` + 수동 파견 | `wiki/`를 `<repo>.wiki.git`로 동기화하고 `Home.md`를 `INDEX.md`로 생성합니다. ·

## 로컬 연산자 Workflow
| 단계 | 명령 | 결과 |
인포메이션
| 설치 deps | `npm install` | 현지 환경 ·
| 현지 카탈로그 | `./scripts/populate-local-skills.sh` | `public/skills/index.json` 및 파일 체크섬. ·
| 현지 피드를 Populate | `./scripts/populate-local-feed.sh --days 120` | 현지 대리점의 공급 사본을 업데이트했습니다. ·
| wiki llms 수출 | `npm run gen:wiki-llms` | 업데이트 `public/wiki/llms.txt` 및 페이지 수출. ·
| 런 로컬 게이트 | `./scripts/prepare-to-push.sh` | CI-like pass/fail 신호. ·
| start dev UI | `npm run dev` | 현지 Vite 엔드포인트의 브라우저 미리보기. ·

# # # # # # # # # # 공지사항
- 버전 범프 및 문서 패성은 PR / 태그 경로에 적용됩니다.
- 기술 포장에는 SBOM-declared 파일과 무결성가 나타납니다.
- `checksums.json`는 워크플로우 실행에서 즉시 확인됩니다.
- 선택된 게시-to-ClawHub 작업은 구성될 때 성공적인 GitHub 릴리스 후 실행됩니다.
- 같은 주요 라인 내의 이전 릴리스는 자동화에 의해 superseded/deleted 수 있습니다.

## 자문 작업 흐름 세부
- NVD 워크플로는 이전 피드 `updated` 타임스탬프에서 증가된 창을 결정합니다.
- 변형 단계지도 CVE 메트릭은 severity/type에 따라 영향을 받는 표적을 정상화합니다.
- 커뮤니티 자문 워크플로는 문제 메타데이터에서 deterministic ID (`CLAW-YYYY-NNNN`)를 생성합니다.
- 두 권의 워크플로우 업데이트 기술 피드 복사 및 서명 동반자.

## 예제 Snippets
```bash
# manual release prep for a skill
./scripts/release-skill.sh clawsec-feed 0.0.5
# then push tag if running in release branch mode
```

```yaml
# pages deploy depends on successful upstream workflow run
on:
  workflow_run:
    workflows: ["CI", "Skill Release"]
    types: [completed]
```

## 운영 위험
- Workflow 권한 및 비밀 범위 misconfiguration는 signing/publishing을 차단할 수 있습니다.
- NVD/API 일시적인 실패는 자문 신선도를 지연할 수 있습니다.
- 잘못된 태그 naming 또는 버전 mismatches halt 릴리스 자동화.
- 로컬 스크립트 및 CI는 연산자 기계가 예상되는 binaries (`jq`, `openssl`, `clawhub`)가 부족한 경우 다이브레이터 할 수 있습니다.

## 소스 참조
- 스크립트/출시-skill.sh
- 스크립트/prepare-to-push.sh
- 스크립트/populate-local-feed.sh
- 스크립트/populate-local-skills.sh
- 스크립트/generate-wiki-llms.mjs
- .github/workflows/ci.yml의 경우
- .github/workflows/poll-nvd-cves.yml의 경우
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml의 경우
- .github/workflows/deploy-pages.yml의 경우
- .github/workflows/페이지-verify.yml
- .github/workflows/wiki-sync.yml의 경우
- .github/workflows/codeql.yml의
- .github/workflows/scorecard.yml의 경우
- .github/actions/sign-and-verify/action.yml
