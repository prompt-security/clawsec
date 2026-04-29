<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../glossary.md
Review status: draft
-->

₢ 킹 회사 소개

> 핵심 용어: `clawsec-suite`

## 약관
| 용어 | 정의 |
인포메이션
| Advisory Feed | JSON 문서(`feed.json`)는 기술/플랫폼에 대한 보안 자문을 포함하고 있습니다. ·
| 액티베이터 | `skill@1.2.3`, 와일드카드 등의 스킬 셀렉터, 또는 일치 논리에 사용되는 범위. ·
| Guarded Install | 고문 경기시 명시적 확인이 필요한 2단계 설치 동작. ·
| SBOM 파일 | 포장 및 검증을 위해 사용되는 `skill.json`의 숙련도 목록. ·
| 시그니처 | Base64 시그니처 파일(`.sig`)는 서명된 페이로드에서 별도로 저장됩니다. ·
| Checksum Manifest | 파일 해시 맵(`checksums.json`)은 페이로드 무결성을 검증하는 데 사용됩니다. ·

## 기술 포장 기간
| 용어 | 정의 |
인포메이션
| 기술 태그 | Git 태그는 릴리스 자동화에 의해 사용되는 `<skill>-v<semver>`로 포맷되었습니다. ·
| Release Assets | GitHub 릴리스에 첨부된 파일(zip, `skill.json`, 체크섬, 서명) ·
| 카탈로그 인덱스 | `public/skills/index.json`, 웹 카탈로그에 의해 생성 된 목록. ·
| 임베디드 부품 | 또 다른 한 기술로부터의 기능 번들(예를 들어, 스위트에 임베디드) ·

## 자문 및 보안 약관
| 용어 | 정의 |
인포메이션
| Fail-Closed Verification | 시그니처 또는 체크섬 유효성 검사가 실패한 경우 급여를 거부합니다. ·
| 할당된 호환성 모드 | `CLAWSEC_ALLOW_UNSIGNED_FEED=1`를 통한 임시 우회 경로. ·
| Suppression Rule | `checkId` 및 `skill`와 일치하는 컨피케이트를 구성하여 알려진 발견을 억제합니다. ·
| 키 지문 | SHA-256 키 일관성 검사에 사용되는 DER-encoded 공공 키의 소화. ·

## 런타임 및 플랫폼 약관
| 용어 | 정의 |
인포메이션
| OpenClaw Hook | 런타임 이벤트 핸들러(`clawsec-advisory-guardian`) ·
| NanoClaw IPC | 자문을 위한 호스트/컨테이너 작업 교환, 서명 검증, 무결성 검사. ·
| Integrity Baseline | 보호된 파일용 hashes/snapshot를 저장했습니다. ·
| 해시체인 감사 로그 | 각 항목이 이전 해시에 따라 달라집니다. ·

## CI/CD 이용 약관
| 용어 | 정의 |
인포메이션
| Poll NVD CVEs Workflow | NVD CVEs를 고문으로 바꾸는 워크플로를 계획했습니다. ·
| Community Advisory Workflow | 승인된 커뮤니티 자문을 출판하는 이슈 라벨 트리거 워크. ·
| 스킬 릴리즈 워크플로 | 태그 트리거 포장/신호/신호 파이프라인 기술 ·
| 배포 페이지 워크플로우 | 사이트 자산과 미러링/사설물을 구축하는 워크플로우. ·

## 소스 참조
- 유형.ts
- 기술/하프스위트/skill.json
- 기술/하프-nanoclaw/skill.json
- 기술/클래스/scripts/guarded_skill_install.mjs
- 기술/하프스위트/훅/하프스위트 자문/lib/feed.mjs
- 기술/하프스위트/훅/하프스위트 자문/lib/suppression.mjs
- 기술/하프-nanoclaw/guardian/integrity-monitor.ts
- 스크립트/populate-local-feed.sh
- .github/workflows/poll-nvd-cves.yml의 경우
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml의 경우
- .github/workflows/deploy-pages.yml의 경우
