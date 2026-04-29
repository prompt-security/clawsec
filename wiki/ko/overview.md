# Overview (한국어)

## 목적
- ClawSec은 OpenClaw 및 NanoClaw 환경을 위한 공개 웹 카탈로그와 설치형 보안 스킬을 결합한 보안 중심 저장소입니다.
- 정적 사이트 배포, 서명된 advisory 배포, clawsec-suite 같은 스킬 단위 GitHub 릴리스 패키징을 동시에 지원합니다.

## 저장소 구성
| 경로 | 역할 | 비고 |
인포메이션
| `pages/`, `components/`, `App.tsx`, `index.tsx` | Vite + React UI | 스킬 카탈로그, advisory 피드, 상세 페이지 |
| `skills/` | 보안 스킬 패키지 | 각 스킬은 `skill.json`, `SKILL.md`, 선택적 scripts/tests/docs 포함 |
| `advisories/` | 리포지토리 advisory 채널 | 서명된 `feed.json` + `feed.json.sig` |
| `scripts/` | 로컬 자동화 | feed/skills populate, pre-push 점검, release helper |
| `.github/workflows/` | CI/CD 파이프라인 | CI, release, NVD polling, pages deploy |
| `wiki/` | 문서 허브 | 아키텍처, 운영 런북, 검증 가이드 |

## 진입점
- `index.tsx`: React 앱 부트스트랩
- `App.tsx`: 라우트 정의 (`/`, `/skills`, `/feed`, `/wiki/*`)
- `scripts/prepare-to-push.sh`: 로컬 품질 게이트
- `scripts/generate-wiki-llms.mjs`: wiki `llms.txt` 생성

## 핵심 워크플로우
1. 로컬 개발: `npm install && npm run dev`
2. 로컬 데이터 미리보기:
   - `./scripts/populate-local-skills.sh`
   - `./scripts/populate-local-feed.sh --days 120`
3. 품질 게이트: `./scripts/prepare-to-push.sh`

## 예시 명령
```bash
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run dev
```

## 참고
- 상세 기준 문서는 영어 원문을 참고하세요: [../overview.md](../overview.md)
- 위키 인덱스(한국어): [INDEX.md](INDEX.md)

## 업데이트 노트
- 2026-04-27: 한국어 overview 초기 버전 추가.

## 소스 참조
- `README.md`
- `App.tsx`
- `index.tsx`
- `scripts/prepare-to-push.sh`
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `scripts/generate-wiki-llms.mjs`
