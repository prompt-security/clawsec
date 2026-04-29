<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../migration-signed-feed.md
Review status: draft
-->

# 마이그레이션 기록 : 위임 된 피드 → 서명 피드 (완료)

# # # # # # # # # # 1) 목표 및 상태

ClawSec 자문 배포가 서명되지 않은 `feed.json` 납품에서 레거시 클라이언트를 위해 보존 된 호환성과 함께 분리 된 서명 확인을 수행하는 방법 문서.

`main`의 현재 상태:
- Signed Feed Publishinging은 자문 작업 흐름과 워크플로우를 배치하는 역할을 합니다.
- Suite 및 NanoClaw 소비자는 기본적으로 피드 엔드포인트를 서명합니다.
- 별도의 호환성 우회(`CLAWSEC_ALLOW_UNSIGNED_FEED=1`)만 존재합니다.

# # # # # # # # # # 2) 기본 (일, 포스트 마이그레이션)

활성 사용의 현재 공급 경로:
- 진실의 근원: `advisories/feed.json`
- 소스 서명 : `advisories/feed.json.sig`
- 기술 복사 : `skills/clawsec-feed/advisories/feed.json`
- 기술 사본 서명: `skills/clawsec-feed/advisories/feed.json.sig`
- 페이지 사본: `public/advisories/feed.json`
- 페이지 서명: 사이트맵
- 최신 미러 복사 : `public/releases/latest/download/advisories/feed.json` (+ `.sig`)

현재 소비자 과태:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`의
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`의
- `skills/clawsec-nanoclaw/lib/advisories.ts`의
- 기본 URL: `https://clawsec.prompt.security/advisories/feed.json`

# # # # # # # # # # 3) 마이그레이션 원리

-**Dual-publish first**: 검증을 위해 서명을 게시합니다.
- ** 전환 중 만 실패 - ** : 임시 호환성 기간은 명시되어 있으며 시간 제한.
-**Measured rollout**: telemetry 후의 검증은 안정적인 서명 게시를 확인합니다.
-**Fast rollback**: 루트 원인이 조사되는 동안 불신명한 행동으로 다시 길을 보존합니다.

# # # # # # # # # # 4) 단계별 타임라인 (historical)

# # # # # # # # # # # 단계 0 - 준비 (완료)

공급 능력:
- 기록된 키 및 지문 서명
- GitHub 비밀 생성
- 대중 키 (s) repo에 추가
- runbooks 승인 (`security-signing-runbook.md`,이 파일)

출구 기준:
- 검토자가 확인한 키 지문
- 보호된 분지/workflow 통제 활성화

# # # # # # # # # # # 단계 1 - CI 서명 활성화, 클라이언트 집행 없음 (완료)

구현 :
- `advisories/feed.json.sig`를 생성하는 급식 서명 단계/작업 흐름을 추가하십시오
- 선택적으로 생성 `advisories/checksums.json` + `.sig`
- CI는 게시하기 전에 서명을 검증합니다.

또한 업데이트 배포:
- `.sig` artifacts를 `public/advisories/`로 복사
- `.sig`의 미러 `.sig`

출구 기준:
- 모든 피드 업데이트 경로에 성공적으로 생성 된 서명
- 배치 artifacts는 payload와 서명 동반자를 포함합니다

# # # # # # # # # # # 주요연혁 2 — 소비자 듀얼-레드/듀얼-verify 지원 (완료)

소비자의 구현:
- `feed.json` 및 `feed.json.sig`를 읽으십시오
- pinned public key로 확인
- 이동 창 도중 통제되는 임시 불이행한 fallback를 지킵니다

유효성:
- 테스트 원격 서명 경로
- 로컬 서명된 fallback 경로 테스트
- 테스트 잘못된 서명 거부

출구 기준:
- 검증 논리 및 테스트
- 적시에 부정적 검증 실패 없음

# # # # # # # # # # # 3 단계 - 시행 (완료)

활동 :
- 기본 경로의 일시적 불이행된 fallback 동작
- `.sig`가 누락될 때 실패한 CI/publish 문을 추가하십시오
- 릴리스 노트 및 docs의 시행일 발표

출구 기준:
- 모든 생산 클라이언트는 기본적으로 서명을 확인합니다
- 표준 임명 교류에 있는 unsigned 급식 의존도 없음

# # # # # # # # # # # 주요연혁 4 - 안정화 (Ongoing)

활동 :
- 첫번째 열쇠 교체 탁상 교련을 달리십시오
- 롤백 탁상 드릴 실행
- post-implementation 검토와 가까운 이동

# # # # # # # # # # 5) 롤백 계획

## 롤백 트리거

다음의 경우 롤백을 시작:
- 클라이언트의 지속적인 서명 검증 실패
- 서명 워크플로는 유효한 서명을 생성할 수 없습니다
- 키 손상 의심하지만 교체 키는 아직 배포되지 않습니다
- 배포 경로는 잘못된 payload/signature 쌍을 게시

## # 롤백 레벨

## 레벨 1 (preferred): Verification bypass 창, 서명된 게시 유지

사용될 때: signing는 건강합니다, 클라이언트 측 verifier에는 결함이 있습니다.

활동 :
1. 명세 클라이언트 릴리스 지점의 임시 취소 방지 동작.
2. 명세 bypass에 대한 명시된 만료 날짜와 선박 패치 릴리스.
3. 명세 정품 간격을 피하기 위해 파이프라인을 서명하십시오.

복구 대상 : 24 ~ 48h 이내에 엄격한 검증을 복원합니다.

### 레벨 2: 서명된 파이프라인 일시적으로 권한이 없는, 위탁된 급식

사용될 때: signing 파이프라인은 불안정하거나 inconsistent artifacts를 일으키.

활동 :
1. 명세 작업 흐름 또는 서명 단계가 비활성화됩니다.
2. 기존 워크플로우를 통해 `advisories/feed.json`를 서명하지 않는 것을 계속합니다.
3. 명세 `.sig` artifacts가 필요한 게이트를 다시 배포합니다.
4. 명세 사건 기록 및 추적 시간 표시되지 않은 모드에서.

복구 대상 : 서명 된 출판 ASAP, 이상적으로 <72h.

### 레벨 3: 전체 릴리스 동결

사용될 때: repository/workflows의 타협 또는 완전성은 의심합니다.

활동 :
1. 명세 Pause feed mutation 및 배포 워크플로우.
2. 명세 자문 파일 / 워크 플로에 대한 알려진 좋은 커밋 복원.
3. 명세 열쇠와 자격.
4. 명세 보안 검토 표지판 후만 이력서 파이프라인.

## 롤백 후 롤백

- 루트 원인 확인
- 회귀 테스트/게이트 추가
- redeploy 서명된 artifacts
- 출판사 사건 + 재화 요약

# # # # # # # # # # 6) 통신 계획

시행 및 롤백 이벤트의 경우, 통신 :
- 어떤 변경
- 예상 연산자/클라이언트 작업
- 임시 겸용성 형태의 내구 (모든 경우에)
- 사용자의 검증 명령

권장 채널:
- GitHub 릴리스 노트
- 저장소 README/docs 업데이트
- repository에 있는 문제점/incident 보고

# # # # # # # # # # 7) Go/No-Go 체크리스트

모두 true인 경우에만 이동하십시오:
- 대화 워크플로 성공률은 안정
- 서명은 모든 문서 피드 엔드포인트에 미러링됩니다.
- 원격 + 로컬 fallback에 대한 소비자 검증 경로 테스트
- 롤백 소유자는 할당 및 도달 가능
- 열쇠 교체 절차는 적어도 한 번 말립니다

## 소스 참조
- .github/workflows/poll-nvd-cves.yml의 경우
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml의 경우
- 기술/하프스위트/훅/하프스위트 자문/handler.ts
- 기술/클래스/scripts/guarded_skill_install.mjs
- 고문/feed.json
- 위키 / 보안 - 서명 - Runbook.md
