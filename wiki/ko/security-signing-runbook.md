<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../security-signing-runbook.md
Review status: draft
-->

# ClawSec 서명 작업 Runbook

# # # # # # # # # # # 1) 목적

이 runbook은 ClawSec 저장소에 암호화 서명을 도입하고 실행하기위한 작업 절차를 정의합니다.

그것은 덮습니다:
- 키 생성
- GitHub 비밀 관리
- 작업 흐름 통합 서명
- 키 교체 및 재발급
- 사건 응답

# # # # # # # # # # 2) 현재 운영 국가 (위탁자)

`main`에서 고문 및 릴리스 채널은 기본적으로 서명하고 검증됩니다.

- 급식 작가:
- `.github/workflows/poll-nvd-cves.yml` 업데이트 `advisories/feed.json` 및 표지 `advisories/feed.json.sig`
- `.github/workflows/community-advisory.yml`는 승인된 문제점 보고를 위해 동일합니다
- 둘 다 동기화는 `skills/clawsec-feed/advisories/`로 공식 급식 artifacts를 서명했습니다
- 피드 출판 경로:
- `.github/workflows/deploy-pages.yml` 발행 `public/advisories/feed.json` + `.sig`
- 생성 및 표시 `public/checksums.json` + `public/checksums.sig`
- `public/signing-public.pem` 및 `public/advisories/feed-signing-public.pem`로 canonical 키 게시
- `public/releases/latest/download/` (`feed.json`, `feed.json.sig`, `checksums.json`, `checksums.sig`, `signing-public.pem` 포함)의 미러 호환성 예측
- 공급 소비자:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`의
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`의
- `skills/clawsec-nanoclaw/lib/advisories.ts`의
- 기본 피드 URL은 `https://clawsec.prompt.security/advisories/feed.json`입니다.

지정되지 않은 모드는 명시된 호환성 우회 (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`)에 남아 있으며 꾸준한 운영 모델이 아닙니다.

# # # # # # # # # # 3) 표적 서명된 artifacts

### 자문 피드 채널
- `advisories/feed.json` (페이로드)
- `advisories/feed.json.sig` (Ed25519 서명; base64)
- `advisories/feed-signing-public.pem` (핀 공공 키)

# # # # # # # # # # # artifact 채널 출시
- `<release>/checksums.json`의
- `<release>/checksums.sig`의
- `<release>/signing-public.pem`의

# # # # # # # # # # 4) 중요한 역할 및 custody

- ** 보안 소유자 ** : 키 수명주기 변경 및 사고 조치를 승인하십시오.
- **플랫폼 소유자**: 워크플로우와 GitHub 비밀 유지.
-**Reviewer**: PRs/releases의 지문을 검증합니다.

정책:
- 개인 키는 결코 최선을 다하고 있지 않습니다.
- 공공 키는 최선을 다하고 코드 검토
- 키 생성은 신뢰할 수있는 연산자 워크스테이션 또는 HSM 백업 환경에 발생합니다.

# # # # # # # # # # 5) 키 생성 (Ed25519)

· 안전한 워크스테이션에서 실행. CI 런너를 공유하지 마십시오.

```bash
# Feed signing keypair
openssl genpkey -algorithm Ed25519 -out feed-signing-private.pem
openssl pkey -in feed-signing-private.pem -pubout -out feed-signing-public.pem

# Release checksums signing keypair (optional separate key)
openssl genpkey -algorithm Ed25519 -out release-signing-private.pem
openssl pkey -in release-signing-private.pem -pubout -out release-signing-public.pem
```

지문 생성 (표/변경 기록에 있는 상점):

```bash
openssl pkey -pubin -in feed-signing-public.pem -outform DER | shasum -a 256
openssl pkey -pubin -in release-signing-public.pem -outform DER | shasum -a 256
```

발행하기 전에 선택적 테스트 서명:

```bash
echo '{"probe":"ok"}' > /tmp/probe.json
openssl pkeyutl -sign -rawin -inkey feed-signing-private.pem -in /tmp/probe.json -out /tmp/probe.sig.bin
openssl base64 -A -in /tmp/probe.sig.bin -out /tmp/probe.sig
openssl base64 -d -A -in /tmp/probe.sig -out /tmp/probe.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey feed-signing-public.pem -in /tmp/probe.json -sigfile /tmp/probe.sig.bin
```

# # # # # # # # # # 6) GitHub 비밀 설정

# # # # # # # # # # # 필수 비밀

- `CLAWSEC_SIGNING_PRIVATE_KEY` - PEM-encoded Ed25519 개인 키 (사료 및 릴리스 서명 모두 사용)
- `CLAWSEC_SIGNING_PRIVATE_KEY_PASSPHRASE` - (옵션) 전용 키가 암호화되는 경우 passphrase

### 절차

1. 명세 **Repo Settings → Secrets and variables → Actions → 새로운 저장소 secret**로 이동하십시오.
2. header/footer를 포함하여 풀 PEM.
3. 명세 프리퍼 GitHub **Environment secrets**(필요한 검토자 포함)는 워크플로우 스코핑을 할 수 있습니다.
4. 명세 기록 교환권:
- 비밀 이름
- 제작자
- 창조 시간
- 키 지문

# # # # # # # # # # # 권장 환경 보호

- 비밀 서명을 사용할 수있는 워크플로우에 대한 매뉴얼 승인.
- 보호된 워크플로우를 편집할 수 있는 제한.
- `main`에 대한 분기 보호 및 워크플로우 변경에 대한 검토가 필요합니다.

# # # # # # # # # # 7) Workflow 통합 점

이 재포는 포스트 mutation로 서명합니다, 사전 발행 통제.

### 피드 파이프

현재 급식 mutation 점:
- `.github/workflows/poll-nvd-cves.yml`의
- `.github/workflows/community-advisory.yml`의

현재 행동:
- 작업 흐름 단계 표지 `advisories/feed.json`로 `advisories/feed.json.sig`
- 작업 흐름 실행 중에 생성 된 서명을 표시
- 서명된 artifacts는 PR 자동화를 통해 투입됩니다

# # # # # # # # # # # 페이지 파이프라인

현재 발행인:
- `.github/workflows/deploy-pages.yml`의

현재 행동:
- `public/advisories/`에 payload/signature 복사
- 생성 + `public/checksums.json` 및 `public/checksums.sig` 표지판
- `public/signing-public.pem` 및 `public/advisories/feed-signing-public.pem`에 서명 키 게시
- 미러 자문 + 서명 / 체크섬 / 키 동반자 `public/releases/latest/download/` 호환성 경로

# # # # # # # # # # # Skill release 파이프라인 (추천 경화)

현재 방출 발전기:
- `.github/workflows/skill-release.yml`의

현재 행동:
- `checksums.json`를 생성하고 `checksums.sig`로 서명하고 게시하기 전에 서명을 검증합니다.
- 릴리스 자산에 `signing-public.pem` 포함
- canonical 키 재료에 대한 생성 된 공공 키 지문을 검증

# # # # # # # # # # 8) 교체 정책 및 runbook

### 교체 cadence
- 루틴: 90 일 (또는 엄격한 org 정책).
- Immediate: 의심의 여지없이 노출, 무단 작업 흐름 변화, 또는 부정확한 서명 잘못.

### Routine 교체 단계

1. 명세 새로운 keypair(s) 생성.
2. 명세 공공 키 파일(s) 및 지문 문서를 업데이트하는 PR을 엽니다.
3. 명세 GitHub secret(s)로 새로운 개인 키 추가
4. 명세 새로운 키(s)를 사용하는 작업 흐름 변경.
5. 명세 Re-sign 최신 피드/출판은 나타납니다.
6. 명세 CI 및 외부 클라이언트의 검증을 검증합니다.
7. 명세 오래된 개인 키 비밀 제거(s).
8. 명세 과거의 검증에 필요한 만큼 긴 공공 키 참조를 유지하십시오.

## # 재직 단계

1. 명세 손상된 키를 사용하여 작업 흐름을 비활성화합니다.
2. 손상된 GitHub 비밀 제거(s).
3. 명세 재직 및 새로운 공공 키.
4. 명세 보충 열쇠를 가진 최신 artifacts를 서명하십시오.
5. 명세 타임스탬프와 충격적인 창을 가진 사건 자문.

# # # # # # # # # # 9) 사용 응답 playbook (signing-specific)

## 트리거
- 서명 검증은 새로 출판된 Feed/release에 실패합니다.
- 알 수없는 커밋 / 워크 플로우 편집 경로
- 유출된 핵심 물자, 사고 로깅, 또는 의심스러운 비밀 접근

## # Severity 가이드
- **SEV-1**: 키 exfiltration 확인 또는 악성 서명된 페이로드
- **SEV-2**: 알 수없는 원인과 검증 실패
- **SEV-3**: 비응축, 활성 타협 없음

# # # # # # # # # # # 응답 단계

1. 명세 **컨테이너* * 이름
- pause signing/publish 워크플로우
- 정품이 불확실한 경우 더 많은 피드 합병을 차단
2. **투자**
- 검토 워크플로우 실행 로그
- `.github/workflows/`, `advisories/` 및 키 파일에 영향을 미치는 리뷰 커밋
- 첫번째 나쁜 타임스탬프 및 영향 받은 artifacts를 결정하십시오
3. 명세 ** 정보**
- 회전/복합된 키(s)
- 알려진 좋은 커밋에서 신뢰할 수있는 artifacts 복원
4. 명세 ** 복구 **
- 재 위탁 artifacts
- Redeploy 페이지/출판
- 자주 묻는 질문
5. 명세 ** 우편 번호 * * 이름
- 간행물 및 구제 요약
- 조임 컨트롤 (리뷰 게이트, 보호 된 환경, 비밀 범위)

## 10) 감사 증거 체크리스트

각 방출 주기 또는 급식 위탁 달리기를 위해, 유지하십시오:
- 워크플로우 실행 URL 및 커밋 SHA
- 사용에 있는 signer 열쇠 지문
- 검증 결과 로그
- 연산자/리뷰어 승인
- 모든 예외 또는 우회 합리적

## 11) 엄격한 정책 변경 전 최소 합격 기준

정책을 더 바짝 죄기 전에 (예를 들어, 호환성 우회 경로 제거):
- 서명된 artifacts는 적어도 2 주 동안 일관되게 생성합니다
- 파이프라인 미러 서명 동반자 배치
- 1개의 rollback 교련 및 1개의 열쇠 교체 교련은 성공적으로 완료했습니다
- 식별 및 문서화 된 계정 소유자의 사건 응답

## 소스 참조
- 고문/feed.json
- 고문/feed.json.sig
- 고문 / 채권-public.pem
- clawsec 서명-public.pem
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml의 경우
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml의 경우
- .github/workflows/skill-release.yml의 경우
- 스크립트/ci/verify_signing_key_consistency.sh
- 위키/이민 위탁-feed.md
