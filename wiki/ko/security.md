# Security (한국어)

## 보안 모델 개요
- ClawSec은 콘텐츠 배포(서명된 아티팩트)와 런타임 동작(advisory gating, 무결성 모니터링)을 모두 보호합니다.
- 신뢰 앵커는 리포지토리에 고정된 공개 키이며, 워크플로우 산출물과 대조해 검증합니다.
- 런타임 소비자는 기본적으로 verification-first 동작을 사용하며, 마이그레이션용 bypass 플래그는 명시적으로만 허용됩니다.

## 암호학적 통제
| 통제 | 메커니즘 | 위치 |
인포메이션
| Feed authenticity | Ed25519 detached signatures (`feed.json.sig`) | Advisory 워크플로우 + 소비자 검증 라이브러리 |
| Artifact integrity | SHA-256 checksum manifests (`checksums.json`) | 스킬 릴리스 및 pages 배포 워크플로우 |
| Key consistency | 문서/정본 PEM 간 fingerprint 비교 | `scripts/ci/verify_signing_key_consistency.sh` |
| Signature verification action | CI의 composite sign+verify 액션 | `.github/actions/sign-and-verify/action.yml` |

## 런타임 enforcement 통제
|제어 | 부품 | 효과 |
인포메이션
| Advisory hook gating | `clawsec-advisory-guardian` | 매칭된 advisory 기반 경고 및 보수적 가이드 제공 |
| Double-confirmation installer | `guarded_skill_install.mjs` | advisory 매칭 시 명시적 확인 전까지 `42`로 종료 |
| Reputation extension | `clawsec-clawhub-checker` | 설치 전 추가 리스크 스코어링 |
| NanoClaw signature gate | `skill-signature-handler.ts` + MCP tool | 정책에 따라 변조/미서명 패키지 설치 차단 |
| Integrity baseline monitor | `soul-guardian` + NanoClaw integrity monitor | drift 탐지, 격리, 복구, 감사 가능한 이력 |

## 공급망 및 CI 통제
- CI는 Trivy, npm audit, CodeQL, Scorecard 워크플로우를 실행합니다.
- 로컬 pre-push 점검은 `gitleaks` 설치 시 `gitleaks detect`를 실행할 수 있습니다.
- 릴리스 워크플로우는 패키징 전에 SBOM 파일 존재를 검증합니다.
- 배포 워크플로우는 생성된 signing key fingerprint를 정본 키와 대조 검증합니다.
- 릴리스 문서에는 downstream 소비자를 위한 수동 검증 명령이 포함됩니다.

## 인시던트 및 키 로테이션 플레이북
- `wiki/security-signing-runbook.md`는 키 생성/보관/로테이션 및 인시던트 단계를 정의합니다.
- `wiki/migration-signed-feed.md`는 단계적 enforcement 및 rollback 레벨을 정의합니다.
- 롤백 경로는 가능한 경우 서명된 배포를 유지하고, bypass는 시간 제한 하에 사용하도록 설계됩니다.

## 예시 스니펫
```bash
# verify canonical public key fingerprint
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
```

```bash
# run repo key-consistency guardrail used in CI
./scripts/ci/verify_signing_key_consistency.sh
```

## 알려진 보안 트레이드오프
- unsigned 호환 모드는 보증 수준을 낮출 수 있으므로 마이그레이션 완료 후 비활성화해야 합니다.
- 일부 배포 경로는 하위 호환을 위해 legacy unsigned checksum asset을 허용합니다.
- 평판 체크는 외부 툴 출력에 의존하므로 휴리스틱 오탐/미탐 가능성이 있습니다.
- 로컬 스크립트는 실행 환경 신뢰를 상속하므로, 로컬 셸이 손상되면 운영자 워크플로우가 우회될 수 있습니다.

## 하드닝 기회
- 마이그레이션 안정화 후 unsigned 호환 플래그 제거
- 미러된 릴리스 파일 전체에 대한 결정론적 checksum/signature 검증 확대
- 워크플로우 수준 서명 실패 시나리오에 대한 명시적 테스트 추가
- advisory fetch/verify 실패에 대한 런타임 텔레메트리 강화로 인시던트 트리아지 단순화

## 업데이트 노트
- 2026-04-27: `wiki/security.md` 한국어 번역 추가.
- 2026-02-26: signing/migration 참조를 루트 `docs/`에서 `wiki/` 운영 페이지로 재지정.

## 소스 참조
- `SECURITY.md`
- `wiki/security-signing-runbook.md`
- `wiki/migration-signed-feed.md`
- `scripts/ci/verify_signing_key_consistency.sh`
- `.github/actions/sign-and-verify/action.yml`
- `.github/workflows/poll-nvd-cves.yml`
- `.github/workflows/community-advisory.yml`
- `.github/workflows/skill-release.yml`
- `.github/workflows/deploy-pages.yml`
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs`
- `skills/soul-guardian/scripts/soul_guardian.py`
- `skills/clawsec-nanoclaw/host-services/skill-signature-handler.ts`
- `skills/clawsec-nanoclaw/guardian/integrity-monitor.ts`
