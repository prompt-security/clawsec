<!--
Translation source: ../skill-feature-matrix.md
Last synchronized: 2026-08-02
Method: Codex-assisted translation with repository terminology and structural parity checks
Review status: native-speaker review pending
-->

# 스킬 기능 매트릭스

이 페이지는 ClawSec의 패키지별 기능 비교를 보존합니다. 영어 페이지가 정본이며, 이 번역은 동일한 패키지 순서와 상태 의미를 유지합니다.

플랫폼 요약은 현재 패키지 제품군 전체의 지원 범위를 집계합니다. 일부 기능은 플랫폼의 기본 진입점에 포함되지 않고 별도의 스킬을 필요로 할 수 있습니다.

## 플랫폼 요약

| 플랫폼 | 보안 권고 및 피드 처리 | 무결성 및 드리프트 | 감사 및 보안 태세 | 설치 위험 게이트 | 설치 후보 아티팩트 검증 | 커뮤니티 보고 | 런타임 트래픽 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw | 서명 검증 및 외부 조회 | 옵션 `soul-guardian` 패키지를 통해 제공 | 제공 | 보안 권고 및 평판 게이트 | 통합 후보 아티팩트 검증기 없음, 설치는 ClawHub에 위임 | 옵트인 | 사양만 제공 |
| NanoClaw | fail-closed 방식의 서명 검증 | 내장 | 보안 권고 및 취약점 감사 | 보안 권고 사전 점검 | 구현된 NanoClaw 통합, 고정된 신뢰 키를 사용하는 후보 패키지 서명 검증 | 옵트인 | 사양만 제공 |
| Hermes | fail-closed 방식의 서명 검증 | 내장 | 증명 및 보안 태세 검증 | 보안 권고 사전 점검만 | 후보 아티팩트 검증 없음 | 옵트인 | 사양만 제공 |
| Picoclaw | 상위 단계에서 검증된 피드 상태 사용 | 내장 | 내장 보안 태세 프로파일링 + 별도 읽기 전용 검토 | 설치 게이트 없음 | 실행 가능한 릴리스 아티팩트 검증, 호출자가 신뢰하는 키를 사용 | 옵트인 | 사양만 제공 |

릴리스된 모든 ClawSec 패키지는 자체 단독 배포 아카이브를 대상으로 서명된 매니페스트를 수동으로 사전 검증하는 절차를 문서화합니다. 이 공통 릴리스 무결성 기준선은 아래 각 행에 반복하지 않습니다. `claw-release`는 이러한 서명된 릴리스 생성도 안내합니다. 후보 검증 열은 패키지 자체 아카이브가 아닌 설치 아티팩트 검증에만 사용합니다.

## 패키지별 지원 범위

<!-- skill-feature-matrix:start -->
| 스킬 이름 | 플랫폼 | 보안 권고 및 피드 처리 | 무결성 및 드리프트 | 감사 및 보안 태세 | 설치 위험 게이트 | 설치 후보 아티팩트 검증 | 커뮤니티 보고 | 런타임 트래픽 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claw-release` | OpenClaw | 없음 | 없음 | 없음 | 없음 | 후보 아티팩트 검증 없음 | 없음 | 없음 |
| `clawsec-clawhub-checker` | OpenClaw + `clawsec-suite` 통합 | 스위트 보안 권고 게이트 | 없음 | 없음 | ClawHub 평판 + 스위트 보안 권고 게이트 | 후보 아티팩트 검증 없음 | 없음 | 없음 |
| `clawsec-feed` | OpenClaw | 보안 권고 데이터 패키지, 폴링은 스위트 또는 운영자가 관리하며 피드 서명 검증 없음 | 없음 | 없음 | 없음 | 후보 아티팩트 검증 없음 | 없음 | 없음 |
| `clawsec-nanoclaw` | NanoClaw | fail-closed 방식의 서명 검증 | 파일 기준선 + 선택적 복원 | 보안 권고/취약점 감사, 능동 테스트 없음 | 보안 권고 사전 점검 | 구현된 NanoClaw 통합, 고정 키 후보 패키지 서명 검증 | 없음 | 없음 |
| `clawsec-scanner` | OpenClaw | 외부 CVE 조회, 서명된 피드 검증 없음 | 없음 | 종속성, SAST, 정적 훅 감사, 능동적 악용 없음 | 없음 | 후보 아티팩트 검증 없음 | 없음 | 없음 |
| `clawsec-suite` | OpenClaw | 서명된 피드 검증 + 체크섬 매니페스트 검증 | 옵션 `soul-guardian`을 통해 제공, 내장 아님 | 없음 | 보안 권고 게이트 + 명시적 확인 | 통합 후보 아티팩트 검증기 없음, 분리 서명을 검증하는 범용 유틸리티만 제공, 설치는 ClawHub에 위임 | 없음 | 없음 |
| `clawtributor` | 모든 핵심 플랫폼 | 없음 | 없음 | 없음 | 없음 | 없음 | 승인 기반 로컬 초안 + 수동 제출 | 없음 |
| `hermes-attestation-guardian` | Hermes | fail-closed 방식의 서명 검증 | 증명, 설정, 신뢰 앵커 드리프트 | 증명 및 보안 태세 검증 | 보안 권고 사전 점검만 | 후보 아티팩트 검증 없음 | 없음 | 없음 |
| `hermes-traffic-guardian` | Hermes | 없음 | 계획된 보안 태세 내보내기만 | 없음 | 없음 | 없음 | 없음 | 사양만 제공, 런타임 프록시 없음 |
| `nanoclaw-traffic-guardian` | NanoClaw | 없음 | 없음 | 없음 | 없음 | 없음 | 없음 | 사양만 제공, 런타임 프록시 없음 |
| `openclaw-audit-watchdog` | OpenClaw | 없음 | 없음 | 심층 모드를 포함한 자동 감사, 능동적 악용 없음 | 없음 | 없음 | 없음 | 없음 |
| `openclaw-traffic-guardian` | OpenClaw | 없음 | 없음 | 없음 | 없음 | 없음 | 없음 | 사양만 제공, 런타임 프록시 없음 |
| `picoclaw-security-guardian` | Picoclaw | 검증된 피드 상태 사용, 암호학적 검증은 상위 단계에서 수행 | 결정론적 프로필 및 설정 드리프트 | 읽기 전용 보안 태세 검사 | 없음 | 실행 가능한 Picoclaw 릴리스 아티팩트 체크섬 검증 + 서명된 매니페스트 검증, 호출자가 신뢰하는 키를 사용 | 없음 | 없음 |
| `picoclaw-self-pen-testing` | Picoclaw | 없음 | 없음 | 읽기 전용 self-pen 보안 태세 검토, 능동적 악용 없음 | 없음 | 없음 | 없음 | 없음 |
| `picoclaw-traffic-guardian` | Picoclaw | 없음 | 계획된 프로필 내보내기만 | 없음 | 없음 | 없음 | 없음 | 사양만 제공, 런타임 프록시 없음 |
| `soul-guardian` | OpenClaw | 없음 | 워크스페이스 파일 기준선, 드리프트 탐지, 선택적 복원 | 없음 | 없음 | 없음 | 없음 | 없음 |
<!-- skill-feature-matrix:end -->

## 상태 정의

- **서명 검증**은 패키지가 서명된 신뢰 자료를 직접 검증한다는 뜻입니다. **모니터링**, **외부 조회**, **상위 단계에서 검증된 상태**는 별도로 표시합니다.
- **설치 위험 게이트**는 설치 전 보안 권고 또는 평판 검사를 뜻하며, 후보 아티팩트의 출처 검증과는 다릅니다.
- 모든 패키지에 공통인 **자체 패키지 사전 검증**은 각 패키지의 릴리스 아카이브만 다룹니다. 후보 검증 열은 다른 설치 아티팩트의 검증을 표시합니다.
- **감사 및 보안 태세**에는 정적 검사, 종속성, 보안 권고, 증명, 읽기 전용 태세 검사가 포함됩니다. 능동적 악용을 하지 않는 경우 이를 명시합니다.
- **옵션 추가 패키지를 통해 제공**은 기본 패키지가 별도 스킬을 찾거나 연동할 수 있지만 해당 기능을 직접 포함하지는 않음을 뜻합니다.
- **사양만 제공**은 디렉터리, 메타데이터, frontmatter, 구현 계약은 있지만 런타임 프록시는 제공되지 않음을 뜻합니다.
- **계획된 보안 태세/프로필 내보내기만**은 traffic-guardian 사양의 통합 계약을 설명하며, 제공 중인 드리프트 모니터를 뜻하지 않습니다.

`clawtributor`는 여러 플랫폼에서 사용하는 인시던트 보고 패키지입니다. `없음` 값은 매트릭스의 다른 보호 기능이 보고 범위 밖이라는 의미이며, 패키지가 비활성 상태라는 뜻이 아닙니다.

## 유지 관리

16개 패키지 행은 이전 README 매트릭스에서 복구했습니다. 기존 이진 값이 모니터링과 검증, 감사와 능동 테스트, 추가 패키지와 내장 기능, 보안 권고 게이트와 아티팩트 출처를 혼동한 부분은 기능 축을 분리했습니다.

매트릭스는 `skills/` 아래 디렉터리와 일치해야 합니다. 번역 QA는 각 현지화 매트릭스가 동일한 16개 패키지 식별자, 동일한 순서, 9열 구조를 유지하는지 검증합니다.

## 소스 참조

- `skills/*/skill.json`
- `skills/*/SKILL.md`
- [ClawSec Suite Core](../modules/clawsec-suite.md)
- [ClawSec Scanner](../modules/clawsec-scanner.md)
- [NanoClaw Integration](../modules/nanoclaw-integration.md)
- [Hermes Attestation Guardian](../modules/hermes-attestation-guardian.md)
- [Picoclaw Security Guardian](../modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](../modules/picoclaw-self-pen-testing.md)
- [Runtime Traffic Guardian Baseline](../modules/runtime-traffic-guardian-baseline.md)
