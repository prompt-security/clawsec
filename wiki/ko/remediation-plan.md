<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../remediation-plan.md
Review status: draft
-->

# 교차 플랫폼 구제 계획

# # # # # # # # # # 단계 1: 즉시 위험 폐쇄 (완료)

## 마일스톤
- 명시된 홈-경로 확장 + 높은-리스크 런타임/설치 경로의 의심스러운 토큰 거부 구현.
- 경로 확장 및 탈출을 위한 회귀 테스트 추가.
- `.gitattributes` LF 정책을 추가하십시오.
- Linux/macOS/Windows에 Node lint/type/build CI 적용을 확장합니다.
- 업데이트는 shell-specific 지도와 리터럴 `$HOME` 문제 해결과 함께 docs를 설치합니다.

## # 결과
- 리터 `$HOME` 경로 propagation 버그는 소스에 주소.
- Core advisory/install 경로 설정은 이제 잘못된 경로 토큰에 빠지지 않습니다.

--- ---

# # # # # # # # # # 단계 2: 긴요한 워크 플로우에 대한 Windows Parity (다음)

## 빠른 승리
- 전원 추가 Shell은 가장 많이 사용되는 수동 설치 / 체크 명령에 해당합니다.
- `skills/clawsec-suite/SKILL.md`의
- `skills/openclaw-audit-watchdog/SKILL.md`의
- `README.md`의
- 경량 `scripts/preflight.mjs`를 추가하여 누락된 도구와 인쇄 OS-특수 설치 힌트를 감지합니다.

## 마일스톤
- 네이티브 파워 스위트 설정 및 자문 후크에 대한 쉘 지침.
- WSL/Git Bash fallback은 쉘 스크립트가 비례 없는 곳에 문서화되었습니다.

--- ---

# # # # # # # # # # 단계 3: POSIX 감소 포탄 표면 (Deeper Refactor)

## Refactor 대상
- `scripts/populate-local-feed.sh`의
- `scripts/populate-local-skills.sh`의
- `scripts/release-skill.sh`의

### 접근
- `jq/sed/awk/find/chmod` 파이프라인에 의존성을 제거하기 위해 Node/Python의 중요한 경로 재개.
- 백워드 호환성을 위한 예비 쉘 래퍼; 새로운 크로스 플랫폼 구현 경로.

### 마이그레이션 노트
- 적어도 하나의 미성년자 릴리스에 대한 래퍼로 오래된 스크립트 엔트리 포인트를 유지.
- 정확한 마이그레이션 명령으로 경고를 전송합니다.

--- ---

# # # # # # # # # # 4 단계 : CI 경화 및 양파 검증

## 마일스톤
- 필요한 체크로 Node matrix (Linux/macOS/Windows)를 유지하십시오.
- 설치 경로 처리를위한 대상 Windows 연기 테스트 추가.
- macOS 체크를 OpenSSL 명령 호환성 메모에 추가하십시오.

# # # # # # # # # # # 시험 전략
- 지역:
- 경로 확장/suppression/install 동작을 커버하는 Node Test Suite를 실행합니다.
- 수정된 스크립트를 위한 구문 체크를 실행합니다.
- CI:
- Matrix Node 체크 + 가드 설치 프로그램 / 압축 / 경로 테스트.
- Linux 전용 보안 검사는 남아 있지만 Linux-scoped로 표시되어 있습니다.

--- ---

## 롤아웃 / 출시 고려

- - - 이 패치 세트에 도입 된 인터페이스 변경 없음; 동작은 잘못된 / 예상 경로 토큰에만 엄격합니다.
- 릴리스 노트에서 Communicate:
- 경로 토큰 유효성 검증
- 잘못된 인용 된 env 값을 수정하는 방법
- 어디 힘 Shell 예제

## 소스 참조
- .gitattributes의
- .github/workflows/ci.yml의 경우
- 스크립트/populate-local-feed.sh
- 스크립트/populate-local-skills.sh
- 스크립트/출시-skill.sh
- 기술/하프스위트/훅/하프스위트 자문/handler.ts
- 기술/클래스/scripts/guarded_skill_install.mjs
- 기술/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- 위키/platform-verification.md
