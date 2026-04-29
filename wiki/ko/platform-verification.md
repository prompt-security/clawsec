<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ko)
Source: ../platform-verification.md
Review status: draft
-->

# 플랫폼 검증 체크리스트

이 체크리스트를 사용하여 변경 후 포트성과 경로 추적 작업을 검증합니다.

## 리눅스 검증

1. 명세 핵심 노드 테스트를 실행:
   ```bash
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
   ```
예상 : 모든 테스트 패스.

2. 명세 리터 `$HOME` 경로 합격을 확인:
   ```bash
   CLAWSEC_LOCAL_FEED='\$HOME/advisories/feed.json' \
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
예상 : `Unexpanded home token` 오류로 비소를 종료합니다.

3. `$HOME` 확장 작품을 검증:
   ```bash
   HOME=/tmp/clawsec-home node skills/clawsec-suite/test/path_resolution.test.mjs
   ```
예상되는: `$HOME` 확장 시험 통행.

## macOS 인증

1. 명세 같은 노드 테스트 스위트를 Linux로 실행합니다.
2. OpenSSL 도구 경로 가정을 확인:
- LibreSSL/OpenSSL 변형을 사용하는 경우, docs에서 테스트된 명령 양식을 확인합니다.
3. 명세 config 경로에서 tilde 확장을 검증:
   ```bash
   OPENCLAW_AUDIT_CONFIG=~/.openclaw/security-audit.json \
   node skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs --enable-suppressions
   ```
예상 : 경로는 올바르게 해결 (또는 확장 된 위치에 명확한 파일 기반 오류).

## 윈도우 검증 (PowerShell)

1. 명세 Node 테스트 실행:
   ```powershell
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   ```
예상 : 모든 패스.

2. 명세 공급 능력 Shell env 경로 확장 동작:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '$env:USERPROFILE\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
예상 : 경로 토큰은 확장 / 정상화 또는 대상 파일이 누락 된 경우 명확한 오류로 실패합니다.

3. 명세 탈출 된 리터럴 토큰 거부 :
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '\$HOME\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
예상 : `Unexpanded home token` 오류; 리터 `$HOME`와 디렉토리 생성.

# # # # # # # # # # 라인 종료 Sanity

1. 명세 LF 정책 확인은 현재:
   ```bash
   test -f .gitattributes && grep -n "eol=lf" .gitattributes
   ```
예상 : 스크립트 / 구성 파일 패턴은 LF를 적용합니다.

2. 명세 CRLF-prone 체크 아웃 후, 여전히 스크립트를 확인:
   ```bash
   bash -n scripts/populate-local-feed.sh
   bash -n scripts/populate-local-skills.sh
   ```
예상 : `^M` shebang/parse 오류가 없습니다.

## Explicit 버그 검사: 리터 `$HOME` 없음 연락처

1. 명세 리터/escaped 토큰으로 경로 구성.
2. 명세 설정/설치 명령을 실행합니다.
3. 명세 Verify 명령은 토큰 오류로 일찍 실패합니다.
4. `$HOME` 세그먼트 디렉토리가 작업 디렉터리에 생성되지 않았습니다.

예상 결과: **Laral `$HOME`를 포함하는 디렉터리가 지원되는 설정 스크립트에 의해 생성됩니다. 더 보기

## 소스 참조
- .gitattributes의
- 스크립트/populate-local-feed.sh
- 스크립트/populate-local-skills.sh
- 기술/클래스/테스트/path_resolution.test.mjs
- 기술/클래스/테스트/guarded_install.test.mjs
- 기술/하프스위트/테스트/advisory_suppression.test.mjs
- 기술/클래스/scripts/guarded_skill_install.mjs
- 기술/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- 기술/openclaw-audit-watchdog/test/suppression_config.test.mjs
