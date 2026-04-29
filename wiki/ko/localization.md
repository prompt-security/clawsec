# 로컬라이제이션 워크플로우 (한국어)

## 목적
ClawSec README 및 위키 문서를 반복 가능하게 번역/현지화하기 위한 표준 파이프라인을 정의합니다.

## 범위
- 원문(정본) 언어: 영어 (`README.md`, `wiki/*.md`)
- 현재 번역 언어: 스페인어 (`README.es.md`, `wiki/es/*.md`)
- 한국어 파일럿 언어: 한국어 (`README.ko.md`, `wiki/ko/*.md`)
- 향후 언어: `wiki/<lang>/...`, `README.<lang>.md`

## Source of Truth 규칙
1. 영어 문서가 정본입니다.
2. 번역 시 명령어, 파일 경로, 코드 블록, 식별자는 원문과 동일하게 유지합니다.
3. 제품/스킬 이름은 번역하지 않습니다 (`ClawSec`, `OpenClaw`, `NanoClaw`, `Hermes`, `Picoclaw`, 스킬 패키지명).
4. 번역 커버리지가 부분적일 경우, 번역 문서에 범위를 명시합니다.

## 폴더 규칙
- README 번역:
- `README.es.md`의
  - `README.ko.md`
  - 향후 예시: `README.fr.md`, `README.de.md`, `README.ja.md`
- 위키 번역:
  - `wiki/es/INDEX.md`, `wiki/es/<page>.md`
  - `wiki/ko/INDEX.md`, `wiki/ko/<page>.md`
  - 향후 예시: `wiki/fr/<page>.md`, `wiki/de/<page>.md`
- 로컬라이제이션 자산:
- `wiki/i18n/terminology-en-es.md`의
- `wiki/i18n/translation-tracker.md`의
  - `scripts/i18n/qa_check.py`

## 업데이트 워크플로우
1. **원문 정리 우선**
   - 번역 전에 영어 원문의 구조/명확성을 먼저 정리합니다.
2. **변경 추적**
   - `wiki/i18n/translation-tracker.md`에 변경 페이지를 기록합니다.
3. **변경분 번역**
   - Markdown 구조(헤더 레벨/링크/코드 블록)를 보존합니다.
4. **QA 점검**
   - 링크 해상도, 코드 블록/인라인 명령어 불변성, 용어 일관성을 확인합니다.
5. **내보내기 재생성**
   - `npm run gen:wiki-llms` 실행.
6. **리뷰 및 PR**
   - 번역 완료 페이지와 미완료 범위를 PR에 명시합니다.

## 번역 QA 체크리스트
- [ ] 헤더 계층 유지
- [ ] 명령어 스니펫 불변 및 실행 가능
- [ ] 파일 경로/URL 불변
- [ ] 스킬/플랫폼 이름 불변
- [ ] 보안 용어 일관성
- [ ] `wiki/INDEX.md`에 번역 링크 존재
- [ ] `wiki/<lang>/INDEX.md`에서 미번역 문서는 영어 원문으로 연결

## 권장 언어 확장 순서
1. 스페인어 (`es`) — 기본선 완료
2. 한국어 (`ko`) — 파일럿 진행 중
3. 프랑스어/독일어 (`fr`, `de`) — 기술 사용자층 확장
4. 일본어 (`ja`) — 고품질 플랫폼 문서 확장

## 소스 참조
- `wiki/localization.md`
- `wiki/es/localization.md`
- `wiki/ko/INDEX.md`
- `wiki/i18n/translation-tracker.md`
- `scripts/i18n/qa_check.py`
