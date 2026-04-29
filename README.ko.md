# ClawSec: AI 에이전트를 위한 보안 스킬 스위트

> 한국어 번역 (초기 버전)

## 🌍 번역
- English (source of truth): [README.md](README.md)
- Español: [README.es.md](README.es.md)
- 한국어: `README.ko.md`

## ✅ 번역 상태 (Korean Phase 1)
이 한국어 문서는 핵심 온보딩/운영 흐름을 우선 제공합니다.
고급 스키마, 전체 CI/CD 세부사항, 최신 기준 문서는 영어 README를 참고하세요.

## 🦞 ClawSec란?
ClawSec은 **OpenClaw, NanoClaw, Hermes, Picoclaw 같은 AI 에이전트 플랫폼용 종합 보안 스킬 스위트**입니다.
프롬프트 인젝션, 드리프트, 악성 지시로부터 에이전트 동작을 보호하기 위해
통합 보안 모니터링, 무결성 검증, 위협 인텔리전스를 제공합니다.

## 🚀 빠른 시작

### AI 에이전트용
```bash
npx clawhub@latest install clawsec-suite
```

설치 후 ClawSec 스위트는 다음을 수행할 수 있습니다:
1. 공개 스킬 카탈로그에서 설치 가능한 보호 기능 탐색
2. 서명된 체크섬을 통한 릴리스 무결성 검증
3. advisory 모니터링 및 훅 기반 보호 흐름 설정
4. 선택적 스케줄 점검 추가

### 사람 운영자용
에이전트에게 다음 지시를 전달하세요:

· `npx clawhub@latest install clawsec-suite`로 ClawSec을 설치 한 다음 생성 된 지침에서 설정 단계를 완료하십시오.

## 🧭 위키 문서
플랫폼/스위트 상세 문서는 wiki 모듈을 참고하세요:
- [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- [wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- [wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- [wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)

## 📡 보안 advisory 피드
정식 엔드포인트:
- `https://clawsec.prompt.security/advisories/feed.json`

## 🛠️ 로컬 개발
```bash
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run gen:wiki-llms
npm run dev
```

## 📄 라이선스
- Source code: GNU AGPL v3.0 or later — [LICENSE](LICENSE)
- Font assets: [`font/README.md`](font/README.md)
