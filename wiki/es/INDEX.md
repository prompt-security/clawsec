# Índice del Wiki

## Resumen
- Propósito: documentar ClawSec como catálogo web, canal de advisories firmados y sistema de distribución de múltiples skills de seguridad.
- Stack tecnológico: frontend React 19 + Vite + TypeScript, scripts Node/ESM, utilidades Python, automatización Bash y pipelines de GitHub Actions.
- Puntos de entrada: `index.tsx`, `App.tsx`, `scripts/prepare-to-push.sh`, `scripts/populate-local-feed.sh`, `scripts/populate-local-skills.sh`, y workflows en `.github/workflows/`.
- Dónde empezar: lee [Overview (ES)](overview.md), luego [Architecture (EN)](../architecture.md), y después los módulos según el área que vas a editar.
- Cómo navegar: usa Guides para temas transversales, Operations para runbooks y planes de migración, Modules para límites de implementación, y Source References al final de cada página para saltar al código.

## Empieza aquí
- [Overview (ES)](overview.md)
- [Architecture (EN)](../architecture.md)

## Guías
- [Flujo de localización](localization.md)
- [Dependencies](../dependencies.md)
- [Data Flow](../data-flow.md)
- [Configuration](../configuration.md)
- [Testing](../testing.md)
- [Workflow](../workflow.md)
- [Security](security.md)

## Operaciones
- [Security Signing Runbook](../security-signing-runbook.md)
- [Signed Feed Migration Plan](../migration-signed-feed.md)
- [Platform Verification Checklist](../platform-verification.md)
- [Cross-Platform Remediation Plan](../remediation-plan.md)

## Módulos
- [Frontend Web App](../modules/frontend-web.md)
- [ClawSec Suite Core](../modules/clawsec-suite.md)
- [ClawSec Scanner](../modules/clawsec-scanner.md)
- [Hermes Attestation Guardian](../modules/hermes-attestation-guardian.md)
- [Hermes Attestation Guardian Draft History (Archived)](../modules/hermes-attestation-guardian-draft-history.md)
- [NanoClaw Integration](../modules/nanoclaw-integration.md)
- [Picoclaw Security Guardian](../modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](../modules/picoclaw-self-pen-testing.md)
- [Runtime Traffic Guardian Baseline](../modules/runtime-traffic-guardian-baseline.md)
- [Automation and Release Pipelines](../modules/automation-release.md)
- [Local Validation and Packaging Tools](../modules/local-tooling.md)

## Glosario
- [Glossary](../glossary.md)

## Metadata de generación
- [Generation Metadata](../GENERATION.md)

## Notas de actualización
- 2026-05-04: Added runtime traffic guardian baseline module and platform-specific skill scaffolds for OpenClaw, Hermes, NanoClaw, and Picoclaw.
- 2026-04-27: Añadida traducción inicial al español (`wiki/es/INDEX.md`, `wiki/es/overview.md`) como fase 1.
- 2026-04-26: Separado Picoclaw self-pen-testing en `picoclaw-self-pen-testing`; actualizados docs y referencias de módulo Picoclaw.
- 2026-04-25: Añadido módulo Picoclaw Security Guardian para awareness de advisories, detección de drift de configuración y verificación de cadena de suministro.

## Referencias de código
- `README.md`
- `README.es.md`
- `App.tsx`
- `package.json`
- `scripts/prepare-to-push.sh`
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `skills/clawsec-suite/skill.json`
- `skills/clawsec-scanner/skill.json`
- `skills/hermes-attestation-guardian/skill.json`
- `skills/hermes-traffic-guardian/skill.json`
- `skills/nanoclaw-traffic-guardian/skill.json`
- `skills/openclaw-traffic-guardian/skill.json`
- `skills/picoclaw-security-guardian/skill.json`
- `skills/picoclaw-self-pen-testing/skill.json`
- `skills/picoclaw-traffic-guardian/skill.json`
- `wiki/modules/runtime-traffic-guardian-baseline.md`
- `.github/workflows/ci.yml`
