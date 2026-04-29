# Seguridad

## Resumen del modelo de seguridad
- ClawSec protege tanto la distribución de contenido (artefactos firmados) como el comportamiento en runtime (advisory gating, monitoreo de integridad).
- Las anclas de confianza son claves públicas fijadas en el repo y verificadas contra outputs generados por workflows.
- Los consumidores runtime usan por defecto un modelo verification-first, con flags de bypass explícitos solo para migración.

## Controles criptográficos
| Control | Mecanismo | Ubicación |
Silencio.
| Autenticidad del feed | Firmas detached Ed25519 (`feed.json.sig`) | Workflows de advisories + librerías de verificación del consumidor. |
| Integridad de artefactos | Manifiestos de checksum SHA-256 (`checksums.json`) | Workflows de release de skill y deploy de pages. |
| Consistencia de claves | Comparación de fingerprint entre docs + PEM canónicos | `scripts/ci/verify_signing_key_consistency.sh`. |
| Acción de verificación de firma | Acción compuesta de sign+verify en CI | `.github/actions/sign-and-verify/action.yml`. |

## Controles de enforcement en runtime
| Control | Componente | Efecto |
Silencio.
| Advisory hook gating | `clawsec-advisory-guardian` | Alertas y guía cautelosa según advisories coincidentes. |
| Instalador con doble confirmación | `guarded_skill_install.mjs` | Sale con código `42` hasta recibir confirmación explícita en advisories coincidentes. |
| Extensión de reputación | `clawsec-clawhub-checker` | Scoring de riesgo adicional antes de instalar. |
| Signature gate en NanoClaw | `skill-signature-handler.ts` + herramienta MCP | Bloquea instalaciones de paquetes manipulados/no firmados por política. |
| Monitor de baseline de integridad | `soul-guardian` + monitor de integridad NanoClaw | Detección de drift, cuarentena, restauración e historial auditable. |

## Controles de cadena de suministro y CI
- CI ejecuta Trivy, npm audit, CodeQL y Scorecard.
- Los checks locales pre-push pueden ejecutar `gitleaks detect` si `gitleaks` está instalado.
- Los workflows de release validan existencia de SBOM antes de empaquetar.
- El workflow de deploy verifica el fingerprint de la signing key generada contra material de clave canónico.
- La documentación de release incluye comandos de verificación manual para consumidores downstream.

## Playbooks de incidentes y rotación
- `wiki/security-signing-runbook.md` define generación de claves, custodia, rotación y fases de incidentes.
- `wiki/migration-signed-feed.md` define enforcement por etapas y niveles de rollback.
- Los paths de rollback priorizan preservar publicación firmada cuando sea posible y limitar temporalmente cualquier bypass.

## Snippets de ejemplo
```bash
# verificar fingerprint de la clave pública canónica
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
```

```bash
# ejecutar guardrail de consistencia de claves usado en CI
./scripts/ci/verify_signing_key_consistency.sh
```

## Tradeoffs de seguridad conocidos
- El modo de compatibilidad sin firma reduce garantía y debe deshabilitarse cuando termine la migración.
- Algunos paths de deploy toleran assets de checksums legacy sin firma por compatibilidad retroactiva.
- Los checks de reputación dependen de output de tooling externo y pueden incluir falsos positivos/negativos heurísticos.
- Los scripts locales heredan confianza del entorno; un shell local comprometido aún puede subvertir flujos del operador.

## Oportunidades de hardening
- Eliminar flags de compatibilidad unsigned tras estabilizar migración.
- Expandir verificación determinista de checksum/firma para todos los archivos release espejados.
- Añadir tests explícitos para escenarios de falla de firma a nivel workflow.
- Aumentar telemetría runtime para fallas en fetch/verify de advisories y simplificar triage de incidentes.

## Notas de actualización
- 2026-04-27: Traducción inicial al español de `wiki/security.md`.
- 2026-02-26: Referencias de signing y migración movidas desde `docs/` raíz a páginas operativas en `wiki/`.

## Referencias de código
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
