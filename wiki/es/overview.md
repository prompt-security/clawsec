# Sinopsis

## Propósito
- ClawSec es un repositorio orientado a seguridad que combina un catálogo web público con habilidades de seguridad instalables para entornos OpenClaw, NanoClaw, Hermes y Picoclaw.
- El codebase soporta tres rutas de entrega en paralelo: publicación de sitio estático, distribución de advisories firmados y empaquetado de releases por skill en GitHub.
- Los usuarios principales son operadores de agentes, desarrolladores de skills y maintainers que ejecutan automatización de seguridad basada en CI.

![Prompt Security Logo](../assets/overview_img_01_prompt-security-logo.png)
![ClawSec Mascot](../assets/overview_img_02_clawsec-mascot.png)

## Layout del repositorio
| Ruta | Rol | Notas |
Silencio.
| `pages/`, `components/`, `App.tsx`, `index.tsx` | UI Vite + React | Catálogo de skills, feed de advisories y páginas de detalle. |
| `skills/` | Paquetes de skills de seguridad | Cada skill contiene `skill.json`, `SKILL.md` y opcionalmente scripts/tests/docs. |
| `advisories/` | Canal de advisories del repositorio | `feed.json` firmado + `feed.json.sig` y material de claves. |
| `scripts/` | Automatización local | Poblar feed/skills, checks pre-push y helpers de release. |
| `.github/workflows/` | Pipelines CI/CD | CI, releases, polling NVD, ingesta de advisory comunitario y deploy de pages. |
| `utils/` | Utilidades Python | Validación de skills y helpers de empaquetado/checksums. |
| `public/` | Assets estáticos publicados | Media del sitio, advisories espejados y artefactos generados de skills. |
| `wiki/` | Hub de documentación | Arquitectura, runbooks operativos, compatibilidad y guías de verificación. |

## Puntos de entrada
| Entrada | Tipo | Propósito |
Silencio.
| `index.tsx` | Bootstrap frontend | Monta la app React en `#root`. |
| `App.tsx` | Router frontend | Define rutas para home, skills, feed y wiki. |
| `scripts/prepare-to-push.sh` | Flujo dev | Ejecuta checks de lint/type/build/security antes de push. |
| `scripts/populate-local-feed.sh` | Bootstrap de datos | Obtiene CVEs del NVD y actualiza feeds locales de advisories. |
| `scripts/populate-local-skills.sh` | Bootstrap de datos | Construye `public/skills/index.json` y checksums por skill. |
| `scripts/generate-wiki-llms.mjs` | Export de docs | Genera `public/wiki/llms.txt` y exportes wiki por página. |
| `.github/workflows/skill-release.yml` | Entrada de release | Maneja checks PR (paridad de versión/dry-run) y empaquetado/firmado/release basado en tags. |
| `.github/workflows/poll-nvd-cves.yml` | Feed programado | Consulta NVD y actualiza advisories. |

## Artefactos clave
| Artefacto | Producido por | Consumido por |
Silencio.
| `advisories/feed.json` | Poll NVD + workflows comunitarios | UI web, hook de clawsec-suite, instaladores. |
| `advisories/feed.json.sig` | Pasos de firmado en workflow | Verificación de firma en tooling de suite/nanoclaw. |
| `public/skills/index.json` | Workflow de deploy / script local | `pages/SkillsCatalog.tsx` y `pages/SkillDetail.tsx`. |
| `public/wiki/llms.txt` + `public/wiki/**/llms.txt` | Script generador wiki + hooks de build | Exportes wiki para LLM enlazados desde la UI del wiki. |
| `public/checksums.json` + `public/checksums.sig` | Workflow de deploy | Artefactos de integridad publicados para operadores y clientes runtime. |
| `release-assets/checksums.json` | Workflow de release de skill | Consumidores de release que verifican integridad de zips. |
| `skills/*/skill.json` | Autores de skills | Generación de catálogo del sitio, validadores y pipelines de release. |

## Flujos clave
- Desarrollo web local: `npm install` y luego `npm run dev`.
- Preview local de datos de seguridad: ejecuta `./scripts/populate-local-skills.sh` y `./scripts/populate-local-feed.sh` antes de abrir `/skills` y `/feed`.
- Quality gate pre-push: ejecuta `./scripts/prepare-to-push.sh` (opcional `--fix`).
- Ciclo de vida de skill: edita `skills/<name>/`, valida con `python utils/validate_skill.py`, y etiqueta `<skill>-vX.Y.Z` para disparar workflow de release.
- Ciclo de advisories: el polling programado de NVD y la ingesta comunitaria por labels convergen en el mismo feed firmado.

## Snippets de ejemplo
```bash
# UI local + datos locales poblados
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run dev
```

```bash
# checks canónicos de TypeScript usados por CI
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

## Dónde empezar
- Lee `README.md` para posicionamiento del producto y rutas de instalación.
- Abre `App.tsx` y `pages/` para entender el comportamiento de cara al usuario.
- Abre `skills/clawsec-suite/skill.json` para entender el contrato de la suite y sus componentes embebidos.
- Revisa `.github/workflows/ci.yml`, `.github/workflows/pages-verify.yml`, `.github/workflows/skill-release.yml`, `.github/workflows/deploy-pages.yml` y `.github/workflows/wiki-sync.yml` para el comportamiento productivo.

## Cómo navegar
- El comportamiento de UI está centrado en `pages/`; los wrappers visuales están en `components/`.
- La lógica específica de cada skill está aislada por carpeta bajo `skills/`; cada carpeta incluye sus propios scripts/tests/docs.
- El manejo de feeds aparece en tres capas: archivos feed del repositorio, updates de workflows y consumidores runtime (`clawsec-suite`/`clawsec-nanoclaw`).
- Los quality gates operativos viven en `scripts/` y en YAMLs de workflows.
- Para trazas de generación y baseline de actualizaciones, empieza por `wiki/GENERATION.md` y luego ramifica hacia páginas de módulo.

## Errores comunes
- Usar tokens home literales (por ejemplo `\$HOME`) en variables de ruta puede disparar fallas de validación.
- Solicitar JSON desde rutas SPA puede devolver HTML con status 200; las páginas lo tratan como estado vacío.
- El modo bypass de feed no firmado (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) existe solo por compatibilidad de migración y no debe usarse en estado estable.
- La automatización de release espera paridad de versión entre `skill.json` y frontmatter de `SKILL.md`.
- Algunos scripts son POSIX-oriented; en Windows conviene PowerShell o WSL.

## Notas de actualización
- 2026-04-27: Traducción inicial al español en `wiki/es/` como fase 1.
- 2026-02-26: Layout actualizado para apuntar documentación operativa a `wiki/` en lugar del directorio raíz `docs/` (eliminado).

## Referencias de código
- `README.md`
- `README.es.md`
- `package.json`
- `App.tsx`
- `index.tsx`
- `pages/Home.tsx`
- `pages/SkillsCatalog.tsx`
- `pages/SkillDetail.tsx`
- `pages/FeedSetup.tsx`
- `scripts/prepare-to-push.sh`
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `skills/clawsec-suite/skill.json`
- `.github/workflows/ci.yml`
- `.github/workflows/pages-verify.yml`
- `.github/workflows/skill-release.yml`
- `.github/workflows/deploy-pages.yml`
- `.github/workflows/wiki-sync.yml`
