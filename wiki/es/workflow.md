<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../workflow.md
Review status: draft
-->

# Workflow

## End-to-End Lifecycle
- El desarrollo comienza con la codificación local + la población de datos locales para una presentación realista de la interfaz de usuario.
- PR CI valida suites de calidad/seguridad y pruebas de habilidad.
- PR Pages-verify validates production build/signing behaviour without publishing.
- Paquetes de flujo de trabajo de liberación impulsados por la etiqueta y signos artifactos de habilidad.
- Páginas desplegando espejos de flujo de trabajo liberación / artefactos advisorios y publica el sitio estático.
- Wiki-sync workflow publica repo `wiki/` docs to GitHub Wiki on `main`.
- Los flujos de trabajo programados enriquecen continuamente la visibilidad de la fuente de asesoramiento y la cadena de suministro.

Mapa de flujo de trabajo primario
Silencioso de trabajo Silencioso de la lucha
Silencio.
← CI Silencio PR/push to `main` tención Lint, tipocheck, build, Python checks, security scans, skill tests. Silencio
Silencio Pages Verify TENIDO PRs a `main` ANTE Build Pages artefacto y validar salidas de firma (no publicar). Silencio
← Encuesta NVD CVEs Silencio Cron diario + despacho manual ← Fetch CVEs, transform/dedupe, feed de actualización, artefactos de firma, cambios de PR. Silencio
← Procesamiento Comunidad Asesoramiento TENIDO Etiqueta `advisory-approved` Silencio Forma de emisión Parse, crear asesoría, feed de firma, PR abierto, cuestión de comentarios. Silencio
← Skill Release Silencio Etiquetas de la habilidad + metadatos PR cambios Silencio PR: versión-paridad + cheques de funcionamiento seco; etiquetas: paquete/sign/publicar activos de liberación. Silencio
Silencio Páginas de Despliegue Silencio Exitosa CI/Libertad o envío manual Silencio Discover releases, mirror assets, sign public advisories/checksums, deployment site. Silencio
← Sincronización Wiki tención Empuja a `main` tocando `wiki/**` + despacho manual  Sync `wiki/` en `<repo>.wiki.git` y generar `Home.md` de `INDEX.md`. Silencio

## Local Operator Workflow
TEN TERRITORIO TERRITORIO ANTERIOR ANTERIOR
Silencio.
Silencio Install deps Silencio `npm install` ← Entorno local listo. Silencio
tención Populate local catalog Silencio `./scripts/populate-local-skills.sh` Silencioso `public/skills/index.json` y checksums de archivos. Silencio
Silencio Populate local feed Silencio `./scripts/populate-local-feed.sh --days 120` tención Actualizado local advisory feed copy. Silencio
¦ Generate wiki llms exports Silencio `npm run gen:wiki-llms` Silencio Actualizaciones `public/wiki/llms.txt` y exportaciones por página. Silencio
Silencio Ejecute la puerta local Silencio `./scripts/prepare-to-push.sh` TENIENDO CI-como la señal de paso/fail. Silencio
Silencio Inicio dev UI Silencio `npm run dev` Silencio Vista previa del navegador en el punto final local Vite. Silencio

## Detalles del flujo de trabajo de liberación
- La paridad de versiones y docs se aplican para las vías PR/tag.
- Embalaje de habilidad incluye archivos declarados por SBOM y manifiestos de integridad.
- `checksums.json` está firmado e inmediatamente verificado en ejecución de flujo de trabajo.
- El trabajo opcional public-to-ClawHub funciona después de la exitosa publicación GitHub cuando está configurado.
- Las versiones más antiguas dentro de la misma línea principal pueden ser superadas o eliminadas por la automatización.

## Advisory Workflow Details
- El flujo de trabajo NVD determina la ventana incremental de la alimentación anterior `updated` timetamp.
- Transformar mapas de fase CVE métricas a la gravedad/tipo y normalizar objetivos afectados.
- El flujo de trabajo de asesoramiento comunitario crea identificaciones deterministas (`CLAW-YYYY-NNNN`) de metadatos de emisión.
- Ambos flujos de trabajo de asesoramiento actualizan copias de alimentación y compañeros de firma.

## Ejemplos Snippets
```bash
# manual release prep for a skill
./scripts/release-skill.sh clawsec-feed 0.0.5
# then push tag if running in release branch mode
```

```yaml
# pages deploy depends on successful upstream workflow run
on:
  workflow_run:
    workflows: ["CI", "Skill Release"]
    types: [completed]
```

## Operational Risks
- Los permisos de flujo de trabajo y la inconfiguración de alcance secreto pueden bloquear la firma / publicación.
- Los fallos transitorios NVD/API pueden retrasar la frescura asesora.
- Nombramiento de etiquetas inválidos o desajustes de versiones detienen la automatización de liberación.
- Los scripts locales y el CI pueden divergir si la máquina del operador carece de binarios esperados (`jq`, `openssl`, `clawhub`).

## Referencias Fuente
- scripts/release-skill.sh
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- scripts/generate-wiki-llms.mjs
- .github/workflows/ci.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/pages-verify.yml
- .github/workflows/wiki-sync.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
