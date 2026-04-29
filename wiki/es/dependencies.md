<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../dependencies.md
Review status: draft
-->

# Dependencias

## Build and Runtime
Layer ← Dependencias Primarias
Silencio.
Silencio Frontend runtime Silencio `react`, `react-dom`, `react-router-dom`, `lucide-react` ANTE UI rendering, routing, iconography. Silencio
Silencio Markdown rendering ← `react-markdown`, `remark-gfm` ANTE Render habilidad docs/readmes y wiki in-app paginas de marcado. Silencio
Silencio Construir herramientas Silenciosos `vite`, `@vitejs/plugin-react`, `typescript` TEN Fast TS/TSX bundling and production builds. Silencio
Las utilidades de Python ← stdlib + `ruff`/`bandit` policy from `pyproject.toml` TEN Validate/package skills and run static checks. Silencio
Silencio Automatización de cascos TEN `bash`, `jq`, `curl`, `openssl`, `sha256sum`/`shasum` ANTES Feed polling, signing, checksum generation, release checks. Silencio

## Dependency Details
Silencioso paquete ← Versión anterior
Silencio.
Silencio `react` / `react-dom` Silencio `^19.2.4` Silencio Frontend runtime Silencio
Silencio `react-router-dom` Silencio `^7.13.1` Silencio Frontend routing ←
Silencio `lucide-react` Silencio `^0.575.0` Silencioso icono UI conjunto
Silencio `vite` Silencio `^7.3.1` Silencio Servidor Dev + construya
Silencio `typescript` Silencioso `~5.8.2` Silencio Tipo de comprobación
Silencio `eslint` Silencio `^9.39.2` Silencio JS/TS linting Silencio
Silencio `@typescript-eslint/*` Silencio `^8.55.0` / `^8.56.0` Silencio TS lint parser/rules ←
Silencio `fast-check` Silencio `^4.5.3` Silencio Pruebas de estilo de propiedad/fuzz

← Sobrevivir Silencioso Versión grabada
Silencio.
Silencio `ajv` Silencio `6.14.0` Silencio Seguridad y estabilización de compatibilidad. Silencio
Silencio `balanced-match` Silencio `4.0.3` Silencio Transitive vulnerability control. Silencio
TENIDO `brace-expansion` TENIDO `5.0.2` TENIDO Durmiendo la dependencia transitiva. Silencio
Silencio `minimatch` Silencio `10.2.1` Silencio Comportamiento de dependencia determinista. Silencio

## External Services
← Servicio Silencioso usado por Silencioso
Silencio.
TEN NVD API (`services.nvd.nist.gov`) TENIDO `poll-nvd-cves` flujo de trabajo + script de alimentación local ¦ Pull CVEs por palabra clave/fecha ventana. Silencio
Silencio GitHub API tención Desploy/release workflows TEN Discover releases, download assets, publish outputs. Silencio
← Páginas de GitHub ← Deploy workflow ← Servir el sitio estático y los artefactos espejo. Silencio
← ClawHub CLI/registry tención Install scripts + trabajos opcionales publicitarios tención Instalar y publicar habilidades. Silencio
tención Opcional SMTP/sendmail local Silencio `openclaw-audit-watchdog` scripts Silencio Entrega informes de auditoría por correo electrónico. Silencio

## Development Tools
← Herramienta Silencioso Silencioso
Silencio.
TEN ESLint TENIDO `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0` TENIDO Frontend y forro de script. Silencio
Silencio TipoScript Silencio `npx tsc --noEmit` tención Compile-time TS checks contract. Silencio
TENIDO Ruff TENIDO `ruff check utils/` TENIDO Estilo Python y cheques de patrón de errores. Silencio
Silencio Bandit Silencio `bandit -r utils/ -ll` Silencio Controles de seguridad Python. Silencio
Silencio Trivy Silencio flujo de trabajo + funcionamiento local opcional Silencio FS/config vulnerabilidad escaneos. Silencio
Silencio Gitleaks Silencio `scripts/prepare-to-push.sh` Funcionamiento local opcional tención detección de fugas secretas antes de empujar. Silencio

## Ejemplos Snippets
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.2.4",
    "react-router-dom": "^7.13.1"
  }
}
```

```toml
[tool.ruff]
target-version = "py310"
line-length = 120

[tool.bandit]
exclude_dirs = ["__pycache__", ".venv"]
skips = ["B101"]
```

## Compatibilidad Notes
- Cuenta de scripts locales para las diferencias de macOS vs Linux en `date` y `stat`.
- Algunos flujos de trabajo/scripts requieren funciones OpenSSL utilizadas con Ed25519 y `pkeyutl -rawin`.
- El soporte de Windows es más fuerte para herramientas basadas en Nodo; los caminos de shell POSIX pueden requerir WSL/Git Bash.
- Los consumidores alimentados incluyen bypasses de compatibilidad para las fases migratorias, pero el modo firmado es el estado fijo previsto.

## Versioning Notes
- Las etiquetas de liberación de habilidad siguen `<skill>-v<semver>` y son analizadas por la automatización CI/deploy.
- La validación de PR impone la paridad de la versión entre `skill.json` y el frontmatter `SKILL.md` para habilidades contuídas.
- El índice de habilidades públicas mantiene la última versión descubierta por habilidad para la visualización UI.
- Los manifiestos de artefactos firmados (`checksums.json`) se versionan por versión e incluyen hashes de archivos y URLs.

## Referencias Fuente
- paquete.json
- paquete-lock.json
- pyproject.toml
- eslint.config.js
- tsconfig.json
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
