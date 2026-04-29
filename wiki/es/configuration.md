<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../configuration.md
Review status: draft
-->

# Configuración

## Scope
- La configuración abarca los ajustes de construcción de frontend, las rutas de alimentación de tiempo de ejecución, los desencadenantes de flujo de trabajo y los contratos de metadatos de habilidad.
- La mayoría de controles sensibles a tiempo de ejecución son variables ambientales prefijadas con `CLAWSEC_` o `OPENCLAW_`.
- La normalización del camino es sensible a la seguridad y rechaza intencionalmente literales sin resolver.

## Core Runtime Variables
Silencio Variable ← Default Silencio Usado por
Silencio.
TEN `CLAWSEC_FEED_URL` ANTE Hosted advisory URL TEN Suite hook and guarded installer feed loading. Silencio
Silencio `CLAWSEC_FEED_SIG_URL` Silencio `<feed>.sig` Silencio Fuente de firma independiente. Silencio
Silencio `CLAWSEC_FEED_CHECKSUMS_URL` Silencio `checksums.json` cerca de la URL de alimentación TEN Opcional checksum-manifest source. Silencio
Silencio `CLAWSEC_FEED_PUBLIC_KEY` Silencio Suite-local PEM file ← Verificación de la firma Feed. Silencio
TENIDO `CLAWSEC_ALLOW_UNSIGNED_FEED` TENIDO `0` TENIDO Bandera de circunvalación migratoria temporal. Silencio
Silencio `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` Silencio `1` Silencio Permite verificación de suma-manifiesto. Silencio
Silencio `CLAWSEC_HOOK_INTERVAL_SECONDS` Silencio `300` Silencioso de la exploración de ganchos. Silencio

## Path Resolution Rules
Silencio Silencio Silencio Silencio Silencioso
Silencio.
Silencio `~` expansion ← Resolvado para detectar directorio de inicio ← Funciones de utilidad de ruta compartida en scripts de suite/watchdog. Silencio
Silencio `$HOME` / `${HOME}` expansion tención Resolvido cuando no escaped  durable Las mismas utilidades. Silencio
Silencio Windows case tokens ← `%USERPROFILE%`, `$env:USERPROFILE` normalizado TENIDOS Mismo utilities. Silencio
Silencio Tokens Escaped (`\$HOME`) Silencio Rechazado con error explícito ← Impide la creación accidental del directorio literal. Silencio
tención Sendero explícito inválido Silencio Puede retroceder a la ruta predeterminada con la advertencia de los ayudantes `resolveConfiguredPath`. Silencio

## Frontend and Build Configuration
- `vite.config.ts` define el puerto (`3000`), host (`0.0.0.0`), y el alias de ruta (`@`).
- `index.html` proporciona Tailwind runtime config, fuentes personalizadas y tokens de color base.
- `tsconfig.json` utiliza la resolución del módulo del paqueter, `noEmit` y la configuración del tiempo de ejecución JSX.
- `eslint.config.js` aplica TS, React, ganchos y reglas de forro específicas para scripts.

## Skill Metadata Configuración
Silencioso Grupo de Campo Silencioso Ubicación
Silencio.
Silencio Identidad de la habilidad básica Ø `skills/*/skill.json` TENIDO Nombre/versión/autor/license/descripción metadatos. Silencio
Silencio SBOM lista de archivos Silencio `skill.json -> sbom.files` Silencio Declara artefactos que requieren liberación. Silencio
Metadatos de plataformas ← `openclaw` o `nanoclaw` bloquean los requisitos de CLI, disparadores, consejos de capacidad de plataforma. Silencio
Metadatos del catálogo Silenciosos `skills/clawsec-suite/skill.json -> catalog` TENIDO Comportamiento integrado/default/consentimiento para miembros de la suite. Silencio

Configuración del flujo de trabajo
- La configuración de programación existe en las entradas `cron` (`poll-nvd-cves`, `codeql`, `scorecard`).
- El flujo de trabajo de lanzamiento espera el patrón de nombres de etiquetas `<skill>-v<semver>`.
- El flujo de trabajo de despliegue se activa con eventos exitosos de CI/release `workflow_run` y envío manual.
- La acción de firma compuesta requiere entradas clave privadas y verifica firmas inmediatamente después de la firma.

## Ejemplos Snippets
```bash
# run guarded install with explicit local signed feed paths
CLAWSEC_LOCAL_FEED="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json" \
CLAWSEC_LOCAL_FEED_SIG="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json.sig" \
CLAWSEC_FEED_PUBLIC_KEY="$HOME/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem" \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill clawtributor --dry-run
```

```json
{
  "name": "example-skill",
  "version": "1.2.3",
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Install docs" }
    ]
  }
}
```

## Operational Notes
- Mantenga la firma de llaves fuera del repositorio e inyecte solo a través de GitHub Secrets.
- Preferir caminos absolutos o expresiones hogareñas sin escatimar en entornos locales cambian las variables.
- Tratar el modo de alimentación sin firmar como soporte de migración temporal, no operación normal.
- Re-run release-link validation al editar URLs `SKILL.md` para evitar referencias de artefacto roto.

## Referencias Fuente
- vite.config.ts
- index.html
- tsconfig.json
- eslint.config.js
- habilidades/clawsec-suite/skill.json
- habilidades/clawsec-nanoclaw/skill.json
- habilidades/clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs
- habilidades/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- habilidades/clawsec-suite/scripts/guarded_skill_install.mjs
- scripts/validate-release-links.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/skill-release.yml
- .github/actions/sign-and-verify/action.yml
