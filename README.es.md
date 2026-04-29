■h1 align="center"
■img src="./img/prompt-icon.svg" alt="prompt-icon" ancho="40"
  ClawSec: Suite de habilidades de seguridad para agentes de IA
■img src="./img/prompt-icon.svg" alt="prompt-icon" ancho="40"
■/h1 título

"Cierto"

## Protege tus agentes OpenClaw, NanoClaw, Hermes y Picoclaw con una suite de seguridad completa

<h4>Traído por <a href="https://prompt.security">Prompt Security</a>, la plataforma de seguridad para IA</h4>

■/div titulada

"Cierto"

! [Prompt Security Logo](./img/Black+Color.png)
■img src="./public/img/mascot.png" alt="clawsec mascot" ancho="200" /

■/div titulada

"Cierto"

🌐 **En vivo en: [https://clawsec.prompt.security](https://clawsec.prompt.security) [https://prompt.security/clawsec](https://prompt.security/clawsec)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)

■/div titulada

-...

## 🌍 Traducciones

- English (source of truth): [README.md](README.md)
- Español: `README.es.md`

## ✅ Estado de traducción (Fase 1)

Esta traducción en español cubre el flujo principal de onboarding y operación.
Para detalles de bajo nivel, schema completo y notas avanzadas de CI/CD, consulta el README en inglés.

## 🦞 ¿Qué es ClawSec?

ClawSec es una **suite completa de habilidades de seguridad para plataformas de agentes de IA**. Proporciona monitoreo de seguridad unificado, verificación de integridad e inteligencia de amenazas para proteger la arquitectura cognitiva del agente frente a inyección de prompts, deriva y/o instrucciones maliciosas.

### Plataformas compatibles

- **OpenClaw** (MoltBot, Clawdbot y clones): suite completa con instalador de habilidades, protección de integridad de archivos y auditorías de seguridad
- **NanoClaw**: seguridad para bot de WhatsApp en contenedor, con herramientas MCP para monitoreo de advisories, verificación de firmas e integridad de archivos
- **Hermes**: habilidades nativas de Hermes para verificación de feed firmado, verificación protegida con contexto de advisories, generación determinista de attestation, fail-closed verification y detección de drift de baseline
- **Picoclaw**: chequeos livianos de postura de seguridad en gateway de IA, con awareness de advisories, detección de drift de configuración, verificación de artefactos de release y paquete opcional separado de self-pen-testing

### Capacidades principales

- **📦 Instalador de suite**: instalación de todas las habilidades de seguridad con un solo comando y verificación de integridad
- **🛡️ Protección de integridad de archivos**: detección de drift y auto-restauración de archivos críticos del agente (`SOUL.md`, `IDENTITY.md`, etc.)
- **📡 Advisories de seguridad en vivo**: polling automatizado de CVEs del NVD e inteligencia comunitaria
- **🔍 Auditorías de seguridad**: scripts de auto-chequeo para detectar marcadores de prompt injection y vulnerabilidades
- **🔐 Verificación por checksums**: hashes SHA256 para artefactos de habilidades
- **Health checks**: actualizaciones y verificación de integridad automatizadas para habilidades instaladas

-...

## 🚀 Inicio rápido

### Para agentes de IA

```bash
# Instala la suite de seguridad de ClawSec
npx clawhub@latest install clawsec-suite
```

Después de instalar, la suite puede:
1. Descubrir protecciones instalables desde el catálogo de habilidades publicado
2. Verificar la integridad de releases con checksums firmados
3. Configurar monitoreo de advisories y flujos de protección basados en hooks
4. Añadir chequeos programados opcionales

Opción manual/source-first:

> Lee https://github.com/prompt-security/clawsec/releases/latest/download/SKILL.md y sigue las instrucciones de instalación.

### Para humanos

Copia esta instrucción a tu agente:

> Instala ClawSec con `npx clawhub@latest install clawsec-suite`, y luego completa los pasos de setup desde las instrucciones generadas.

### Notas de shell y SO

Los scripts de ClawSec se dividen entre:
- Tooling cross-platform en Node/Python (`npm run build`, hooks/setup `.mjs`, `utils/*.py`)
- Flujos POSIX shell (`*.sh`, la mayoría de snippets de instalación manual)

Para Linux/macOS (`bash`/`zsh`):
- Usa variables home sin comillas simples o con comillas dobles: `export INSTALL_ROOT="$HOME/.openclaw/skills"`
- **No** uses comillas simples con variables expandibles (por ejemplo, evita `'$HOME/.openclaw/skills'`)

Para Windows (PowerShell):
- Prefiere construir rutas de forma explícita:
- `$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\\skills"`
- `node "$env:INSTALL_ROOT\\clawsec-suite\\scripts\\setup_advisory_hook.mjs"`
- Los scripts POSIX `.sh` requieren WSL o Git Bash.

Si ves rutas tipo `~/.openclaw/workspace/$HOME/...`, una variable home se pasó de forma literal. Re-ejecuta con ruta absoluta o con expresión home expandible.

-...

## 🧭 Documentación por plataforma y suite

La documentación detallada vive en los módulos del wiki:
- NanoClaw: [wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- Hermes: [wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- Picoclaw: [wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)
- Picoclaw auto-pen-testing: [wiki/modules/picoclaw-self-pen-testing.md](wiki/modules/picoclaw-self-pen-testing.md)
- ClawSec Suite (OpenClaw): [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- Pipelines CI/CD: [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Instalación rápida:
- NanoClaw: [skills/clawsec-nanoclaw/INSTALL.md](skills/clawsec-nanoclaw/INSTALL.md)
- Hermes: `skills/hermes-attestation-guardian/`
- Picoclaw guardian: `skills/picoclaw-security-guardian/`
- Picoclaw self-pen-testing: `skills/picoclaw-self-pen-testing/`
- Suite: `skills/clawsec-suite/`

-...

## 📡 Feed de advisories de seguridad

ClawSec mantiene un feed de advisories continuamente actualizado, poblado automáticamente desde la National Vulnerability Database (NVD) de NIST.

### URL del feed

```bash
# Obtener advisories recientes
curl -s https://clawsec.prompt.security/advisories/feed.json | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

Endpoint canónico: `https://clawsec.prompt.security/advisories/feed.json`  
Mirror de compatibilidad (legacy): `https://clawsec.prompt.security/releases/latest/download/feed.json`

### Palabras clave monitoreadas

El feed consulta CVEs relacionados con:
- **OpenClaw**: `OpenClaw`, `clawdbot`, `Moltbot`
- **NanoClaw**: `NanoClaw`, `WhatsApp-bot`, `baileys`
- **Picoclaw**: `Picoclaw`, gateways ligeros de IA, exposición de gateway MCP
- Patrones de prompt injection
- Vulnerabilidades de seguridad en agentes

### Contexto de explotabilidad

ClawSec enriquece advisories de CVE con **contexto de explotabilidad** para ayudar a evaluar riesgo real, más allá del score CVSS bruto.

Puede incluir:
- **Evidencia de exploit**: si hay exploits públicos activos
- **Estado de weaponization**: si hay integración en frameworks comunes de ataque
- **Requisitos de ataque**: prerequisitos para explotar (acceso de red, autenticación, interacción de usuario)
- **Evaluación de riesgo**: nivel contextualizado que combina severidad técnica y explotabilidad

Esto ayuda a priorizar vulnerabilidades de amenaza inmediata frente a riesgos teóricos.

-...

## 🛠️ Desarrollo local

### Prerrequisitos

- Node.js 20+
- Python 3.10+ (herramientas offline)
- Npm

#### Setup

```bash
# Instala dependencias
npm install

# Arranca servidor de desarrollo
npm run dev
```

### Poblar datos locales

```bash
# Poblar catálogo de skills desde skills/
./scripts/populate-local-skills.sh

# Poblar advisory feed con CVEs reales del NVD
./scripts/populate-local-feed.sh --days 120

# Generar exportes llms desde wiki/ (preview local)
./scripts/populate-local-wiki.sh

# Entry point directo del generador (usado por predev/prebuild)
npm run gen:wiki-llms
```

Notas:
- `npm run dev` y `npm run build` regeneran automáticamente exportes `llms.txt` (`predev`/`prebuild`).
- `public/wiki/` es salida generada (local + CI) y está gitignored intencionalmente.

### Build

```bash
npm run build
```

-...

## 📁 Estructura del proyecto

```text
├── advisories/
├── components/
├── pages/
├── wiki/
├── scripts/
├── skills/
├── utils/
├── .github/workflows/
└── public/
```

Para la estructura detallada (scripts, workflows y paquetes de habilidades), consulta el README principal en inglés: [README.md](README.md).

-...

## 🤝 Contribuir

¡Contribuciones bienvenidas! Revisa [CONTRIBUTING.md](CONTRIBUTING.md).

### Enviar advisories de seguridad

¿Encontraste un vector de prompt injection, skill malicioso o vulnerabilidad? Repórtalo en GitHub Issues:

1. Abre un issue nuevo con la plantilla **Security Incident Report**
2. Completa campos requeridos (severidad, tipo, descripción, skills afectados)
3. Un maintainer revisa y agrega `advisory-approved`
4. El advisory se publica automáticamente en el feed como `CLAW-{YEAR}-{ISSUE#}`

Guía detallada: [CONTRIBUTING.md#submitting-security-advisories](CONTRIBUTING.md#submitting-security-advisories)

### Añadir nuevas skills

1. Crea carpeta bajo `skills/`
2. Agrega `skill.json` con metadata requerida y SBOM
3. Agrega `SKILL.md` con instrucciones legibles por agente
4. Valida con `python utils/validate_skill.py skills/your-skill`
5. Envía PR para review

## 📚 Fuente de verdad de la documentación

Todo el contenido wiki se edita en `wiki/` dentro de este repo. El GitHub Wiki (`<repo>.wiki.git`) se sincroniza desde `wiki/` vía `.github/workflows/wiki-sync.yml` cuando cambia `wiki/**` en `main`.

Los exportes para LLM se generan desde `wiki/` hacia `public/wiki/`:
- `/wiki/llms.txt` exporta `wiki/INDEX.md` (o índice fallback generado si falta `INDEX.md`)
- `/wiki/<page>/llms.txt` exporta la página wiki individual

-...

## 📄 Licencia

- Código fuente: GNU AGPL v3.0 o posterior — ver [LICENSE](LICENSE)
- Fuentes en `font/`: licencia separada — ver [`font/README.md`](font/README.md)

-...

"Cierto"

**ClawSec** · Seguridad Prompt, SentinelOne

🦞 Fortaleciendo flujos agentic, skill por skill.

■/div titulada
