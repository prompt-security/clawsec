# Flujo de localización

## Objetivo
Definir un pipeline repetible para localización de documentación (README y wiki) en ClawSec.

## Alcance
- Idioma fuente: inglés (`README.md`, `wiki/*.md`)
- Idioma traducido actual: español (`README.es.md`, `wiki/es/*.md`)
- Idiomas futuros: `wiki/<lang>/...` y `README.<lang>.md`

## Reglas de fuente de verdad
1. Los archivos en inglés son canónicos.
2. Las traducciones deben preservar exactamente comandos, rutas, bloques de código e identificadores.
3. Nombres de producto y skills no se traducen (`ClawSec`, `OpenClaw`, `NanoClaw`, `Hermes`, `Picoclaw`).
4. Si la cobertura de traducción es parcial, el archivo traducido debe declararlo.

## Convenciones de carpetas
- Traducciones README:
- `README.es.md`
  - Futuro: `README.fr.md`, `README.de.md`, `README.ja.md`
- Traducciones wiki:
- `wiki/es/INDEX.md`
- `wiki/es/<page>.md`
- Assets de localización:
- `wiki/i18n/terminology-en-es.md`
- `wiki/i18n/translation-tracker.md`

## Flujo de actualización
1. Normalizar docs fuente en inglés.
2. Registrar cambios en `wiki/i18n/translation-tracker.md`.
3. Traducir páginas modificadas preservando estructura Markdown.
4. Ejecutar QA (enlaces, comandos, terminología).
5. Ejecutar `npm run gen:wiki-llms`.
6. Abrir PR con páginas traducidas y gaps pendientes.

## Checklist QA
- [ ] Jerarquía de títulos preservada.
- [ ] Snippets de comandos sin cambios.
- [ ] Rutas y URLs sin cambios.
- [ ] Nombres de skills/plataformas sin cambios.
- [ ] Terminología de seguridad consistente.
- [ ] Enlaces de traducción visibles desde índices.
