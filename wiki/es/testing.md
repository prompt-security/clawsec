<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../testing.md
Review status: draft
-->

# Testing

## Testing Strategy
- El repositorio utiliza verificación en capas en lugar de un comando `npm test` raíz.
- La confianza básica proviene de las puertas de forro/tipo/construcción más la habilidad local suites de pruebas de nodos.
- Python y shell tooling se validan mediante controles de seguridad y forro dedicados.
- Las tuberías de flujo de trabajo ejecutan las mismas clases de comandos utilizadas en la automatización local pre-push.

## Verification Layers
← Layer ← Comandos
Silencio.
Controles de Frontend/static TEN ESLint + `tsc --noEmit` + `npm run build` ANTE TS/TSX corrección y construcción de viabilidad. Silencio
Exámenes de la unidad de Habilidad Silencio `node skills/<skill>/test/*.test.mjs` ANTE Signature, matching, suppression, installer contracts. Silencio
← Calidad de Python TENIDO `ruff check utils/`, `bandit -r utils/ -ll` ANTE Utility correctness and security patterns. Silencio
TEN Shell/script quality TEN ShellCheck + manual script smoke runs ← Higiene del script y robustez del comando. Silencio
tención CI escáneres de seguridad Silencio Trivy, auditoría npm, CodeQL, Scorecard tención Dependencia, configuración y postura de seguridad de cadena de suministro. Silencio
tención Local pre-push security scan TEN Opcional `gitleaks detect` vía `scripts/prepare-to-push.sh` ANTE La detección de fugas secretas antes de empujar. Silencio

## Skill Test Matrix
← Habilidad tóxica Archivos de prueba
Silencio.
TENIDO `clawsec-suite` ANTE `feed_verification`, `guarded_install`, `path_resolution`, pruebas de fuzz ANTES Controles de firmas, gatitas de asesoramiento, seguridad de ruta, solidez de combinación. Silencio
tención `openclaw-audit-watchdog` Silencioso de supresión config y hacer pruebas TEN Config parsing, comportamiento de supresión, reportar formato. Silencio
Silencio `clawsec-clawhub-checker` Silencio `reputation_check.test.mjs` Silencio Validación de entrada y comportamiento de determinación de reputación. Silencio

## CI Workflow Coverage
Silencioso de trabajo Silencioso Silencio
Silencio.
Silencio `ci.yml` Silencio PR/push a `main` Silencio Lint/type/build, cheques de Python, escaneos de seguridad, pruebas de habilidad. Silencio
TEN `codeql.yml` TENER PR/push/schedule TEN JS/TS static security analysis. Silencio
Silencio `scorecard.yml` Silencio agenda/push Silencio Presentación de informes de posturas de cadena de suministro y carga SARIF. Silencio
confidencialidad `skill-release.yml` Etiquetas de la vida + PRs TEN Version parity and release artifact verification. Silencio

## Comandos locales de prueba
```bash
# baseline frontend + config checks
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

```bash
# representative skill tests
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
```

## Patrones de fracaso para ver
- Los accesorios de firma/pruebas pueden fallar en el desajuste clave/pago cuando los archivos esperados se regeneran incoherentemente.
- Las pruebas de la resolución del camino fallan intencionadamente en los tokens del hogar escapados; este comportamiento es esperado y relevante para la seguridad.
- Los scripts locales que confían en los binarios `openclaw` o `clawhub` pueden fallar en entornos donde estos CLI están ausentes.
- La lógica de deplorar/renunciar puede pasar localmente mientras que falla en el CI si la firma de secretos o permisos de flujo de trabajo difieren.

## Orden de prueba sugerida
1. Ejecute `./scripts/prepare-to-push.sh` para una puerta local completa.
2. Ejecutar directamente las pruebas de habilidad local impactadas.
3. Para los cambios de alimentación/signación, ejecute primero las pruebas de verificación de suite (`feed_verification`, `guarded_install`).
4. Para cambios de flujo de trabajo o liberación, también ejecute `scripts/validate-release-links.sh` y script de consistencia clave.

## Update Notes
- 2026-02-26: Referencias de origen actualizadas a la lista de verificación `wiki/platform-verification.md` migrada.

## Referencias Fuente
- AGENTS.md
- scripts/prepare-to-push.sh
- scripts/validate-release-links.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/skill-release.yml
- habilidades/clawsec-suite/test/feed_verification.test.mjs
- habilidades/clawsec-suite/test/guarded_install.test.mjs
- habilidades/clawsec-suite/test/path_ resolution.test.mjs
- habilidades/openclaw-audit-watchdog/test/suppression_config.test.mjs
- habilidades/clawsec-clawhub-checker/test/reputation_check.test.mjs
- wiki/platform-verification.md
