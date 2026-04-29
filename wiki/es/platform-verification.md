<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../platform-verification.md
Review status: draft
-->

Lista de verificación de la plataforma

Utilice esta lista de verificación para validar la portabilidad y el comportamiento de manejo de caminos después de cambios.

## Linux Verification

1. Ejecutar las pruebas del núcleo del nodo:
   ```bash
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
   ```
Se espera: todas las pruebas pasan.

2. No verifique ninguna aceptación literal del camino `$HOME`:
   ```bash
   CLAWSEC_LOCAL_FEED='\$HOME/advisories/feed.json' \
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Se espera: salidas no cero con error `Unexpanded home token`.

3. Verificar las obras de expansión `$HOME`:
   ```bash
   HOME=/tmp/clawsec-home node skills/clawsec-suite/test/path_resolution.test.mjs
   ```
Se espera: las pruebas de expansión `$HOME` pasan.

## MacOS Verification

1. Ejecute la misma suite de pruebas Node que Linux.
2. Confirme que se documentan los supuestos de la ruta de la herramienta OpenSSL:
- Si utilizas las variaciones LibreSSL/OpenSSL, asegúrate de utilizar formularios de comando probados de los docs.
3. Verificar la expansión de inclinación en el camino de config:
   ```bash
   OPENCLAW_AUDIT_CONFIG=~/.openclaw/security-audit.json \
   node skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs --enable-suppressions
   ```
Se espera: la ruta resuelve correctamente (o el error de archivo claro no encontrado en la ubicación ampliada).

## Verificación de Windows (PowerShell)

1. Ejecutar pruebas de Nodo:
   ```powershell
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   ```
Se espera: pasen todos.

2. Verificar el poder Shell env ruta comportamiento de expansión:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '$env:USERPROFILE\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Se espera: el token de ruta se expande/normaliza o falla con un error claro si faltan los archivos de destino.

3. Verify escape literal token rejection:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '\$HOME\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Se espera: error `Unexpanded home token`; no creación de directorio con literal `$HOME`.

## Line Endings Sanity

1. La política de confirmación está presente:
   ```bash
   test -f .gitattributes && grep -n "eol=lf" .gitattributes
   ```
Se espera: script/config patrones de archivo ejecuten LF.

2. Después de un checkout prono CRLF, verifique los scripts todavía parse:
   ```bash
   bash -n scripts/populate-local-feed.sh
   bash -n scripts/populate-local-skills.sh
   ```
Se espera: ningún error `^M` shebang/parse.

## Explicit Bug Check: No Literal `$HOME` Creación del directorio

1. Configure un camino con un token literal/escaped.
2. Ejecute el comando setup/install.
3. Verify command fails early with token error.
4. Confirmar no `$HOME` directorio de segmento fue creado bajo directorios de trabajo.

Resultado esperado: ** ningún directorio que contenga `$HOME` literal son creados por scripts de configuración compatibles. #

## Referencias Fuente
- .gitattributes
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- habilidades/clawsec-suite/test/path_ resolution.test.mjs
- habilidades/clawsec-suite/test/guarded_install.test.mjs
- habilidades/clawsec-suite/test/advisory_suppression.test.mjs
- habilidades/clawsec-suite/scripts/guarded_skill_install.mjs
- habilidades/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- habilidades/openclaw-audit-watchdog/test/suppression_config.test.mjs
