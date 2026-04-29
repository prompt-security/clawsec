<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../glossary.md
Review status: draft
-->

# Glosario

## Terms
TENIDO TÉPTIMO TENIDO Definición ANTE
Silencio.
← Asesoramiento Feed Silencio documento JSON (`feed.json`) que contiene asesorías de seguridad para habilidades/platformas. Silencio
Silencio Especificador Afectado Silencio Selector de Habilidad como `skill@1.2.3`, comodín, o rango utilizado en la lógica de juego. Silencio
TEN Guarded Install Silencio Comportamiento del instalador de dos pasos que requiere confirmación explícita cuando los avisos coinciden. Silencio
← Archivos SBOM ← Lista de artefactos declarados por Habilidad en `skill.json` utilizada para embalaje y validación. Silencio
Archivo de firmas TEN Base64 (`.sig`) almacenado por separado de la carga útil firmada. Silencio
Silencio Checksum Manifest Silencio File hash map (`checksums.json`) utilizado para verificar la integridad de la carga útil. Silencio

## Skill Packaging Terms
TENIDO TÉPTIMO TENIDO Definición ANTE
Silencio.
Tag tóxico etiqueta Git formateado como `<skill>-v<semver>` utilizado por la automatización de liberación. Silencio
tención de lanzamiento de activos Silenciosos archivos adjuntos a la liberación de GitHub (zip, `skill.json`, checksums, signatures). Silencio
tención Catálogo Índice Silencioso `public/skills/index.json`, lista generada consumida por el catálogo web. Silencio
← Componentes embedded Silencio Capability paquete de una habilidad incluida en otra (por ejemplo, la alimentación incrustada en suite). Silencio

## Condiciones de asesoramiento y seguridad
TENIDO TÉPTIMO TENIDO Definición ANTE
Silencio.
← Verificación perdida de Fail TEN Rechazar la carga útil si la validación de la firma o el chequesum falla. Silencio
← Modo de Compatibilidad Insigned tención Sendero de bypass temporal habilitado a través de `CLAWSEC_ALLOW_UNSIGNED_FEED=1`. Silencio
tención permanente Regla tención Config entrada que coincida con `checkId` y `skill` para suprimir hallazgos conocidos/aceptados. Silencio
TEN Key Fingerprint TEN SHA-256 digest of DER-encoded public key used for key consistency checks. Silencio

## Runtime and Platform Terms
TENIDO TÉPTIMO TENIDO Definición ANTE
Silencio.
← OpenClaw Hook Silencio Runtime event handler (`clawsec-advisory-guardian`) que comprueba las advertencias. Silencio
Silencio NanoClaw IPC Silencio Host/container task exchange for advisory ref, signature verification, integrity checks. Silencio
← Integrity Baseline tención Guardado hahes/snapshots aprobado para archivos protegidos. Silencio
Hash-Chained Audit Log Registro de auditorías sólo de apéndice donde cada entrada depende del hash anterior. Silencio

## CI/CD Terms
TENIDO TÉPTIMO TENIDO Definición ANTE
Silencio.
Contaminación del NVD CVEs Workflow ← Corriente de trabajo programada que fetches y transforma CVEs NVD en asesorías. Silencio
TEN Comunidad Asesoramiento flujo de trabajo Silencioso flujo de trabajo desencadenado por la etiqueta de edición que publica asesorías comunitarias aprobadas. Silencio
Flujo de trabajo de liberación de Habilidades TENIDO Embalaje/envase/envase/envase publicado por etiqueta para habilidades. Silencio
Silencio Páginas de Implementación Flujo de trabajo Silencioso que construye activos del sitio y espejos liberación / artefactos advisorios. Silencio

## Referencias Fuente
- tipos.
- habilidades/clawsec-suite/skill.json
- habilidades/clawsec-nanoclaw/skill.json
- habilidades/clawsec-suite/scripts/guarded_skill_install.mjs
- habilidades/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- habilidades/clawsec-suite/hooks/clawsec-advisory-guardian/lib/suppression.mjs
- habilidades/clawsec-nanoclaw/guardian/integrity-monitor.ts
- scripts/populate-local-feed.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
