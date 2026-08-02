<!--
Translation source: ../skill-feature-matrix.md
Last synchronized: 2026-08-02
Method: Codex-assisted translation with repository terminology and structural parity checks
Review status: native-speaker review pending
-->

# Matriz de funciones por skill

Esta página conserva la comparación de funciones por paquete de ClawSec. La página en inglés es la fuente canónica; esta traducción mantiene el mismo orden de paquetes y el mismo significado de los estados.

El resumen por plataforma agrupa la cobertura de la familia actual de paquetes. Una función puede requerir una skill separada en lugar de estar incluida en el punto de entrada principal de la plataforma.

## Resumen por plataforma

| Plataforma | Gestión de advisories y del feed | Integridad y drift | Auditoría y postura | Control de riesgo de instalación | Verificación del artefacto candidato a instalar | Informes comunitarios | Tráfico en runtime |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw | Verificación de firmas y consultas externas | Mediante el paquete opcional `soul-guardian` | Disponible | Controles por advisory y reputación | Sin verificador integrado de artefactos candidatos; instalación delegada a ClawHub | Opt-in | Solo especificación |
| NanoClaw | Verificación de firmas con fail-closed | Integrada | Auditoría de advisories y vulnerabilidades | Comprobación previa de advisories | Integración de NanoClaw implementada; verificación de firmas de paquetes candidatos con una clave anclada | Opt-in | Solo especificación |
| Hermes | Verificación de firmas con fail-closed | Integrada | Verificación de atestaciones y postura | Solo comprobación previa de advisories | Sin verificación del artefacto candidato | Opt-in | Solo especificación |
| Picoclaw | Consume un estado del feed verificado aguas arriba | Integrada | Perfilado de postura integrado + revisión independiente de solo lectura | Sin control de instalación | Verificación ejecutable de artefactos de release; clave que el invocador considera de confianza | Opt-in | Solo especificación |

Cada paquete publicado de ClawSec documenta una comprobación previa manual del manifiesto firmado para su propio archivo independiente. Esa base común de integridad de releases no se repite en cada fila. `claw-release` también guía la producción de esos releases firmados. La columna de verificación de candidatos se reserva para artefactos de instalación distintos del archivo propio de cada paquete.

## Cobertura paquete por paquete

<!-- skill-feature-matrix:start -->
| Nombre de la skill | Plataforma | Gestión de advisories y del feed | Integridad y drift | Auditoría y postura | Control de riesgo de instalación | Verificación del artefacto candidato a instalar | Informes comunitarios | Tráfico en runtime |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claw-release` | OpenClaw | No | No | No | No | Sin verificación del artefacto candidato | No | No |
| `clawsec-clawhub-checker` | OpenClaw + integración con `clawsec-suite` | Control de advisories de la suite | No | No | Reputación de ClawHub + control de advisories de la suite | Sin verificación del artefacto candidato | No | No |
| `clawsec-feed` | OpenClaw | Paquete de datos de advisories; consulta gestionada por la suite o el operador; sin verificación de firma del feed | No | No | No | Sin verificación del artefacto candidato | No | No |
| `clawsec-nanoclaw` | NanoClaw | Verificación de firmas con fail-closed | Baselines de archivos + restauración opcional | Auditoría de advisories/vulnerabilidades; sin pruebas activas | Comprobación previa de advisories | Integración de NanoClaw implementada; verificación de firmas de paquetes candidatos con clave fijada | No | No |
| `clawsec-scanner` | OpenClaw | Consulta externa de CVE; sin verificación del feed firmado | No | Auditoría de dependencias, SAST y hooks estáticos; sin explotación activa | No | Sin verificación del artefacto candidato | No | No |
| `clawsec-suite` | OpenClaw | Verificación del feed firmado + del manifiesto de checksums | Mediante `soul-guardian` opcional; no integrado | No | Control por advisory + confirmación explícita | Sin verificador integrado de artefactos candidatos; solo una utilidad genérica para verificar firmas separadas; instalación delegada a ClawHub | No | No |
| `clawtributor` | Todas las plataformas principales | No | No | No | No | No | Borrador local sujeto a aprobación + envío manual | No |
| `hermes-attestation-guardian` | Hermes | Verificación de firmas con fail-closed | Drift de atestaciones, configuración y anclas de confianza | Verificación de atestaciones y postura | Solo comprobación previa de advisories | Sin verificación del artefacto candidato | No | No |
| `hermes-traffic-guardian` | Hermes | No | Solo exportación de postura planificada | No | No | No | No | Solo especificación; sin proxy de runtime |
| `nanoclaw-traffic-guardian` | NanoClaw | No | No | No | No | No | No | Solo especificación; sin proxy de runtime |
| `openclaw-audit-watchdog` | OpenClaw | No | No | Auditoría automatizada con modo profundo; sin explotación activa | No | No | No | No |
| `openclaw-traffic-guardian` | OpenClaw | No | No | No | No | No | No | Solo especificación; sin proxy de runtime |
| `picoclaw-security-guardian` | Picoclaw | Consume un estado del feed verificado; la verificación criptográfica se realiza aguas arriba | Drift determinista de perfil y configuración | Comprobaciones de postura de solo lectura | No | Verificación ejecutable de artefactos de release de Picoclaw mediante la verificación del checksum y del manifiesto firmado; clave que el invocador considera de confianza | No | No |
| `picoclaw-self-pen-testing` | Picoclaw | No | No | Revisión de postura self-pen de solo lectura; sin explotación activa | No | No | No | No |
| `picoclaw-traffic-guardian` | Picoclaw | No | Solo exportación de perfil planificada | No | No | No | No | Solo especificación; sin proxy de runtime |
| `soul-guardian` | OpenClaw | No | Baseline de archivos del workspace, detección de drift y restauración opcional | No | No | No | No | No |
<!-- skill-feature-matrix:end -->

## Definiciones de estado

- **Verificación de firmas** significa que el paquete verifica por sí mismo el material de confianza firmado. El **monitoreo**, la **consulta externa** y el **estado verificado aguas arriba** se indican por separado.
- El **control de riesgo de instalación** describe comprobaciones de advisories o reputación antes de instalar. No demuestra la procedencia del artefacto candidato.
- La **comprobación previa común para el propio paquete** solo cubre el archivo de release correspondiente. La columna de verificación de candidatos registra la comprobación de otros artefactos de instalación.
- **Auditoría y postura** incluye comprobaciones estáticas, de dependencias, advisories, atestaciones y postura de solo lectura. La matriz indica cuándo no existe explotación activa.
- **Mediante paquete adicional opcional** significa que el paquete principal puede descubrir o coordinar una skill separada, pero no incluye esa función.
- **Solo especificación** significa que existen el directorio, los metadatos, el frontmatter y el contrato de implementación, pero no se distribuye un proxy de runtime.
- **Solo exportación de postura/perfil planificada** describe un contrato de integración en una especificación traffic-guardian, no un monitor de drift distribuido.

`clawtributor` es un paquete multiplataforma para informar incidentes. Sus valores `No` significan que las demás funciones de protección de la matriz quedan fuera de su ámbito de informes, no que el paquete esté inactivo.

## Mantenimiento

Las 16 filas de paquetes se recuperaron de la anterior matriz del README. Los ejes se separaron cuando los antiguos valores binarios confundían monitoreo con verificación, auditoría con pruebas activas, paquetes adicionales con funciones integradas o controles de advisories con procedencia de artefactos.

La matriz debe mantenerse alineada con los directorios de `skills/`. El control de calidad de traducciones verifica que cada matriz localizada conserve los mismos 16 identificadores de paquete, el mismo orden y una estructura de nueve columnas.

## Referencias fuente

- `skills/*/skill.json`
- `skills/*/SKILL.md`
- [Núcleo de ClawSec Suite](../modules/clawsec-suite.md)
- [ClawSec Scanner](../modules/clawsec-scanner.md)
- [Integración con NanoClaw](../modules/nanoclaw-integration.md)
- [Hermes Attestation Guardian](../modules/hermes-attestation-guardian.md)
- [Picoclaw Security Guardian](../modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](../modules/picoclaw-self-pen-testing.md)
- [Baseline de Runtime Traffic Guardian](../modules/runtime-traffic-guardian-baseline.md)
