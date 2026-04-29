<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../migration-signed-feed.md
Review status: draft
-->

# Migration Record: Unsigned Feed → Signed Feed (Completed)

## 1) Objetivo y situación

Document how ClawSec advisory distribution moved from unsigned `feed.json` delivery to detached-signature verification, with compatibility kept for legacy clients.

Situación actual en `main`:
- La publicación de alimentos firmados está activa en los flujos de trabajo consultivos y el flujo de trabajo.
- Los consumidores de Suite y NanoClaw predeterminan firmar puntos finales de alimentación.
- La conducta no firmada sólo existe como bypass de compatibilidad explícita (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`).

## 2) Base de referencia (hoy, después de la migración)

Vías de alimentación actuales en uso activo:
- Fuente de la verdad: `advisories/feed.json`
- Firma de origen: `advisories/feed.json.sig`
- Copia de habilidad: `skills/clawsec-feed/advisories/feed.json`
- Firma de copia de la piel: `skills/clawsec-feed/advisories/feed.json.sig`
- Copia de las páginas: `public/advisories/feed.json`
- Firma de páginas: `public/advisories/feed.json.sig`
- Última copia del espejo: `public/releases/latest/download/advisories/feed.json` (+ `.sig`)

Por defecto del consumidor actual:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- URL predeterminada: `https://clawsec.prompt.security/advisories/feed.json`

## 3) Principios de migración

- ** Publicación final**: publicar firmas antes de ejecutar la verificación.
**Apenado rápido sólo durante la transición**: el período de compatibilidad temporal es explícito y con plazos.
- **Enrollo asegurado**: hacer cumplir la verificación después de la telemetría confirma la publicación firmada estable.
- **Regreso rápido**: preservar un camino de regreso a un comportamiento sin firmar mientras la causa raíz es investigada.

## 4) Línea temporal gradual (histórica)

### Fase 0 — Preparación (Completa)

Entregas:
- claves de firma generadas y huellas digitales grabadas
- Secretos GitHub creados
- clave(s) públicas añadidos en repo
- gobooks aprobados (`security-signing-runbook.md`, este archivo)

Criterios de salida:
- huellas digitales clave verificadas por el revisor
- Controles de rama/flujo de trabajo protegidos

### Fase 1 - Firma de la CI activada, sin cumplimiento del cliente (Completed)

Aplicar:
- añadir paso de firma de alimentos/flujo de trabajo para producir `advisories/feed.json.sig`
- Producción opcional `advisories/checksums.json` + `.sig`
- asegurar que CI verifica firmas antes de publicar artefactos

Actualizar también el despliegue:
- copiar artefactos `.sig` a `public/advisories/`
- espejo `.sig` en `public/releases/latest/download/advisories/`

Criterios de salida:
- firmas generadas con éxito para todas las rutas de actualización de alimentación
- desplegar artefactos contienen tanto carga útil como compañeros de firma

### Fase 2 - Apoyo dual-read/dual-verify al consumidor (completo)

Aplicar en consumidores:
- leer `feed.json` y `feed.json.sig`
- verificar con llave pública
- mantener bajo control temporal sin señalización durante la ventana de migración

Validación:
- prueba remoto camino firmado
- probar el camino de regreso firmado local
- test invalid signature rejection

Criterios de salida:
- lógica de verificación liberada y probada
- no fallas de verificación falsos positivos en el período de empapado

### Fase 3 - Ejecución (completa)

Acciones:
- deshabilitar el comportamiento temporal sin firmar en los caminos predeterminados
- añadir las puertas CI/publish que fallan cuando `.sig` falta
- anunciar fecha de ejecución en notas de liberación y documentos

Criterios de salida:
- todos los clientes de producción verifican firmas por defecto
- ninguna dependencia de alimentación no firmada en el flujo de instalación estándar

### Fase 4 - Estabilización (en curso)

Acciones:
- ejecutar el primer simulacro de rotación clave
- perforación de mesa redondeada
- migración estrecha con revisión posterior a la ejecución

## 5) Plan de retroceso

### Rollback triggers

Inicie la devolución si se produce alguno de los siguientes:
- fallas sostenidas de verificación de firmas entre clientes
- El flujo de trabajo de firma no puede producir firmas válidas
- compromiso clave sospechoso, pero aún no se ha desplegado la llave de reemplazo
- ruta de despliegue publica pares de carga/signatura desajustados

## Rollback levels

## Nivel 1 (preferido): Ventana de bypass de verificación, mantenga la publicación firmada

Usar cuando: firmar es saludable, el verificador del lado cliente tiene un defecto.

Acciones:
1. Re-enable comportamiento temporal de aceptación no firmada en la rama de liberación del cliente.
2. Entrega de parche con fecha de vencimiento explícita para bypass.
3. Mantenga activo el oleoducto para evitar la brecha de autenticidad.

Objetivo de recuperación: restaurar la verificación estricta dentro de 24 a 48h.

### Level 2: Signed pipeline paused, unsigned feed temporary authoritative

Utilizar cuando: firmar el oleoducto es inestable o producir artefactos inconsistentes.

Acciones:
1. Desactivar el flujo de trabajo de firma o paso de firma.
2. Seguir publicando `advisories/feed.json` sin firmar a través de los flujos de trabajo existentes.
3. Revertir las puertas de despliegue que requieren artefactos `.sig`.
4. Abrir registro de incidentes y tiempo de seguimiento en modo no firmado.

Objetivo de recuperación: restaurar la publicación firmada ASAP, idealmente.

### Level 3: Full release freeze

Use cuando: compromiso o integridad del repositorio/flujos de trabajo está en duda.

Acciones:
1. Pause feed mutation and deployment workflows.
2. Restaurar archivos de asesoramiento/flujos de trabajo conocidos.
3. Rotar claves y credenciales.
4. Reanuda el oleoducto sólo después del inicio de la revisión de seguridad.

## Roll-forward after rollback

- identificar la causa raíz
- añadir pruebas de regresión / puertas
- redistribuir artefactos firmados
- publicar incidente + resumen de remediación

## 6) Plan de comunicación

For enforcement and rollback events, communicate:
- ¿Qué cambió?
- acción esperada del operador/cliente
- duración del modo de compatibilidad temporal (si existe)
- comandos de verificación para usuarios

Canales recomendados:
- Notas de liberación GitHub
- actualizaciones del repositorio README/docs
- informe de emisión/incidente en el repositorio

## 7) Lista de verificación de go/no go

Sólo si todos son verdaderos:
- La tasa de éxito del flujo de trabajo de firma es estable
- las firmas se reflejan en todos los puntos finales de alimentación documentados
- ruta de verificación del consumidor probada para retroceso remoto + local
- el propietario de la devolución es asignado y accesible
- el procedimiento de rotación clave ha sido seco al menos una vez

## Referencias Fuente
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- habilidades/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- habilidades/clawsec-suite/scripts/guarded_skill_install.mjs
- asesorías/feed.json
- wiki/security-signing-runbook.md
