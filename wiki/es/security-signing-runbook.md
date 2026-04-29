<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../security-signing-runbook.md
Review status: draft
-->

# ClawSec Signing Operations Runbook

## 1) Propósito

Este manual define los procedimientos operativos para introducir y ejecutar la firma criptográfica en el repositorio ClawSec.

Cubre:
- generación clave
- Gestion secreta GitHub
- Integración del flujo de trabajo de firma
- rotación y revocación clave
- respuesta a incidentes

## 2) Estado operativo actual (importante)

En `main`, los canales de asesoramiento y liberación se firman y verifican por defecto:

- Escritores de comida:
- Actualizaciones `.github/workflows/poll-nvd-cves.yml` `advisories/feed.json` y signos `advisories/feed.json.sig`
- `.github/workflows/community-advisory.yml` hace lo mismo para los informes de emisión aprobados
- ambos artefactos de alimentación firmados en `skills/clawsec-feed/advisories/`
- Carril de publicación Feed:
- `.github/workflows/deploy-pages.yml` publica `public/advisories/feed.json` + `.sig`
- genera y firma `public/checksums.json` + `public/checksums.sig`
- publica clave canónica como `public/signing-public.pem` y `public/advisories/feed-signing-public.pem`
- objetos de compatibilidad con espejos bajo `public/releases/latest/download/` (incluyendo `feed.json`, `feed.json.sig`, `checksums.json`, `checksums.sig`, `signing-public.pem`)
- Alimentar a los consumidores:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- URL de alimentación predeterminada es `https://clawsec.prompt.security/advisories/feed.json`

El modo no firmado sigue siendo un bypass de compatibilidad explícita (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) y no es el modelo operativo estable.

## 3) artefactos firmados por objetivos

### Advisory feed channel
- `advisories/feed.json` (carga)
- `advisories/feed.json.sig` (firma independiente Ed25519; base64)
- `advisories/feed-signing-public.pem` (clave público)

### Canal de artefactos de liberación
- `<release>/checksums.json`
- `<release>/checksums.sig`
- `<release>/signing-public.pem`

## 4) Funciones clave y custodia

**Propietario de seguridad**: aprueba cambios clave en el ciclo de vida y acciones de incidentes.
- **Propietario de Platform**: mantiene flujos de trabajo y secretos GitHub.
- **Revisor**: valida las huellas dactilares en PRs/releases.

Política:
- Las llaves privadas nunca se comprometen
- las claves públicas están comprometidas y revisión de código
- generación clave se produce en la estación de trabajo del operador de confianza o en el entorno respaldado por HSM

## 5) Generación clave (Ed25519)

■ Huye de una estación de trabajo segura. No corras con corredores compartidos de CI.

```bash
# Feed signing keypair
openssl genpkey -algorithm Ed25519 -out feed-signing-private.pem
openssl pkey -in feed-signing-private.pem -pubout -out feed-signing-public.pem

# Release checksums signing keypair (optional separate key)
openssl genpkey -algorithm Ed25519 -out release-signing-private.pem
openssl pkey -in release-signing-private.pem -pubout -out release-signing-public.pem
```

Generar huellas dactilares (store in ticket/change record):

```bash
openssl pkey -pubin -in feed-signing-public.pem -outform DER | shasum -a 256
openssl pkey -pubin -in release-signing-public.pem -outform DER | shasum -a 256
```

Opcional test-sign antes de publicar:

```bash
echo '{"probe":"ok"}' > /tmp/probe.json
openssl pkeyutl -sign -rawin -inkey feed-signing-private.pem -in /tmp/probe.json -out /tmp/probe.sig.bin
openssl base64 -A -in /tmp/probe.sig.bin -out /tmp/probe.sig
openssl base64 -d -A -in /tmp/probe.sig -out /tmp/probe.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey feed-signing-public.pem -in /tmp/probe.json -sigfile /tmp/probe.sig.bin
```

## 6) GitHub secrets setup

### Secretos obligatorios

- `CLAWSEC_SIGNING_PRIVATE_KEY` — Llave privada con código PEM Ed25519 (utilizada para la firma de alimentación y liberación)
- `CLAWSEC_SIGNING_PRIVATE_KEY_PASSPHRASE` — (opcional) contraseña si la clave privada está encriptada

#### Procedure

1. Ir a **Repo Settings → Secretos y variables → Acciones → Nuevo secreto del repositorio**.
2. Paste completo PEM incluyendo cabecera/pieza.
3. Preferencia GitHub ** Secretos del medio ambiente** (con revisores requeridos) para el análisis del flujo de trabajo cuando sea posible.
4. Billete de cambio con:
- nombre secreto
- Creador
- tiempo de creación
- huella clave

### Protección del medio ambiente recomendada

- Solicitar aprobación manual para flujos de trabajo que puedan usar secretos de firma.
- Restringir quién puede editar flujos de trabajo protegidos.
- Permitir la protección de ramas para `main` y requerir revisión para cambios de flujo de trabajo.

## 7) Puntos de integración del flujo de trabajo

Este repo impone la firma como un control post-mutación, pre-publicado.

### Feed pipeline

Puntos de mutación de alimentación actuales:
- `.github/workflows/poll-nvd-cves.yml`
- `.github/workflows/community-advisory.yml`

Comportamiento actual:
- signos de flujo de trabajo `advisories/feed.json` en `advisories/feed.json.sig`
- firma de acciones verifica firmas generadas durante la ejecución del flujo de trabajo
- los artefactos firmados se cometen a través de la automatización PR

### Pautas de tuberías

actual fabricante:
- `.github/workflows/deploy-pages.yml`

Comportamiento actual:
- copias de pago/transmisión a `public/advisories/`
- genera + signos `public/checksums.json` y `public/checksums.sig`
- publica la clave de firma de `public/signing-public.pem` y `public/advisories/feed-signing-public.pem`
- Espejos de asesoramiento + firma / checksum/key compañeros en `public/releases/latest/download/` caminos de compatibilidad

### Gasoducto de liberación de habilidades (recomendado endurecimiento)

Generador de liberación actual:
- `.github/workflows/skill-release.yml`

Comportamiento actual:
- crea `checksums.json`, lo firma como `checksums.sig`, y verifica la firma antes de publicar
- incluye `signing-public.pem` en activos de liberación
- valida la huella generada en clave pública contra el material clave canónico

## 8) Política de rotación y guía

## Rotation cadence
- Rutina: cada 90 días (o política de org más estricta).
- Inmediatamente: sobre sospecha de exposición, cambio de flujo de trabajo no autorizado o desajuste de firma no explicada.

### Rotación de rutina

1. Generar nuevo teclado(s).
2. Open PR que actualiza archivos de clave pública y documentación de huellas dactilares.
3. Agregue nuevas teclas privadas como GitHub secret(s).
4. Combina cambios de flujo de trabajo que utilizan nuevas teclas.
5. Reasignar los últimos manifiestos de alimentación/liberación.
6. Validar la verificación en CI y en un cliente externo.
7. Quitar viejos secretos de llave privada.
8. Mantenga la vieja referencia pública clave sólo siempre que sea necesaria para la verificación histórica.

### Pasos de revocación

1. Desactivar los flujos de trabajo utilizando clave comprometida.
2. Retire los secretos de GitHub comprometidos.
3. Presentar nota de revocación y nueva clave pública.
4. Reasignar los últimos artefactos con llave de reemplazo.
5. Publish incident advisory with timestamp and impacted window.

## 9) Libro de juegos de respuesta de incidentes (consignación específica)

## Triggers
- la verificación de firmas falla para la nueva publicación de feed/release
- compromisos desconocidos / ediciones de flujo de trabajo tocando caminos de firma
- filtrado material clave, registro accidental o acceso secreto sospechoso

#### Severity guide
**SEV-1**: la exfiltración clave confirmada o firmada malintencionadamente carga útil publicada
**SEV-2**: fallas de verificación con causa desconocida
**SEV-3**: incumplimiento de procedimiento, no compromiso activo

### Fases de respuesta

1. **Contenimiento* *
- pausa para firmar y publicar flujos de trabajo
- bloque de alimentación se fusiona si la autenticidad es incierta
2. **Investigación**
- revisar registros de flujo de trabajo
- review commits affecting `.github/workflows/`, `advisories/`, and key files
- determinar los tiempos y artefactos afectados
3. *Erradicación*
- rotar/revocar claves comprometidas
- restaurar objetos de confianza de un compromiso conocido-bueno
4. *Recuperación*
- artefactos de re-signación
- Redistribuir páginas/liberaciones
- verificar a través de la comprobación del cliente independiente
5. **Post-incident* *
- publicar cronograma y resumen de remediación
- endurecer los controles (revisar las puertas, entornos protegidos, alcance secreto)

## 10) Lista de comprobación de pruebas de auditoría

Para cada ciclo de liberación o carrera de señalización de alimentación, retén:
- workflow run URL y compromete SHA
- señalización de huellas digitales en uso
- Registros de resultados de verificación
- Aprobaciones del operador/revisor
- cualquier excepción o racional de bypass

## 11) Criterios de aceptación mínima antes de cambios de política más estrictos

Antes de reforzar aún más la política (por ejemplo, eliminar las vías de bypass de compatibilidad):
- los artefactos firmados se producen consistentemente durante al menos 2 semanas
- desplegar espejos de tuberías compañeros de firma
- un taladro de retroceso y un taladro de rotación clave completado con éxito
- respuesta a incidentes identificados y documentados por el propietario

## Referencias Fuente
- asesorías/feed.json
- asesorías/feed.json.sig
- consejeros/feed-signing-public.pem
- Clawsec-signing-public.pem
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
- scripts/ci/verify_signing_key_consistency.sh
- wiki/migration-signed-feed.md
