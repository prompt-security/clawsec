<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (es)
Source: ../remediation-plan.md
Review status: draft
-->

# Cross-Platform Remediation Plan

## Fase 1: Cierre de riesgo inmediato (completo)

### Milestones
- Implementar la expansión explícita del home-path + rechazo de token sospechoso en las rutas de funcionamiento/instalación de alto riesgo.
- Agregue pruebas de regresión para la expansión del camino y el rechazo de token.
- Agregue la política de `.gitattributes` LF.
- Ampliar la cobertura de Node lint/type/build CI a Linux/macOS/Windows.
- Actualizar los docs de instalación con guía específica de shell y solución de problemas literal `$HOME`.

### Outcomes
- Literal `$HOME` path propagation bug addressed at source.
- La guía central/instalación de configuración ahora falla rápidamente en las fichas de ruta inválidas.

-...

## Fase 2: Paridad de Windows para los flujos de trabajo críticos (Siguiente)

### Quick wins
- Add Power Sumas equivalentes para los comandos de instalación/control manual más usados en:
- `skills/clawsec-suite/SKILL.md`
- `skills/openclaw-audit-watchdog/SKILL.md`
- `README.md`
- Agregue un `scripts/preflight.mjs` ligero para detectar herramientas faltantes e imprimir consejos de instalación específicos del sistema operativo.

### Milestones
- Poder nativo Instrucciones de Shell para la configuración de suite y gancho de asesoramiento.
- WSL/Git Bash recuento documentado donde los scripts de shell son inevitables.

-...

## Fase 3: Reducir POSIX Superficie de Shell (Refactor Deeper)

### Refactor targets
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `scripts/release-skill.sh`

### Approach
- Recopilar caminos críticos en Node/Python para eliminar la dependencia de los oleoductos `jq/sed/awk/find/chmod`.
- Envoltorios de conchas preseleccionados para compatibilidad atrasada; ruta a nuevas implementaciones multiplataforma.

### Migration notes
- Mantenga los viejos puntos de entrada de script como envoltorios para al menos una liberación menor.
- Emitir advertencias de deprecación con órdenes de migración exactas.

-...

## Fase 4: endurecimiento del CI y verificación continua

### Milestones
- Mantenga la matriz de Nodo (Linux/macOS/Windows) según sea necesario.
- Agregue pruebas de humo de Windows específicas para el manejo de la ruta de instalación.
- Agregue el cheque macOS para notas de compatibilidad de comandos OpenSSL cuando sea relevante.

### Estrategia de ensayo
- Local:
- Ejecutar suites de ensayo Node que cubren la expansión del camino / supresión / comportamiento de instalación.
- Ejecute cheques de sintaxis para scripts modificados.
- CI:
- Controles Matrix Node + pruebas de instalador/supresión/pata vigiladas.
- Se mantienen solo escáneres de seguridad Linux, pero explícitamente marcados como Linux-scopio.

-...

## Rollout / Release Considerations

- No hay cambios de interfaz de ruptura introducidos en este conjunto de parches; el comportamiento es más estricto sólo para los tokens de ruta inválidos/desgastados.
- Comunicar en notas de liberación:
- la validación de tokens ahora aplicada
- cómo corregir los valores inválidos citados env
- Donde Poder Ejemplos de Shell viven

## Referencias Fuente
- .gitattributes
- .github/workflows/ci.yml
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- scripts/release-skill.sh
- habilidades/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- habilidades/clawsec-suite/scripts/guarded_skill_install.mjs
- habilidades/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- wiki/platform-verification.md
