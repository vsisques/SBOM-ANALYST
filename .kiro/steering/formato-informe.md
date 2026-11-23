---
inclusion: always
---

# Formato de entregables del análisis SBOM

Todos los entregables van en `output/`. Misma convención que nessus-analyst.

## Informe Word

Se genera con `build_outputs.py` sobre la plantilla corporativa
`.kiro/skills/sbom-vuln-triage/assets/BX000XX_REPXXXXXXed0100_XXXX_SBOM_ANALYSIS_TEMPLATE.docx`.
No se crean Word desde cero ni se modifica la plantilla.

- **Título de portada**: `<ELEMENTO> SBOM ANALYSIS` en MAYÚSCULAS (ej. `CORE5G SBOM ANALYSIS`).
  Nunca debe quedar `TEMPLATE`.
- **Código**: `BXXXXXX_REPXXXXXX`, lo asigna el usuario. **Pregúntalo; no lo inventes.**
- **Fichero**: `<CÓDIGO>ed0100_<ELEMENTO>_SBOM_ANALYSIS.docx`
  (ej. `B500023_REP030602ed0100_CORE5G_SBOM_ANALYSIS.docx`).
- Confirma título y código con el usuario antes de generar.

Estructura (la de la plantilla):
1. **INTRODUCCIÓN**: "Este informe analiza las vulnerabilidades relacionadas con el SBOM
   generado el DD/MM/AAAA sobre el sistema <NOMBRE> en su versión <VERSIÓN>.", formato y
   SHA-256 del SBOM, herramienta y versión, y el contexto que dé el usuario.
2. **DESARROLLO**: recuento por severidad, tabla Severidad × (Aplicables / No aplicables /
   Pendientes), limitaciones y un apartado (Heading 2) por hallazgo, ordenado de más a menos
   grave: `<ID> - <componente> - <SEVERIDAD> - <VEREDICTO>`, con justificación, evidencias
   (tipo, detalle, fuente) y **Remediación** si es real.
3. **CONCLUSIONES**: vulnerabilidades clasificadas en Aplicables / No aplicables /
   Pendientes de verificar, y dentro de cada tipo por gravedad.
4. **REFERENCIAS** y **CONTROL DE CAMBIOS** (fecha de generación y "Versión inicial").

Redacción: español con acentuación correcta, informe autocontenido, sin credenciales, rutas
internas ni datos personales. Recordar al usuario: al abrir en Word, aceptar "actualizar
campos" para regenerar el índice.

## Documento VEX

- `<CÓDIGO>ed0100_<ELEMENTO>_SBOM_VEX.openvex.json` (OpenVEX 0.2.0)
- `<CÓDIGO>ed0100_<ELEMENTO>_SBOM_VEX.cdx.json` (CycloneDX 1.5 con `vulnerabilities`)

## Veredictos permitidos

| Veredicto | Significado | OpenVEX | CycloneDX VEX |
|---|---|---|---|
| `VULNERABLE` | Afectado y sin corregir | `affected` | `exploitable` |
| `CORREGIDO` | Versión instalada incluye el fix | `fixed` | `resolved` |
| `NO_AFECTADO` | Componente presente pero la vulnerabilidad no aplica | `not_affected` | `not_affected` |
| `MITIGADO` | Existe mitigación verificada | `not_affected` (`inline_mitigations_already_exist`) | `not_affected` |
| `FALSO_POSITIVO` | El emparejamiento paquete↔CVE es erróneo | `not_affected` | `false_positive` |
| `PENDIENTE` | Falta evidencia | `under_investigation` | `in_triage` |

## Reglas de evidencia (las aplica `build_outputs.py`)

- Todo veredicto distinto de `PENDIENTE` lleva al menos una evidencia con
  `kind` (`sbom`, `tool-output`, `advisory`, `user-statement`, `command-output`),
  `detail` y `source` (comando, URL o "usuario, AAAA-MM-DD").
- `NO_AFECTADO` exige `justification` de OpenVEX: `component_not_present`,
  `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary` o `inline_mitigations_already_exist`.
- `VULNERABLE` exige `action` (remediación concreta).
- `FALSO_POSITIVO` y `MITIGADO` exigen `impact_statement` que explique el motivo.
- Si la única evidencia es `user-statement`, el informe lo marca como "declarado por el
  usuario, no verificado de forma independiente".

### Reglas del VEX

- Productos identificados por **purl** tomado del SBOM; nunca se construye a mano.
- `author` y `timestamp`: autor dado por el usuario y fecha real de generación.
- Un VEX nuevo no sustituye a otro previo sin confirmarlo; incrementa `version` si el
  usuario aporta el anterior.
- Para filtrar con Grype: `grype sbom:<sbom> --vex output/<fichero>.openvex.json`.

## Comprobación antes de entregar

- `build_outputs.py` termina con "Validación correcta" (incluye la del Word).
- Todos los hallazgos de las severidades analizadas aparecen en el informe (el script lo cruza
  con `scan_counts`).
- El usuario ha revisado y confirmado los veredictos.

## Severidad

La del escáner (Grype), con su fuente indicada en cada hallazgo. No se recalcula ni se estima.
