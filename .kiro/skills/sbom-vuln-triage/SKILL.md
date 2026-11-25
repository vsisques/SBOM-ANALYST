---
name: sbom-vuln-triage
description: Analiza SBOM (Syft, CycloneDX, SPDX), obtiene vulnerabilidades con Grype, clasifica falsos positivos y vulnerabilidades reales y genera el informe Word (plantilla corporativa) y el VEX (OpenVEX / CycloneDX). Úsala cuando el usuario aporte un SBOM o pida un VEX.
---

# sbom-vuln-triage

Regla de oro: **nada se asume**. Sin evidencia, el veredicto es `PENDIENTE`.
Scripts en `scripts/` (Python 3.9+; el Word requiere python-docx y lxml, ver `requirements.txt`). Rutas relativas a la
carpeta del agente.

## 0. Entorno

```
python .kiro/skills/sbom-vuln-triage/scripts/check_env.py
```
Comprueba Python, python-docx, lxml, Grype y su base de datos. Si algo falta, remite al
README (apartado Instalación) y espera.

## 1. Inventario

```
python .kiro/skills/sbom-vuln-triage/scripts/sbom_inventory.py <sbom> -o work/<nombre>_inventory.json
```

Lee Syft JSON, CycloneDX JSON/XML y SPDX JSON/tag-value. Calcula SHA-256, muestra la fecha
que declara el propio SBOM (si la trae; **confírmala con el usuario**) y lista componentes
(nombre, versión, tipo, purl, CPE, licencias). Informa de componentes sin versión, sin purl
o duplicados: sin purl/CPE Grype no puede emparejarlos, así que **no aparecerán en los
resultados**; lístalos como limitación explícita en el alcance del informe (son vulnerabilidades
potenciales no evaluadas, no componentes libres de ellas). No se convierte el SBOM: Grype lo lee tal cual.

## 2. Obtención de vulnerabilidades (solo Grype)

```
grype version
grype db status
grype sbom:<sbom> --by-cve -o json > work/<nombre>_grype.json
```
- Anota versión de Grype y fecha de construcción de la BD (`grype db status`, campo Built).
- Si la BD es antigua, **pregunta** antes de actualizarla (`grype db update`, requiere red).
  En equipos sin red: `grype db import <db.tar.zst>` con una BD que aporte el usuario.
- `--by-cve` orienta el resultado por CVE cuando existe (si no, queda el GHSA u otro ID).
- Cada match trae `matchDetails` (tipo de emparejamiento: por CPE, más propenso a falsos
  positivos; o por distribución/ecosistema, más fiable), `fix` (versiones corregidas) y
  `vulnerability.severity`. Úsalos en el triaje y cítalos como evidencia (`tool-output`).
- **Cobertura total**: analiza todas las severidades que devuelva Grype (también Low,
  Negligible y Unknown). No se pregunta cuáles analizar ni se descarta ningún CVE antes del
  análisis; el usuario solo puede priorizar el orden.
- Guarda los totales por severidad en `scan_counts` de la spec e incluye todas esas
  severidades en `analyzed_severities`: `build_outputs.py` exige que cada severidad de
  `scan_counts` esté analizada y que los hallazgos coincidan con esos totales.
- Un hallazgo es el par (vulnerabilidad, purl). Solo se deduplica el par idéntico repetido
  (y se dice). Varios CVE sobre el mismo componente son hallazgos distintos, y el mismo CVE
  sobre varios componentes también.

## 3. Triaje por hallazgo

Cada hallazgo = (componente purl, ID de vulnerabilidad). Orden: severidad descendente.
Comprueba y registra:

1. **Emparejamiento**: ¿ecosistema, nombre y versión del SBOM coinciden con el rango
   afectado del aviso? ¿Se emparejó por CPE de otro producto con nombre similar?
2. **Corrección**: ¿hay versión corregida? ¿La distribución aplica backports (la versión
   upstream aparece vulnerable pero el paquete del distro está corregido)? Verifica con
   el aviso de la distribución (con URL), no por memoria.
3. **Datos que solo tiene el usuario** (pregúntalos, no los deduzcas): versión realmente
   instalada/desplegada, si el componente se carga en ejecución, si la función vulnerable
   se invoca, si la entrada es controlable por un atacante, exposición de red,
   mitigaciones, configuración. Ver `references/preguntas-tipo.md`.
4. **Veredicto** con la tabla de `steering/formato-informe-sbom.md` y evidencias.

Si hay muchos hallazgos con el mismo patrón (p. ej. un paquete del SO), agrúpalos para
preguntar una vez, **pero confirma que el patrón aplica a cada componente** antes de
extender el veredicto. Agrupar no exime del análisis: cada CVE queda en la spec con su
propio veredicto y evidencias. Lo no analizado es `PENDIENTE`, nunca omitido.

## 4. Persistencia del progreso

Guarda el estado en `work/<nombre>_spec.json` tras cada ronda de respuestas, para poder
retomar. Ver `references/spec-ejemplo.json`. Campos que da el usuario y que no se inventan:
`element`, `code` (`BXXXXXX_REPXXXXXX`), `sbom_date` (DD/MM/AAAA), `author`, producto y
versión, `analyzed_severities`.

## 5. Generación

```
python .kiro/skills/sbom-vuln-triage/scripts/build_outputs.py work/<nombre>_spec.json
```

Valida la especificación (reglas de evidencia) y genera en `output/`, según `outputs`:
- `<CÓDIGO>ed0100_<ELEMENTO>_SBOM_ANALYSIS.docx` (informe sobre la plantilla de `assets/`;
  título de portada `<ELEMENTO> SBOM ANALYSIS`).
- `<CÓDIGO>ed0100_<ELEMENTO>_SBOM_VEX.openvex.json` y/o `..._SBOM_VEX.cdx.json`.

Confirma título y código con el usuario antes de generar. No se crean Word desde cero ni
se modifica la plantilla. Si la validación falla, corrige la
spec preguntando al usuario lo que falte; nunca rellenes el hueco tú.

Opcional: comprobar el efecto del VEX con
`grype sbom:<sbom> --vex output/<fichero>.openvex.json -o table` (pide confirmación).
