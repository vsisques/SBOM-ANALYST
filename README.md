# sbom-analyst

Agente de Kiro CLI que analiza un **SBOM** (Syft, CycloneDX o SPDX), obtiene sus
vulnerabilidades con **Grype**, separa **falsos positivos** de **vulnerabilidades reales** y
genera:

- el **informe Word** sobre la plantilla corporativa (`<CÓDIGO>ed0100_<ELEMENTO>_SBOM_ANALYSIS.docx`);
- un **documento VEX** (OpenVEX y/o CycloneDX) para filtrar lo ya analizado o mitigado.

**El agente no asume nada.** Pregunta lo que no sabe y deja como `PENDIENTE` (VEX
`under_investigation`) todo hallazgo sin evidencia. `build_outputs.py` se niega a generar
documentos si un veredicto no tiene evidencia.

## Herramientas de detección

Solo **Grype** (https://github.com/anchore/grype). Grype lee directamente SBOM en Syft JSON,
CycloneDX JSON/XML y SPDX JSON/tag-value, y consulta su base de datos local (NVD, GitHub
Advisories, avisos de distribuciones...). No se convierten formatos. Si quieres usar otra
herramienta, díselo al agente: lo confirmará contigo antes.

Syft solo hace falta si quieres **generar** un SBOM; no es necesario para analizar uno existente.

## Instalación (una sola vez por equipo)

### 1. Kiro CLI

Windows (PowerShell):
```powershell
irm 'https://cli.kiro.dev/install.ps1' | iex
kiro-cli login
```
Cierra y abre PowerShell después de instalarlo. Comprueba con `kiro-cli --version` y
`kiro-cli whoami`.

### 2. Python 3.9 o superior y librerías

```
python --version
python -m pip install -r requirements.txt
```
Windows sin Python: `winget install --id Python.Python.3.12 -e` (marca "Add python.exe to
PATH" si usas el instalador de python.org). Con proxy:
`python -m pip install --proxy http://<proxy>:<puerto> -r requirements.txt`.

### 3. Grype (no se instala con pip)

| Sistema | Comando |
|---|---|
| Linux / WSL / macOS | `curl -sSfL https://get.anchore.io/grype \| sudo sh -s -- -b /usr/local/bin` |
| macOS (Homebrew) | `brew install grype` |
| Windows (Chocolatey) | `choco install grype -y` |
| Windows (manual) | descargar el `.zip` de https://github.com/anchore/grype/releases, descomprimir `grype.exe` y añadir su carpeta al `PATH` |

Descarga la base de datos de vulnerabilidades (necesita red; unos cientos de MB):
```
grype db update
```
Equipo **sin acceso a internet**: en otro equipo con red, descarga la base de datos
(`grype db list` indica la URL del `.tar.zst`), cópiala y ejecuta `grype db import <fichero.tar.zst>`.

### 4. Comprobar el entorno

Desde la carpeta `SBOM-ANALYST`:
```
python .kiro/skills/sbom-vuln-triage/scripts/check_env.py
```
Debe terminar en `Entorno correcto`. El agente ejecuta esta comprobación al empezar.

Para que el agente aparezca: `kiro-cli agent list` desde esta carpeta debe mostrar
`sbom-analyst` (agente de tipo *workspace*; responde "sí" a "Trust this workspace?").

## Uso

1. Entra en la carpeta y arranca el agente:
   ```
   cd SBOM-ANALYST
   kiro-cli chat --agent sbom-analyst
   ```
2. Pídele el análisis indicando el SBOM, por ejemplo:
   > Analiza `C:\ruta\core5g.cdx.json`.
   (Coloca los SBOM donde quieras; el agente solo escribe en `work/` y `output/`.)
3. Responde a sus preguntas. Tendrás que aportar, entre otras cosas:
   - elemento (p. ej. CORE5G), producto y versión, título y código `BXXXXXX_REPXXXXXX`;
   - fecha de generación del SBOM y autor del VEX;
   - qué severidades analizar, en lenguaje natural (desde una mínima, hasta una máxima, solo unas concretas o todas menos algunas). Los nombres se escriben en inglés (Critical, High, Medium, Low, Negligible, Unknown), sin importar mayúsculas o minúsculas. Si no indicas nada, solo se analiza la severidad más alta encontrada;
   - por hallazgo: versión realmente instalada, si el componente se carga, si la función
     afectada se usa, exposición de red, mitigaciones (a veces con la salida de un comando
     en la máquina real).
4. Antes de ejecutar comandos o consultar webs, Kiro pide confirmación.
5. El agente presenta resultados parciales y qué sigue pendiente. Puedes parar y retomar:
   el progreso queda en `work/<nombre>_spec.json`.
6. Al terminar, confirma los veredictos y recoge los ficheros en `output/`. Al abrir el Word,
   responde **Sí** a "actualizar campos" para regenerar el índice.
7. Para salir: `/quit`.

### Aplicar el VEX con Grype

```
grype sbom:<sbom> --vex output/<CÓDIGO>ed0100_<ELEMENTO>_SBOM_VEX.openvex.json
```
Grype omite los hallazgos marcados `not_affected` o `fixed`. Los `affected` y
`under_investigation` siguen apareciendo.

### Veredictos

| Veredicto | Significado | OpenVEX | CycloneDX VEX |
|---|---|---|---|
| VULNERABLE | Afectado y sin corregir (exige remediación) | affected | exploitable |
| CORREGIDO | La versión instalada incluye el fix | fixed | resolved |
| NO_AFECTADO | Presente pero no aplica (exige justificación OpenVEX) | not_affected | not_affected |
| MITIGADO | Mitigación verificada | not_affected | not_affected |
| FALSO_POSITIVO | Emparejamiento paquete-CVE erróneo | not_affected | false_positive |
| PENDIENTE | Falta evidencia | under_investigation | in_triage |

## Uso de los scripts sin el agente

```
python .kiro/skills/sbom-vuln-triage/scripts/sbom_inventory.py <sbom> -o work/<n>_inventory.json
grype sbom:<sbom> --by-cve -o json > work/<n>_grype.json
python .kiro/skills/sbom-vuln-triage/scripts/build_outputs.py work/<n>_spec.json
```
Ejemplo de especificación: `.kiro/skills/sbom-vuln-triage/references/spec-ejemplo.json`.

## Problemas frecuentes

| Síntoma | Solución |
|---|---|
| `grype` no se reconoce | Instálalo (apartado 3) y abre una terminal nueva. |
| `check_env.py` falla en python-docx/lxml | `python -m pip install -r requirements.txt` |
| Grype no encuentra la base de datos | `grype db update` (o `grype db import` sin red). |
| Un componente del SBOM no aparece en los resultados | Sin purl ni CPE Grype no puede emparejarlo; `sbom_inventory.py` lo lista como carencia y el informe lo declara. |
| `build_outputs.py` dice "Validación FALLIDA" | Falta evidencia o un dato (código, fecha...) o los hallazgos no cuadran con `scan_counts`. El agente te pedirá lo que falte. |
| `sbom-analyst` no aparece en `kiro-cli agent list` | No estás dentro de la carpeta `SBOM-ANALYST`. |

## Estructura

```
.kiro/agents/sbom-analyst.json            configuración y permisos (solo escribe en work/ y output/)
.kiro/agents/prompts/sbom-analyst.md      comportamiento: no asumir, preguntar, evidencias
.kiro/steering/formato-informe.md         veredictos, reglas de evidencia, formato Word y VEX
.kiro/skills/sbom-vuln-triage/
  SKILL.md                                procedimiento de análisis
  assets/..._SBOM_ANALYSIS_TEMPLATE.docx  plantilla corporativa del informe
  scripts/check_env.py                    comprueba Python, librerías y Grype
  scripts/sbom_inventory.py               detecta formato y normaliza el SBOM
  scripts/build_outputs.py                valida la spec y genera Word + VEX
  scripts/docx_report.py                  relleno de la plantilla Word
  references/preguntas-tipo.md            preguntas de afinado al usuario
  references/spec-ejemplo.json            ejemplo de especificación
requirements.txt                          librerías de Python (+ nota sobre Grype)
work/  output/                            datos intermedios y entregables (no se versionan)
```

## Mantenimiento

- **Plantilla**: sustituye el `.docx` de `assets/` conservando su nombre (o cambia
  `DEFAULT_TEMPLATE` en `docx_report.py`). Debe mantener INTRODUCCIÓN, REFERENCIAS, los
  campos TITLE/SUBJECT de la portada y la tabla de control de cambios.
- **Datos sensibles**: no versiones SBOM, informes ni salidas de Grype. El `.gitignore`
  excluye `work/` y `output/`.
