# Preguntas tipo (adáptalas; no las des por respondidas)

## Contexto general
- ¿Producto, versión y componente/imagen que describe este SBOM?
- ¿El SBOM se generó del artefacto que realmente se despliega (misma versión/build)?
- ¿Cómo se generó (herramienta y versión, escaneo de imagen, de directorio, de fuentes)?
- ¿Entorno: contenedor, VM, bare metal? ¿Distribución y versión?
- ¿El servicio es accesible desde redes no confiables? ¿Qué puertos/interfaces?
- Nombre del elemento (p. ej. CORE5G), título y código documental `BXXXXXX_REPXXXXXX`.
- ¿Fecha de generación del SBOM? (confirmar la que declara el fichero, si la trae).
- ¿Quién figura como autor del VEX? ¿Hay un VEX previo que actualizar?
- ¿Qué severidades se analizan? (mínima, máxima, solo unas concretas o todas menos algunas; en inglés, mayúsculas o minúsculas). Por defecto, solo la más alta encontrada.

## Por hallazgo
- Ejecuta en la máquina/imagen real: `<comando>`. ¿Qué versión de `<paquete>` devuelve?
- ¿`<componente>` se carga o ejecuta en el producto, o solo está presente en la imagen?
- ¿Se usa la función/módulo/funcionalidad afectada (`<detalle del aviso>`)?
- ¿La entrada que llega a esa función puede ser controlada por un atacante?
- ¿Existe una mitigación (configuración, WAF, aislamiento, parche local)? ¿Cómo se verifica?
- ¿El paquete es de la distribución (backports) o se instaló desde upstream?
- El aviso de la distribución y Grype discrepan en `<CVE>`: ¿cuál consideras de referencia y por qué?

## Cierre
- ¿Doy por cerrados los hallazgos PENDIENTES o prefieres aportar más datos?
- ¿Confirmas los veredictos antes de generar el VEX?
