#!/usr/bin/env python3
"""Valida la especificación de triaje y genera informe Word (plantilla corporativa), OpenVEX y CycloneDX VEX.

Falla (sin generar nada) si un veredicto no tiene la evidencia exigida: el script nunca
rellena huecos.
"""
import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

VERDICTS = {"VULNERABLE", "CORREGIDO", "NO_AFECTADO", "MITIGADO", "FALSO_POSITIVO", "PENDIENTE"}
JUSTIFICATIONS = {
    "component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
EVIDENCE_KINDS = {"sbom", "tool-output", "advisory", "user-statement", "command-output"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}
OUTPUTS = {"report", "openvex", "cyclonedx-vex"}

OPENVEX_STATUS = {"VULNERABLE": "affected", "CORREGIDO": "fixed", "NO_AFECTADO": "not_affected",
                  "MITIGADO": "not_affected", "FALSO_POSITIVO": "not_affected",
                  "PENDIENTE": "under_investigation"}
CDX_STATE = {"VULNERABLE": "exploitable", "CORREGIDO": "resolved", "NO_AFECTADO": "not_affected",
             "MITIGADO": "not_affected", "FALSO_POSITIVO": "false_positive",
             "PENDIENTE": "in_triage"}
CDX_JUSTIF = {"component_not_present": "code_not_present",
              "vulnerable_code_not_present": "code_not_present",
              "vulnerable_code_not_in_execute_path": "code_not_reachable",
              "vulnerable_code_cannot_be_controlled_by_adversary": "protected_at_runtime",
              "inline_mitigations_already_exist": "protected_by_mitigating_control"}


FILTER_MODES = {"min", "max", "include", "exclude"}


def effective_filter(spec):
    """El filtro de la spec; si no hay, por defecto solo la severidad más alta con hallazgos."""
    sf = spec.get("severity_filter")
    if sf:
        return sf
    present = [k for k, n in (spec.get("scan_counts") or {}).items()
               if n and k.lower() in SEV_ORDER]
    if not present:
        return {}
    top = min(present, key=lambda k: SEV_ORDER[k.lower()])
    return {"mode": "include", "severities": [top]}


def severity_filter_error(spec):
    """None si el filtro (explícito o por defecto) es válido; si no, el mensaje de error."""
    sf = effective_filter(spec)
    mode = str(sf.get("mode", "")).lower() if isinstance(sf, dict) else ""
    if mode not in FILTER_MODES:
        return ("Sin severity_filter y sin hallazgos en scan_counts para aplicar el filtro por "
                "defecto. Formato: {\"mode\": min|max|include|exclude, \"severities\": [...]}.")
    sv = sf.get("severities")
    if not isinstance(sv, list) or not sv or any(str(s).lower() not in SEV_ORDER for s in sv):
        return ("severity_filter.severities debe ser una lista no vacía de "
                "Critical/High/Medium/Low/Negligible/Unknown (en inglés; mayúsculas o minúsculas).")
    if mode in ("min", "max") and len(sv) != 1:
        return f"severity_filter modo {mode} admite una sola severidad."
    if not analyzed_severities(spec):
        return "severity_filter no deja ninguna severidad por analizar."
    return None


def analyzed_severities(spec):
    """Severidades a analizar según el filtro (mode: min|max|include|exclude).

    min: esa y las más graves. max: esa y las menos graves.
    include: solo las listadas. exclude: todas menos las listadas.
    Sin severity_filter: solo la severidad más alta encontrada (ver effective_filter).
    """
    sf = effective_filter(spec)
    sev = {str(s).lower() for s in sf.get("severities") or []}
    ranks = [SEV_ORDER.get(s, 5) for s in sev]
    mode = str(sf.get("mode", "")).lower()
    if mode == "min" and ranks:
        return {k for k, v in SEV_ORDER.items() if v <= max(ranks)}
    if mode == "max" and ranks:
        return {k for k, v in SEV_ORDER.items() if v >= min(ranks)}
    if mode == "include":
        return sev & set(SEV_ORDER)
    if mode == "exclude":
        return set(SEV_ORDER) - sev
    return set()


def filter_text(spec):
    sf = effective_filter(spec)
    names = ", ".join(SEV_ES[s.lower()].lower() for s in sf["severities"])
    default = "" if spec.get("severity_filter") else " (filtro por defecto: solo la severidad más alta)"
    return {"min": f"severidad {names} o superior",
            "max": f"severidad {names} o inferior",
            "include": f"las severidades {names}",
            "exclude": f"todas las severidades salvo {names}"}[str(sf["mode"]).lower()] + default


MOJIBAKE = re.compile("[\u00c3\u00c2][\u0080-\u00ff]|\ufffd|\u00e2\u0080")
QMARK = re.compile(r"(?<![\w/=&.-])[^\W\d_]+\?[^\W\d_]+(?![\w/=&.-])")


def encoding_errors(spec):
    """Detecta texto corrupto (UTF-8 mal decodificado o acentos sustituidos por '?')."""
    errs, stack = [], [("spec", spec)]
    while stack:
        path, o = stack.pop()
        if isinstance(o, dict):
            stack += [(f"{path}.{k}", v) for k, v in o.items()]
        elif isinstance(o, list):
            stack += [(f"{path}[{i}]", v) for i, v in enumerate(o)]
        elif isinstance(o, str) and (MOJIBAKE.search(o) or (" " in o and QMARK.search(o))):
            errs.append(f"{path}: caracteres corruptos (acentos/tildes mal codificados): "
                        f"{o[:60]!r}. Reescribe la spec en UTF-8 (sin redirecciones de PowerShell).")
    return errs


def validate(spec):
    errs = []
    for k in ("product", "author", "sbom", "tools", "findings", "outputs", "code", "element",
              "sbom_date", "scan_counts"):
        if not spec.get(k):
            errs.append(f"Falta el campo obligatorio '{k}' (pregúntaselo al usuario).")
    p = spec.get("product") or {}
    for k in ("name", "version"):
        if not p.get(k):
            errs.append(f"product.{k} vacío.")
    for k in ("file", "format", "sha256"):
        if not (spec.get("sbom") or {}).get(k):
            errs.append(f"sbom.{k} vacío.")
    for t in spec.get("tools") or []:
        if not t.get("name") or not t.get("version"):
            errs.append("Cada herramienta necesita name y version.")
    for o in spec.get("outputs") or []:
        if o not in OUTPUTS:
            errs.append(f"Salida desconocida '{o}'. Válidas: {sorted(OUTPUTS)}")
    if spec.get("code") and not re.fullmatch(r"B\d{6}_REP\d{6}", spec["code"]):
        errs.append("code debe tener el formato BXXXXXX_REPXXXXXX.")
    if spec.get("sbom_date") and not re.fullmatch(r"\d{2}/\d{2}/\d{4}", spec["sbom_date"]):
        errs.append("sbom_date debe ser DD/MM/AAAA.")
    e = severity_filter_error(spec)
    if e:
        errs.append(e)
    analyzed = analyzed_severities(spec)
    got = {}
    for f in spec.get("findings") or []:
        got[str(f.get("severity")).lower()] = got.get(str(f.get("severity")).lower(), 0) + 1
    for sv, n in (spec.get("scan_counts") or {}).items():
        sv = sv.lower()
        if sv not in SEV_ORDER:
            errs.append(f"Severidad desconocida en scan_counts: {sv}.")
        elif sv in analyzed and got.get(sv, 0) != n:
            errs.append(f"Severidad {sv}: el escáner da {n} hallazgos y la spec tiene "
                        f"{got.get(sv, 0)}. Cubre todos (los no analizados, como PENDIENTE).")
        elif sv not in analyzed and got.get(sv, 0):
            errs.append(f"Hay hallazgos {sv} fuera del filtro de severidad; quítalos de la spec.")
    errs += encoding_errors(spec)
    seen = set()
    for i, f in enumerate(spec.get("findings") or []):
        tag = f"findings[{i}] {f.get('vuln_id')} / {f.get('purl')}"
        if not f.get("vuln_id") or not f.get("purl"):
            errs.append(f"{tag}: faltan vuln_id o purl.")
        key = (f.get("vuln_id"), f.get("purl"))
        if key in seen:
            errs.append(f"{tag}: hallazgo duplicado.")
        seen.add(key)
        if str(f.get("severity")).lower() not in SEV_ES or not f.get("severity_source"):
            errs.append(f"{tag}: severity y severity_source obligatorios "
                        "(Critical/High/Medium/Low/Negligible/Unknown).")
        v = f.get("verdict")
        if v not in VERDICTS:
            errs.append(f"{tag}: veredicto '{v}' no válido.")
            continue
        if v == "PENDIENTE":
            if not f.get("open_question"):
                errs.append(f"{tag}: PENDIENTE exige open_question.")
            continue
        ev = f.get("evidence") or []
        if not ev:
            errs.append(f"{tag}: {v} sin evidencia.")
        for e in ev:
            if e.get("kind") not in EVIDENCE_KINDS or not e.get("detail") or not e.get("source"):
                errs.append(f"{tag}: evidencia incompleta (kind/detail/source).")
        if v == "NO_AFECTADO" and f.get("justification") not in JUSTIFICATIONS:
            errs.append(f"{tag}: NO_AFECTADO exige justification de OpenVEX.")
        if v == "MITIGADO":
            if f.get("justification") not in (None, "inline_mitigations_already_exist"):
                errs.append(f"{tag}: MITIGADO solo admite inline_mitigations_already_exist.")
            f.setdefault("justification", "inline_mitigations_already_exist")
        if v == "VULNERABLE" and not f.get("action"):
            errs.append(f"{tag}: VULNERABLE exige action.")
        if v in ("FALSO_POSITIVO", "MITIGADO", "NO_AFECTADO") and not f.get("impact_statement"):
            errs.append(f"{tag}: {v} exige impact_statement.")
        if v == "CORREGIDO" and not f.get("action") and not f.get("impact_statement"):
            errs.append(f"{tag}: CORREGIDO exige impact_statement (versión que lo corrige).")
    return errs


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def base_name(spec):
    """Misma convención que nessus-analyst: <CÓDIGO>ed0100_<ELEMENTO>_..."""
    return f"{spec['code']}ed0100_{spec['element']}_SBOM"


def build_openvex(spec, ts):
    stmts = []
    for f in spec["findings"]:
        s = {"vulnerability": {"name": f["vuln_id"]},
             "products": [{"@id": f["purl"], "identifiers": {"purl": f["purl"]}}],
             "status": OPENVEX_STATUS[f["verdict"]]}
        if s["status"] == "not_affected":
            s["justification"] = f.get("justification") or "component_not_present"
            s["impact_statement"] = f["impact_statement"]
        elif s["status"] == "affected":
            s["action_statement"] = f["action"]
        elif s["status"] == "fixed" and f.get("impact_statement"):
            s["status_notes"] = f["impact_statement"]
        elif s["status"] == "under_investigation":
            s["status_notes"] = f["open_question"]
        stmts.append(s)
    return {"@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://openvex.dev/docs/public/vex-{uuid.uuid4()}",
            "author": spec["author"], "timestamp": ts,
            "version": int(spec.get("vex_version", 1)),
            "statements": stmts}


def build_cdx(spec, ts):
    vulns = []
    for f in spec["findings"]:
        a = {"state": CDX_STATE[f["verdict"]]}
        if f["verdict"] in ("NO_AFECTADO", "MITIGADO"):
            a["justification"] = CDX_JUSTIF[f["justification"]]
        if f["verdict"] == "VULNERABLE":
            a["response"] = ["update"]
        a["detail"] = (f.get("impact_statement") or f.get("action")
                       or f.get("open_question") or "")
        v = {"id": f["vuln_id"], "source": {"name": f["severity_source"]},
             "analysis": a, "affects": [{"ref": f["purl"]}]}
        vulns.append(v)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {"timestamp": ts,
                         "authors": [{"name": spec["author"]}],
                         "component": {"type": "application", "name": spec["product"]["name"],
                                       "version": spec["product"]["version"]}},
            "vulnerabilities": vulns}


SEV_ES = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA",
          "negligible": "DESPRECIABLE", "unknown": "DESCONOCIDA"}
VERDICT_ES = {"VULNERABLE": "VULNERABILIDAD REAL", "CORREGIDO": "CORREGIDA",
              "NO_AFECTADO": "NO AFECTADO", "MITIGADO": "MITIGADA",
              "FALSO_POSITIVO": "FALSO POSITIVO", "PENDIENTE": "PENDIENTE DE VERIFICAR"}
GROUP_ORDER = ["VULNERABLE", "PENDIENTE", "MITIGADO", "CORREGIDO", "NO_AFECTADO", "FALSO_POSITIVO"]
GROUP_ES = {"VULNERABLE": "Vulnerables", "PENDIENTE": "Pendientes de verificar",
            "MITIGADO": "Mitigadas", "CORREGIDO": "Corregidas",
            "NO_AFECTADO": "No afectadas", "FALSO_POSITIVO": "Falsos positivos"}
GROUP_INTRO = {"VULNERABLE": "Vulnerabilidades reales: afectan al sistema y no est\u00e1n corregidas.",
               "PENDIENTE": "Falta evidencia para emitir un veredicto.",
               "MITIGADO": "Existe una mitigaci\u00f3n verificada.",
               "CORREGIDO": "La versi\u00f3n instalada incluye la correcci\u00f3n.",
               "NO_AFECTADO": "El componente est\u00e1 presente pero la vulnerabilidad no aplica.",
               "FALSO_POSITIVO": "El emparejamiento paquete-vulnerabilidad es err\u00f3neo."}
APLICABLE = {"VULNERABLE"}
PENDIENTE = {"PENDIENTE"}


def vuln_source(vid):
    if vid.startswith("CVE-"):
        return "nvd"
    if vid.startswith("GHSA-"):
        return "ghsa"
    return None


def comp_label(purl):
    return purl.split("?")[0].replace("pkg:", "", 1)


def sorted_findings(spec):
    return sorted(spec["findings"],
                  key=lambda f: (SEV_ORDER.get(f["severity"].lower(), 5), f["vuln_id"], f["purl"]))


def docx_spec(spec, ts):
    """Deriva del spec de hallazgos la especificacion que consume docx_report.build."""
    P, F = spec["product"], sorted_findings(spec)
    sev = lambda f: SEV_ES[f["severity"].lower()]
    out_name = f"{spec['code']}ed0100_{spec['element']}_SBOM_ANALYSIS.docx"
    tool_txt = ", ".join(f"{t['name']} {t['version']}" for t in spec["tools"])
    intro = [
        f"Este informe analiza las vulnerabilidades relacionadas con el SBOM generado el "
        f"{spec['sbom_date']} sobre el sistema {P['name']} en su versión {P['version']}.",
        f"El SBOM analizado está en formato {spec['sbom']['format']} (SHA-256 "
        f"{spec['sbom']['sha256']}). Las vulnerabilidades se obtienen con {tool_txt}.",
    ] + list(spec.get("context") or [])
    counts = {}
    for f in F:
        counts.setdefault(f["severity"].lower(), []).append(f)
    parts = [f"{len(counts[k])} {SEV_ES[k].lower()}{'s' if len(counts[k]) != 1 else ''}"
             for k in sorted(counts, key=lambda k: SEV_ORDER.get(k, 5))]
    dev = [f"En el análisis de este SBOM con {tool_txt} se detectan {len(F)} hallazgos "
           f"(pares vulnerabilidad-componente): {', '.join(parts)}. A continuación se "
           "analiza cada uno, indicando su veredicto y la evidencia que lo sustenta."]
    notes = list(spec.get("scope_notes") or [])
    skipped = {k: n for k, n in spec["scan_counts"].items()
               if n and k.lower() not in analyzed_severities(spec)}
    if skipped:
        notes.append(f"Alcance: se analizan las vulnerabilidades con {filter_text(spec)}. "
                     "No se analizan " + ", ".join(f"{n} de severidad {SEV_ES[k.lower()].lower()}"
                                                  for k, n in skipped.items()) + ".")
    dev += notes

    def bucket(f):
        return "Aplicables" if f["verdict"] in APLICABLE else \
            "Pendientes" if f["verdict"] in PENDIENTE else "No aplicables"
    rows = []
    for k in sorted(counts, key=lambda k: SEV_ORDER.get(k, 5)):
        c = {"Aplicables": 0, "No aplicables": 0, "Pendientes": 0}
        for f in counts[k]:
            c[bucket(f)] += 1
        rows.append([SEV_ES[k].capitalize(), c["Aplicables"], c["No aplicables"], c["Pendientes"]])
    # Informe organizado por veredicto (H2) > vulnerabilidad (H3) > paquetes afectados
    sections = []
    for verdict in GROUP_ORDER:
        grp = [f for f in F if f["verdict"] == verdict]
        if not grp:
            continue
        sections.append({"heading": f"{GROUP_ES[verdict]} ({len(grp)})", "level": 2,
                         "content": [{"p": GROUP_INTRO[verdict]}]})
        by_vuln = {}
        for f in grp:  # F ya viene ordenado de mas a menos grave
            by_vuln.setdefault(f["vuln_id"], []).append(f)
        for vid, fs in by_vuln.items():
            content = []
            src = vuln_source(vid)
            content.append({"cve": vid, "note": f"{len(fs)} paquete{'s' if len(fs) != 1 else ''} afectado"
                            f"{'s' if len(fs) != 1 else ''}", "source": src} if src
                           else {"bullet": f"{vid}  -  {len(fs)} paquete(s) afectado(s)"})
            for f in fs:
                content.append({"p": f"{sev(f)}; severidad seg\u00fan {f['severity_source']}.",
                                "label": f"Paquete {comp_label(f['purl'])}:"})
                txt = f.get("impact_statement") or f.get("open_question")
                if txt:
                    content.append({"p": txt})
                for e in f.get("evidence") or []:
                    content.append({"bullet": f"Evidencia ({e['kind']}): {e['detail']} (fuente: {e['source']})"})
                if f.get("evidence") and all(e["kind"] == "user-statement" for e in f["evidence"]):
                    content.append({"p": "Declarado por el usuario, no verificado de forma independiente."})
                if f.get("justification"):
                    content.append({"p": f"Justificaci\u00f3n VEX: {f['justification']}."})
                if f.get("action"):
                    content.append({"remediation": f["action"]})
            sections.append({"heading": f"{vid} - {sev(fs[0])}", "level": 3, "content": content})
    concl = []
    for title, pred in (("Aplicables (vulnerabilidades reales)", lambda f: f["verdict"] in APLICABLE),
                        ("No aplicables (falsos positivos, no afectados, mitigados o corregidos)",
                         lambda f: f["verdict"] not in APLICABLE and f["verdict"] not in PENDIENTE),
                        ("Pendientes de verificar", lambda f: f["verdict"] in PENDIENTE)):
        sel = [f for f in F if pred(f)]
        if not sel:
            concl.append(f"{title}: ninguna.")
            continue
        concl.append(f"{title}: {len(sel)}.")
        for f in sel:
            concl.append(f"{sev(f)}: {f['vuln_id']} en {comp_label(f['purl'])} "
                         f"({VERDICT_ES[f['verdict']]}).")
    refs = list(spec.get("references") or [])
    return {
        "output": out_name, "title": f"{spec['element']} SBOM ANALYSIS".upper(),
        "code": spec["code"], "introduction": intro, "development_intro": dev,
        "ip_table": {"heading": "Resumen por severidad", "intro": [],
                     "columns": ["Severidad", "Aplicables", "No aplicables", "Pendientes"],
                     "rows": rows},
        "sections": sections, "conclusions": concl, "references": refs,
        "change_control": {"date": ts[:10], "description": "Versión inicial",
                           "author": spec["author"]},
    }


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    print(f"Generado: {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec")
    ap.add_argument("--outdir", default="output")
    a = ap.parse_args()
    with open(a.spec, encoding="utf-8-sig") as f:
        spec = json.load(f)
    errs = validate(spec)
    if errs:
        print("Validación FALLIDA. No se genera nada:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)
    os.makedirs(a.outdir, exist_ok=True)
    ts, name = now(), base_name(spec)
    if "report" in spec["outputs"]:
        import docx_report  # requiere python-docx y lxml (requirements.txt)
        d = docx_spec(spec, ts)
        d["output"] = os.path.join(a.outdir, d["output"])
        docx_report.build(d, base_dir=os.getcwd())
    if "openvex" in spec["outputs"]:
        write_json(os.path.join(a.outdir, f"{name}_VEX.openvex.json"), build_openvex(spec, ts))
    if "cyclonedx-vex" in spec["outputs"]:
        write_json(os.path.join(a.outdir, f"{name}_VEX.cdx.json"), build_cdx(spec, ts))
    print(f"Hallazgos: {len(spec['findings'])}\nValidación correcta")


if __name__ == "__main__":
    main()
