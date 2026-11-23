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


def validate(spec):
    errs = []
    for k in ("product", "author", "sbom", "tools", "findings", "outputs", "code", "element",
              "sbom_date", "scan_counts", "analyzed_severities"):
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
    analyzed = {x.lower() for x in spec.get("analyzed_severities") or []}
    got = {}
    for f in spec.get("findings") or []:
        got[str(f.get("severity")).lower()] = got.get(str(f.get("severity")).lower(), 0) + 1
    for sv, n in (spec.get("scan_counts") or {}).items():
        sv = sv.lower()
        if sv in analyzed and got.get(sv, 0) != n:
            errs.append(f"Severidad {sv}: el escáner da {n} hallazgos y la spec tiene "
                        f"{got.get(sv, 0)}. Cubre todos o quita la severidad de analyzed_severities.")
        if sv not in analyzed and got.get(sv, 0):
            errs.append(f"Hay hallazgos {sv} pero la severidad no está en analyzed_severities.")
    for sv in analyzed:
        if sv not in SEV_ES:
            errs.append(f"Severidad desconocida en analyzed_severities: {sv}.")
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
    if spec.get("excluded_severities"):
        notes.append("No se analizan los hallazgos de severidad: "
                     + ", ".join(spec["excluded_severities"]) + ".")
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
    sections = []
    for f in F:
        content = []
        txt = f.get("impact_statement") or f.get("open_question")
        if txt:
            content.append({"p": txt})
        item = {"cve": f["vuln_id"], "note": f"componente {comp_label(f['purl'])}; "
                f"severidad según {f['severity_source']}"}
        src = vuln_source(f["vuln_id"])
        if src:
            item["source"] = src
            content.append(item)
        else:
            content.append({"bullet": f"{item['cve']}  -  {item['note']}"})
        for e in f.get("evidence") or []:
            content.append({"bullet": f"Evidencia ({e['kind']}): {e['detail']} (fuente: {e['source']})"})
        if f.get("evidence") and all(e["kind"] == "user-statement" for e in f["evidence"]):
            content.append({"p": "Declarado por el usuario, no verificado de forma independiente."})
        if f.get("justification"):
            content.append({"p": f"Justificación VEX: {f['justification']}."})
        if f.get("action"):
            content.append({"remediation": f["action"]})
        sections.append({"heading": f"{f['vuln_id']} - {comp_label(f['purl'])} - {sev(f)} - "
                                    f"{VERDICT_ES[f['verdict']]}", "content": content})
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
    with open(a.spec, encoding="utf-8") as f:
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
