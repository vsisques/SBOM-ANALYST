#!/usr/bin/env python3
"""Detecta el formato de un SBOM y lo normaliza.

Formatos: Syft JSON, CycloneDX JSON/XML, SPDX JSON/tag-value. Solo biblioteca estándar.
No convierte nada: Grype lee todos estos formatos directamente (grype sbom:<fichero>).

No infiere nada: si un dato no está en el SBOM, queda a null y se informa de la carencia.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect(doc):
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in doc:
        return "spdx"
    if "artifacts" in doc and isinstance(doc.get("descriptor"), dict) \
            and doc["descriptor"].get("name") == "syft":
        return "syft"
    return None


def _lic(values):
    return [v for v in values if v]


def parse_cyclonedx(doc):
    out = []

    def walk(comps):
        for c in comps or []:
            lics = []
            for l in c.get("licenses", []) or []:
                lics.append((l.get("license") or {}).get("id")
                            or (l.get("license") or {}).get("name")
                            or l.get("expression"))
            out.append({
                "name": c.get("name"), "version": c.get("version"),
                "type": c.get("type"), "purl": c.get("purl"),
                "cpes": _lic([c.get("cpe")]), "licenses": _lic(lics),
                "bom_ref": c.get("bom-ref"),
            })
            walk(c.get("components"))
    walk(doc.get("components"))
    return out


def parse_spdx(doc):
    out = []
    for p in doc.get("packages", []) or []:
        purl, cpes = None, []
        for r in p.get("externalRefs", []) or []:
            if r.get("referenceType") == "purl":
                purl = r.get("referenceLocator")
            elif str(r.get("referenceType", "")).startswith("cpe"):
                cpes.append(r.get("referenceLocator"))
        lic = p.get("licenseConcluded")
        if lic in (None, "NOASSERTION", "NONE"):
            lic = p.get("licenseDeclared")
        out.append({
            "name": p.get("name"), "version": p.get("versionInfo"),
            "type": p.get("primaryPackagePurpose"), "purl": purl,
            "cpes": cpes,
            "licenses": [] if lic in (None, "NOASSERTION", "NONE") else [lic],
            "bom_ref": p.get("SPDXID"),
        })
    return out


def parse_syft(doc):
    out = []
    for a in doc.get("artifacts", []) or []:
        lics = [l.get("value") for l in a.get("licenses", []) or []]
        out.append({
            "name": a.get("name"), "version": a.get("version"),
            "type": a.get("type"), "purl": a.get("purl"),
            "cpes": [c.get("cpe") for c in a.get("cpes", []) or []],
            "licenses": _lic(lics), "bom_ref": a.get("id"),
        })
    return out


def parse_cyclonedx_xml(root):
    def loc(e):
        return e.tag.split("}")[-1]

    def child(e, name):
        for c in e:
            if loc(c) == name:
                return c
        return None

    def text(e, name):
        c = child(e, name)
        return c.text.strip() if c is not None and c.text else None

    out = []

    def walk(comps):
        for c in comps:
            lics = []
            lc = child(c, "licenses")
            if lc is not None:
                for l in lc:
                    inner = child(l, "id") if loc(l) == "license" else None
                    if loc(l) == "license":
                        v = text(l, "id") or text(l, "name")
                    else:
                        v = (l.text or "").strip()
                    if v:
                        lics.append(v)
            out.append({"name": text(c, "name"), "version": text(c, "version"),
                        "type": c.get("type"), "purl": text(c, "purl"),
                        "cpes": _lic([text(c, "cpe")]), "licenses": lics,
                        "bom_ref": c.get("bom-ref")})
            sub = child(c, "components")
            if sub is not None:
                walk(list(sub))
    top = child(root, "components")
    if top is not None:
        walk(list(top))
    return out


def parse_spdx_tv(text):
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("PackageName:"):
            cur = {"name": line.split(":", 1)[1].strip(), "version": None, "type": None,
                   "purl": None, "cpes": [], "licenses": [], "bom_ref": None}
            out.append(cur)
        elif cur is None:
            continue
        elif line.startswith("SPDXID:"):
            cur["bom_ref"] = line.split(":", 1)[1].strip()
        elif line.startswith("PackageVersion:"):
            cur["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("PrimaryPackagePurpose:"):
            cur["type"] = line.split(":", 1)[1].strip()
        elif line.startswith("ExternalRef:"):
            parts = line.split(":", 1)[1].split()
            if len(parts) >= 3:
                if parts[1] == "purl":
                    cur["purl"] = parts[2]
                elif parts[1].startswith("cpe"):
                    cur["cpes"].append(parts[2])
        elif line.startswith("PackageLicenseConcluded:") or line.startswith("PackageLicenseDeclared:"):
            v = line.split(":", 1)[1].strip()
            if v not in ("NOASSERTION", "NONE") and not cur["licenses"]:
                cur["licenses"] = [v]
    return out


def sbom_timestamp(fmt, doc):
    """Fecha de generación que declara el propio SBOM (None si no la trae)."""
    if not isinstance(doc, dict):
        return None
    if fmt == "cyclonedx":
        return (doc.get("metadata") or {}).get("timestamp")
    if fmt == "spdx":
        return (doc.get("creationInfo") or {}).get("created")
    if fmt == "syft":
        return (doc.get("descriptor") or {}).get("timestamp")
    return None


PARSERS = {"cyclonedx": parse_cyclonedx, "spdx": parse_spdx, "syft": parse_syft}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sbom")
    ap.add_argument("-o", "--output", help="JSON normalizado de salida")
    a = ap.parse_args()

    try:
        with open(a.sbom, encoding="utf-8") as f:
            raw = f.read()
    except (OSError, UnicodeDecodeError) as e:
        sys.exit(f"ERROR: no se puede leer el fichero ({e}).")
    stripped = raw.lstrip()
    doc, fmt, comps = None, None, None
    if stripped.startswith("{"):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.exit(f"ERROR: JSON no válido ({e}).")
        fmt = detect(doc)
        if fmt:
            comps = PARSERS[fmt](doc)
    elif stripped.startswith("<"):
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            sys.exit(f"ERROR: XML no válido ({e}).")
        if root.tag.split("}")[-1] == "bom" and "cyclonedx" in root.tag:
            fmt, comps = "cyclonedx", parse_cyclonedx_xml(root)
            doc = {"metadata": {"timestamp": next(
                (t.text for t in root.iter() if t.tag.split("}")[-1] == "timestamp"), None)}}
    elif "SPDXVersion:" in raw:
        fmt, comps = "spdx", parse_spdx_tv(raw)
        doc = {"creationInfo": {"created": next(
            (l.split(":", 1)[1].strip() for l in raw.splitlines() if l.startswith("Created:")), None)}}
    if not fmt:
        sys.exit("ERROR: formato no reconocido (Syft JSON, CycloneDX JSON/XML, SPDX JSON/tag-value).")

    gaps = {
        "sin_version": [c["name"] for c in comps if not c["version"]],
        "sin_purl": [c["name"] for c in comps if not c["purl"]],
        "sin_purl_ni_cpe": [c["name"] for c in comps if not c["purl"] and not c["cpes"]],
    }
    dup = [k for k, n in Counter((c["name"], c["version"], c["purl"]) for c in comps).items()
           if n > 1]
    ts = sbom_timestamp(fmt, doc)
    result = {"file": a.sbom, "sha256": sha256(a.sbom), "format": fmt, "sbom_timestamp": ts,
              "component_count": len(comps), "gaps": gaps,
              "duplicates": [list(d) for d in dup], "components": comps}
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Fichero : {a.sbom}\nSHA-256 : {result['sha256']}\nFormato : {fmt}")
    print(f"Fecha declarada en el SBOM: {ts or 'no indicada (preguntar al usuario)'}")
    print(f"Componentes: {len(comps)}")
    for k, v in gaps.items():
        print(f"  {k}: {len(v)}" + (f"  (p. ej. {', '.join(map(str, v[:5]))})" if v else ""))
    print(f"  duplicados: {len(dup)}")
    if a.output:
        print(f"Inventario guardado en {a.output}")


if __name__ == "__main__":
    main()
