#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera el informe Word del analisis SBOM sobre la plantilla corporativa.

No se usa directamente: lo invoca build_outputs.py con una especificacion derivada de los
hallazgos. Adaptado de build_report.py de nessus-analyst (mismo mecanismo de plantilla).
"""
import copy
import json
import os
import re
import sys

import docx
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TEMPLATE = os.path.join(HERE, '..', 'assets', 'BX000XX_REPXXXXXXed0100_XXXX_SBOM_ANALYSIS_TEMPLATE.docx')

PLACEHOLDERS = ['TEMPLATE PENTEST ANALYSIS', 'TEMPLATE SBOM', 'BX000XX', 'REPXXXXXX',
                'Completar listado de referencias', 'FECHA ACTUAL', 'NOMBRE HERRAMIENTA',
                'PEQUEÑO CONTEXTO', 'DESCRIPCIÓN VUNLERABILIDAD', 'NOMBRE VULNERABILIDAD']
HYPERLINK_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink'

# Elementos de w:settings que deben ir DESPUES de w:updateFields (orden del esquema OOXML)
SETTINGS_AFTER_UPDATEFIELDS = {
    'hdrShapeDefaults', 'footnotePr', 'endnotePr', 'compat', 'docVars', 'rsids', 'mathPr',
    'attachedSchema', 'themeFontLang', 'clrSchemeMapping', 'doNotIncludeSubdocsInStats',
    'doNotAutoCompressPictures', 'forceUpgrade', 'captions', 'readModeInkLockDown',
    'smartTagType', 'schemaLibrary', 'shapeDefaults', 'doNotEmbedSmartTags',
    'decimalSymbol', 'listSeparator',
}


def fail(msg):
    raise SystemExit(f'ERROR: {msg}')


# ---------------------------------------------------------------- utilidades de estilo
def style_id(doc, *names):
    """Devuelve el styleId interno de un estilo buscando por su nombre (sin distinguir mayusculas)."""
    wanted = {n.lower() for n in names}
    for s in doc.styles.element.iter(qn('w:style')):
        nm = s.find(qn('w:name'))
        if nm is not None and nm.get(qn('w:val'), '').lower() in wanted:
            return s.get(qn('w:styleId'))
    return None


def p_style(p_el):
    pPr = p_el.find(qn('w:pPr'))
    if pPr is None or pPr.find(qn('w:pStyle')) is None:
        return None
    return pPr.find(qn('w:pStyle')).get(qn('w:val'))


def p_text(el):
    return ''.join(t.text or '' for t in el.iter(qn('w:t')))


# ---------------------------------------------------------------- portada: campos TITLE/SUBJECT
def set_field_results(root, values):
    """Sustituye el texto calculado de los campos cuyo nombre esta en 'values' (TITLE, SUBJECT...)."""
    stack, changed = [], 0
    for r in list(root.iter(qn('w:r'))):
        fc = r.find(qn('w:fldChar'))
        if fc is not None:
            kind = fc.get(qn('w:fldCharType'))
            if kind == 'begin':
                stack.append({'instr': '', 'in_result': False, 'texts': []})
            elif kind == 'separate' and stack:
                stack[-1]['in_result'] = True
            elif kind == 'end' and stack:
                fld = stack.pop()
                m = re.match(r'\s*([A-Z]+)', fld['instr'])
                name = m.group(1) if m else ''
                if name in values and fld['texts']:
                    val = values[name]
                    if r'\* Upper' in fld['instr'] or r'\*Upper' in fld['instr']:
                        val = val.upper()
                    fld['texts'][0].text = val
                    for t in fld['texts'][1:]:
                        t.text = ''
                    changed += 1
            continue
        it = r.find(qn('w:instrText'))
        if it is not None and stack:
            stack[-1]['instr'] += it.text or ''
        if stack and stack[-1]['in_result']:
            stack[-1]['texts'].extend(r.findall(qn('w:t')))
    for fs in root.iter(qn('w:fldSimple')):
        m = re.match(r'\s*([A-Z]+)', fs.get(qn('w:instr'), ''))
        if m and m.group(1) in values:
            ts = list(fs.iter(qn('w:t')))
            if ts:
                ts[0].text = values[m.group(1)]
                for t in ts[1:]:
                    t.text = ''
                changed += 1
    return changed


def replace_literals(root, mapping):
    n = 0
    for t in root.iter(qn('w:t')):
        if t.text:
            for old, new in mapping.items():
                if old in t.text:
                    t.text = t.text.replace(old, new)
                    n += 1
    return n


def header_footer_roots(doc):
    roots = []
    for rel in doc.part.rels.values():
        if rel.reltype.endswith('/header') or rel.reltype.endswith('/footer'):
            roots.append(rel.target_part.element)
    return roots


def enable_update_fields(doc):
    settings = doc.settings.element
    if settings.find(qn('w:updateFields')) is not None:
        return
    uf = OxmlElement('w:updateFields')
    uf.set(qn('w:val'), 'true')
    for child in settings:
        if child.tag.split('}')[-1] in SETTINGS_AFTER_UPDATEFIELDS:
            child.addprevious(uf)
            return
    settings.append(uf)


# ---------------------------------------------------------------- construccion de parrafos
class Builder:
    def __init__(self, doc, anchor):
        self.doc = doc
        self.anchor = anchor  # se inserta todo justo antes de este elemento
        self.s_normal = style_id(doc, 'Normal') or 'Normal'
        self.s_h1 = style_id(doc, 'heading 1')
        self.s_h2 = style_id(doc, 'heading 2')
        self.s_h3 = style_id(doc, 'heading 3') or self.s_h2
        self.s_list = style_id(doc, 'List Paragraph')
        self.s_link = style_id(doc, 'Hyperlink')
        self.bullet_numpr = None
        self.pagebreak = None
        if not (self.s_h1 and self.s_h2 and self.s_list):
            fail('La plantilla no tiene los estilos Heading 1 / Heading 2 / List Paragraph.')

    def _p(self, style):
        p = OxmlElement('w:p')
        pPr = OxmlElement('w:pPr')
        ps = OxmlElement('w:pStyle')
        ps.set(qn('w:val'), style)
        pPr.append(ps)
        p.append(pPr)
        return p

    @staticmethod
    def _run(p, text, bold=False):
        r = OxmlElement('w:r')
        if bold:
            rPr = OxmlElement('w:rPr')
            rPr.append(OxmlElement('w:b'))
            r.append(rPr)
        t = OxmlElement('w:t')
        t.set(qn('xml:space'), 'preserve')
        t.text = text
        r.append(t)
        p.append(r)

    def _link(self, p, url, text):
        rid = self.doc.part.relate_to(url, HYPERLINK_REL, is_external=True)
        h = OxmlElement('w:hyperlink')
        h.set(qn('r:id'), rid)
        r = OxmlElement('w:r')
        rPr = OxmlElement('w:rPr')
        if self.s_link:
            rs = OxmlElement('w:rStyle')
            rs.set(qn('w:val'), self.s_link)
            rPr.append(rs)
        else:
            c = OxmlElement('w:color')
            c.set(qn('w:val'), '0563C1')
            u = OxmlElement('w:u')
            u.set(qn('w:val'), 'single')
            rPr.extend([c, u])
        r.append(rPr)
        t = OxmlElement('w:t')
        t.set(qn('xml:space'), 'preserve')
        t.text = text
        r.append(t)
        h.append(r)
        p.append(h)

    def _put(self, el):
        self.anchor.addprevious(el)
        return el

    def heading1(self, text):
        p = self._p(self.s_h1)
        self._run(p, text)
        self._put(p)

    def heading2(self, text):
        p = self._p(self.s_h2)
        self._run(p, text)
        self._put(p)

    def heading3(self, text):
        p = self._p(self.s_h3)
        self._run(p, text)
        self._put(p)

    def para(self, text, label=None):
        p = self._p(self.s_normal)
        if label:
            self._run(p, label + ' ', bold=True)
        self._run(p, text)
        self._put(p)

    def _bullet_p(self):
        p = self._p(self.s_list)
        if self.bullet_numpr is not None:
            p.find(qn('w:pPr')).append(copy.deepcopy(self.bullet_numpr))
        return p

    def _mark(self, p):
        # la plantilla SBOM no trae lista con viñetas: se simula con un caracter
        if self.bullet_numpr is None:
            self._run(p, '\u2022 ')

    def bullet(self, text):
        p = self._bullet_p()
        self._mark(p)
        self._run(p, text)
        self._put(p)

    def cve(self, cve_id, note, source='nvd', url=None):
        if not url:
            url = {'ubuntu': f'https://ubuntu.com/security/{cve_id}',
                   'nvd': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                   'mitre': f'https://www.cve.org/CVERecord?id={cve_id}',
                   'ghsa': f'https://github.com/advisories/{cve_id}'}.get(source)
            if not url:
                fail(f'Fuente desconocida para {cve_id}: {source}')
        p = self._bullet_p()
        self._mark(p)
        self._link(p, url, cve_id)
        if note:
            self._run(p, '  -  ' + note)
        self._put(p)

    def page_break(self):
        if self.pagebreak is not None:
            self._put(copy.deepcopy(self.pagebreak))
        else:
            p = self._p(self.s_normal)
            r = OxmlElement('w:r')
            br = OxmlElement('w:br')
            br.set(qn('w:type'), 'page')
            r.append(br)
            p.append(r)
            self._put(p)

    def table(self, columns, rows):
        tbl = self.doc.add_table(rows=1, cols=len(columns))
        try:
            tbl.style = self.doc.styles['Table Grid']
        except KeyError:
            pass
        for cell, txt in zip(tbl.rows[0].cells, columns):
            cell.text = ''
            cell.paragraphs[0].add_run(str(txt)).bold = True
        for row in rows:
            cells = tbl.add_row().cells
            for cell, val in zip(cells, row):
                cell.text = str(val)
        self._put(tbl._tbl)
        self.para('')


# ---------------------------------------------------------------- composicion del informe
def render_content(b, items):
    for it in items:
        if 'p' in it:
            b.para(it['p'], label=it.get('label'))
        elif 'bullet' in it:
            b.bullet(it['bullet'])
        elif 'cve' in it:
            b.cve(it['cve'], it.get('note', ''), it.get('source', 'nvd'), it.get('url'))
        elif 'remediation' in it:
            b.para(it['remediation'], label='Remediación:')
        elif 'table' in it:
            b.table(it['table']['columns'], it['table']['rows'])
        else:
            fail(f'Elemento de contenido no reconocido: {it}')


def fill_change_control(doc, date, author, description):
    for t in doc.tables:
        if not t.rows or t.rows[0].cells[0].text.strip() != 'Edición':
            continue
        for row in t.rows:
            if re.match(r'^\d{2}\.\d{2}$', row.cells[0].text.strip()):
                def put(cell, val):
                    if val is None:
                        return
                    par = cell.paragraphs[0]
                    if par.runs:
                        par.runs[0].text = val
                        for r in par.runs[1:]:
                            r.text = ''
                    else:
                        par.add_run(val)
                put(row.cells[1], date)
                put(row.cells[2], description)
                if author and len(row.cells) > 3:
                    put(row.cells[3], author)
                return True
    return False


def fill_references(doc, refs):
    target = None
    for p in doc.paragraphs:
        if 'Completar listado de referencias' in p.text:
            target = p
            break
    if target is None:
        return
    if not refs:
        target._p.getparent().remove(target._p)
        return
    b = Builder.__new__(Builder)  # solo para reutilizar _run/_link
    b.doc = doc
    b.s_link = style_id(doc, 'Hyperlink')
    base = target._p
    prev = base
    for i, ref in enumerate(refs):
        p = copy.deepcopy(base)
        for child in list(p):
            if child.tag != qn('w:pPr'):
                p.remove(child)
        Builder._run(p, ref['text'] + (' ' if ref.get('url') else ''))
        if ref.get('url'):
            b._link(p, ref['url'], ref['url'])
        prev.addnext(p)
        prev = p
    base.getparent().remove(base)


def build(spec, base_dir='.'):
    """Genera el Word a partir de un dict de especificacion (ver build_outputs.docx_spec)."""
    for key in ('output', 'title', 'code', 'introduction', 'sections', 'conclusions'):
        if not spec.get(key):
            fail(f"Falta el campo obligatorio '{key}' en la especificacion del informe")
    base_dir = os.path.abspath(base_dir)
    template = spec.get('template') or DEFAULT_TEMPLATE
    if not os.path.isabs(template):
        template = os.path.normpath(os.path.join(base_dir, template))
    output = spec['output']
    if not os.path.isabs(output):
        output = os.path.normpath(os.path.join(base_dir, output))
    if not os.path.exists(template):
        fail(f'No existe la plantilla: {template}')
    if os.path.abspath(output) == os.path.abspath(template):
        fail('La salida no puede sobrescribir la plantilla.')

    title = spec['title'].strip().upper()
    code = spec['code'].strip()
    doc = docx.Document(template)

    # 1) portada / encabezado / propiedades
    doc.core_properties.title = title
    doc.core_properties.subject = code
    values = {'TITLE': title, 'SUBJECT': code}
    n_fields = set_field_results(doc.element.body, values)
    for root in header_footer_roots(doc):
        n_fields += set_field_results(root, values)
    for root in [doc.element.body] + header_footer_roots(doc):
        replace_literals(root, {'TEMPLATE PENTEST ANALYSIS': title, 'BX000XX_REPXXXXXX': code})
    enable_update_fields(doc)

    # 2) localizar el cuerpo a sustituir
    body = doc.element.body
    s_h1 = style_id(doc, 'heading 1')
    elems = list(body)
    intro = next((e for e in elems if e.tag == qn('w:p') and p_style(e) == s_h1
                  and p_text(e).strip().upper() == 'INTRODUCCIÓN'), None)
    refs_p = next((e for e in elems if e.tag == qn('w:p') and p_text(e).strip().upper() == 'REFERENCIAS'), None)
    if intro is None or refs_p is None:
        fail('No se encuentran los apartados INTRODUCCIÓN y REFERENCIAS en la plantilla.')
    end_anchor = refs_p
    prev = refs_p.getprevious()
    if prev is not None and prev.tag == qn('w:p') and p_style(prev) == s_h1 and not p_text(prev).strip():
        end_anchor = prev  # parrafo vacio con salto de pagina que precede a REFERENCIAS

    b = Builder(doc, end_anchor)
    region, el = [], intro.getnext()
    while el is not None and el is not end_anchor:
        region.append(el)
        el = el.getnext()
    for e in region:
        if e.tag == qn('w:p') and p_style(e) == b.s_list and b.bullet_numpr is None:
            pPr = e.find(qn('w:pPr'))
            if pPr is not None and pPr.find(qn('w:numPr')) is not None:
                b.bullet_numpr = copy.deepcopy(pPr.find(qn('w:numPr')))
        if e.tag == qn('w:p') and b.pagebreak is None and not p_text(e).strip() \
                and any(br.get(qn('w:type')) == 'page' for br in e.iter(qn('w:br'))):
            b.pagebreak = copy.deepcopy(e)
    for e in region:
        if e.find('.//' + qn('w:sectPr')) is not None:
            fail('La region a sustituir contiene un salto de seccion; revisar la plantilla.')
        body.remove(e)

    # entradas de ejemplo del indice (se regenera al abrir en Word): fuera las de la plantilla
    toc_ids = {style_id(doc, n) for n in ('toc 1', 'toc 2', 'toc 3')} - {None}
    for e in list(body.iter(qn('w:p'))):
        if p_style(e) in toc_ids and 'NOMBRE VULNERABILIDAD' in p_text(e):
            e.getparent().remove(e)

    # 3) cuerpo nuevo
    for text in spec['introduction']:
        b.para(text)
    b.heading1('DESARROLLO')
    for text in spec.get('development_intro', []):
        b.para(text)
    if spec.get('ip_table'):
        t = spec['ip_table']
        if t.get('heading'):
            b.heading2(t['heading'])
        for text in t.get('intro', []):
            b.para(text)
        b.table(t['columns'], t['rows'])
    for sec in spec['sections']:
        (b.heading3 if sec.get('level') == 3 else b.heading2)(sec['heading'])
        render_content(b, sec.get('content', []))
    b.page_break()
    b.heading1('CONCLUSIONES')
    for text in spec['conclusions']:
        b.para(text)

    # 4) referencias y control de cambios
    fill_references(doc, spec.get('references', []))
    cc = spec.get('change_control', {})
    fill_change_control(doc, cc.get('date'), cc.get('author'), cc.get('description', 'Versión inicial'))

    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    doc.save(output)
    validate(output, title, code, n_fields)


def validate(path, title, code, n_fields):
    doc = docx.Document(path)
    problems = []
    roots = [doc.element.body] + header_footer_roots(doc)
    alltext = ' '.join(p_text(r) for r in roots)
    for ph in PLACEHOLDERS:
        if ph in alltext:
            problems.append(f'queda el marcador de plantilla "{ph}"')
    if doc.core_properties.title != title:
        problems.append('la propiedad Título no se ha actualizado')
    if title not in p_text(doc.element.body):
        problems.append('el título no aparece en la portada')
    if code not in p_text(doc.element.body):
        problems.append('el código no aparece en la portada')
    s_h1, s_h2 = style_id(doc, 'heading 1'), style_id(doc, 'heading 2')
    heads1 = [p.text for p in doc.paragraphs if p._p is not None and p_style(p._p) == s_h1 and p.text.strip()]
    s_h3 = style_id(doc, 'heading 3')
    heads2 = [p.text for p in doc.paragraphs if p_style(p._p) in (s_h2, s_h3)]
    for h in ('INTRODUCCIÓN', 'DESARROLLO', 'CONCLUSIONES'):
        if h not in [x.strip().upper() for x in heads1]:
            problems.append(f'falta el apartado {h}')
    links = len(list(doc.element.body.iter(qn('w:hyperlink'))))

    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    print(f'Informe generado: {path}')
    print(f'  Título portada : {title}')
    print(f'  Código         : {code}')
    print(f'  Campos TITLE/SUBJECT actualizados: {n_fields}')
    print(f'  Apartados nivel 1: {heads1}')
    print(f'  Hallazgos (nivel 2): {len(heads2)}')
    for h in heads2:
        print(f'    - {h}')
    print(f'  Hipervínculos: {links}')
    if problems:
        print('VALIDACIÓN FALLIDA:')
        for pr in problems:
            print('  - ' + pr)
        sys.exit(1)
    print('Informe Word: validación correcta. Al abrirlo, Word pedirá actualizar los campos: responder "Sí" para regenerar el índice.')

