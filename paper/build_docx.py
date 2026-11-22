"""Build a Word copy of data-descriptor.md: python build_docx.py out.docx"""
import re, sys
from docx import Document
from docx.shared import Pt
src = open(__file__.rsplit('/', 1)[0] + '/data-descriptor.md').read().split('\n')
d = Document(); st = d.styles['Normal']; st.font.name = 'Times New Roman'; st.font.size = Pt(11)
def runs(par, text):
    for part in re.split(r'(`[^`]+`)', text):
        if part.startswith('`'):
            r = par.add_run(part[1:-1]); r.font.name = 'Courier New'; r.font.size = Pt(10)
        else:
            par.add_run(part)
i = 0
while i < len(src):
    l = src[i]
    if l.startswith('# '): d.add_heading(l[2:], 0)
    elif l.startswith('### '): d.add_heading(l[4:], 2)
    elif l.startswith('## '): d.add_heading(l[3:], 1)
    elif l.startswith('|'):
        rows = []
        while i < len(src) and src[i].startswith('|'):
            if not re.match(r'^\|[-| ]+\|$', src[i]): rows.append([c.strip() for c in src[i].strip('|').split('|')])
            i += 1
        t = d.add_table(rows=len(rows), cols=len(rows[0])); t.style = 'Table Grid'
        for a, r in enumerate(rows):
            for b, c in enumerate(r):
                cell = t.cell(a, b); cell.text = ''; runs(cell.paragraphs[0], c)
                if a == 0:
                    for x in cell.paragraphs[0].runs: x.bold = True
        d.add_paragraph(); continue
    elif l.startswith('- '): runs(d.add_paragraph(style='List Bullet'), l[2:])
    elif re.match(r'^\d+\. ', l): runs(d.add_paragraph(style='List Number'), re.sub(r'^\d+\. ', '', l))
    elif l.strip(): runs(d.add_paragraph(), l)
    i += 1
d.save(sys.argv[1])
