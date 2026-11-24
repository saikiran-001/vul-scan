"""
pdf_report.py -- the downloadable PDF (Week 4 deliverable).

WHY REPORTLAB?
--------------
We need a real PDF with tables, colours and page numbers. ReportLab builds
PDFs from "flowables": paragraphs, tables and spacers that are laid out one
after another. If content runs past the bottom of the page, ReportLab starts
a new page automatically -- which is exactly what we want for a long list of
checks.

The input is the same dict the API returns from /status, so the PDF can never
disagree with the web report.
"""

from pathlib import Path                          # output path
from xml.sax.saxutils import escape               # user text must not break ReportLab's mini-HTML

from reportlab.lib import colors                  # colour constants
from reportlab.lib.pagesizes import A4            # page size in points
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet   # text styles
from reportlab.lib.units import mm                # 1 mm in points
from reportlab.platypus import (                  # the building blocks
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# A small, consistent palette.
INK = colors.HexColor("#111827")        # near-black text
MUTED = colors.HexColor("#6b7280")      # grey text
GREEN = colors.HexColor("#15803d")      # pass
AMBER = colors.HexColor("#b45309")      # warning
RED = colors.HexColor("#b91c1c")        # fail
BLUE = colors.HexColor("#1d4ed8")       # info / links
BORDER = colors.HexColor("#e5e7eb")     # table borders
SOFT = colors.HexColor("#f9fafb")       # light backgrounds
CODE_BG = colors.HexColor("#f3f4f6")    # code block background

STATUS_COLOR = {"pass": GREEN, "warn": AMBER, "fail": RED, "info": BLUE}
STATUS_TEXT = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO"}

CONTENT_WIDTH = A4[0] - 36 * mm         # A4 width minus the two 18mm margins


def _styles() -> dict:
    """Build every paragraph style once."""

    base = getSampleStyleSheet()        # ReportLab's defaults
    return {
        "title": ParagraphStyle(
            "VTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=20, leading=24, alignment=0, textColor=INK, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "VSub", parent=base["Normal"], fontSize=9, leading=12,
            textColor=MUTED, spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "VH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=12.5, leading=16, textColor=INK, spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "VH3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=INK, spaceBefore=10, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "VBody", parent=base["BodyText"], fontSize=9, leading=12, textColor=INK,
        ),
        "cell": ParagraphStyle(
            "VCell", parent=base["BodyText"], fontSize=8, leading=10.5, textColor=INK,
        ),
        "cell_muted": ParagraphStyle(
            "VCellMuted", parent=base["BodyText"], fontSize=8, leading=10.5, textColor=MUTED,
        ),
        "mono": ParagraphStyle(
            "VMono", parent=base["Code"], fontName="Courier", fontSize=8, leading=10.5,
            textColor=INK,
        ),
        "small": ParagraphStyle(
            "VSmall", parent=base["BodyText"], fontSize=7.5, leading=10, textColor=MUTED,
        ),
    }


def _p(text: str, style) -> Paragraph:
    """Escape user text, keep line breaks, and wrap it in a Paragraph."""

    safe = escape(str(text or ""))              # <b> in a URL must not become markup
    safe = safe.replace("\n", "<br/>")          # Paragraph has no newline handling
    return Paragraph(safe, style)


def _code_block(snippet: str, styles: dict) -> Table:
    """A shaded box around a monospace snippet."""

    inner = Preformatted(snippet.strip(), styles["mono"])   # Preformatted keeps spaces exactly
    box = Table([[inner]], colWidths=[CONTENT_WIDTH])       # one cell table = background box
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return box


def _footer(canvas, doc) -> None:
    """Draw the disclaimer and page number on every page."""

    canvas.saveState()                                          # save the graphics state
    canvas.setStrokeColor(BORDER)                               # thin separator line
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9.5 * mm, "Only scan websites you own. Passive analysis only.")
    canvas.drawRightString(A4[0] - 18 * mm, 9.5 * mm, f"Page {doc.page}")
    canvas.restoreState()                                       # restore for the next page


def build_pdf(payload: dict, out_path: Path) -> Path:
    """Render a scan result dict into a PDF file and return its path."""

    styles = _styles()
    story = []                                                  # the list of flowables, top to bottom

    score = int(payload.get("score", 0))
    grade = payload.get("grade", "?")
    colour = GREEN if score >= 80 else (AMBER if score >= 60 else RED)

    # ---- title block --------------------------------------------------
    story.append(_p("VulnScan Lite", styles["title"]))
    story.append(_p(
        f"Security health report for {payload.get('final_url') or payload.get('url', '')}",
        styles["subtitle"],
    ))

    scanned_at = str(payload.get("started_at", ""))[:19].replace("T", " ")
    meta = payload.get("meta", {}) or {}

    # ---- score banner -------------------------------------------------
    banner = Table(
        [[
            Paragraph(
                f'<font size="30" color="{colour.hexval()}"><b>{score}</b></font>'
                f'<font size="11" color="#6b7280"> / 100</font>',
                styles["body"],
            ),
            Paragraph(
                f'<font size="16" color="{colour.hexval()}"><b>Grade {escape(grade)}</b></font><br/>'
                f'<font size="8" color="#6b7280">Scanned {escape(scanned_at)} UTC &nbsp;|&nbsp; '
                f'HTTP {int(payload.get("status_code", 0))} &nbsp;|&nbsp; '
                f'{int(payload.get("duration_ms", 0))} ms</font>',
                styles["body"],
            ),
        ]],
        colWidths=[45 * mm, CONTENT_WIDTH - 45 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SOFT),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner)

    # ---- module summary ------------------------------------------------
    story.append(_p("Module scores", styles["h2"]))

    rows = [[
        Paragraph("<b>Module</b>", styles["cell"]),
        Paragraph("<b>Score</b>", styles["cell"]),
        Paragraph("<b>Weight</b>", styles["cell"]),
        Paragraph("<b>What it checks</b>", styles["cell"]),
    ]]
    descriptions = {
        "headers": "CSP, X-Frame-Options, HSTS and other response headers",
        "ssl": "Certificate validity, expiry, TLS version and cipher",
        "cms": "CMS fingerprint and version disclosure",
    }
    for module in payload.get("modules", []):
        module_score = int(module.get("score", 0))
        module_colour = GREEN if module_score >= 80 else (AMBER if module_score >= 60 else RED)
        rows.append([
            _p(module.get("title", ""), styles["cell"]),
            Paragraph(f'<font color="{module_colour.hexval()}"><b>{module_score}</b></font>',
                      styles["cell"]),
            _p(f"{int(module.get('weight', 0) * 100)}%", styles["cell_muted"]),
            _p(descriptions.get(module.get("id", ""), ""), styles["cell_muted"]),
        ])

    table = Table(rows, colWidths=[40 * mm, 18 * mm, 18 * mm, CONTENT_WIDTH - 76 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SOFT),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)

    # ---- every check ---------------------------------------------------
    story.append(_p("Check results", styles["h2"]))

    check_rows = [[
        Paragraph("<b>Check</b>", styles["cell"]),
        Paragraph("<b>Status</b>", styles["cell"]),
        Paragraph("<b>Finding</b>", styles["cell"]),
    ]]
    for check in payload.get("checks", []):
        status = check.get("status", "info")
        status_colour = STATUS_COLOR.get(status, MUTED)
        check_rows.append([
            Paragraph(
                f'<b>{escape(str(check.get("title", "")))}</b><br/>'
                f'<font size="7" color="#6b7280">{escape(str(check.get("module_title", "")))}</font>',
                styles["cell"],
            ),
            Paragraph(
                f'<font color="{status_colour.hexval()}"><b>{STATUS_TEXT.get(status, "INFO")}</b></font>',
                styles["cell"],
            ),
            _p(check.get("detail", ""), styles["cell"]),
        ])

    checks_table = Table(check_rows, colWidths=[42 * mm, 16 * mm, CONTENT_WIDTH - 58 * mm], repeatRows=1)
    checks_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SOFT),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(checks_table)

    # ---- remediation ----------------------------------------------------
    problems = [c for c in payload.get("checks", [])
                if c.get("status") in ("fail", "warn") and c.get("remediation")]
    if problems:
        story.append(_p("How to fix the findings", styles["h2"]))
        for check in problems:
            fix = check["remediation"]
            block = [
                _p(f'{check.get("title", "")}  ({STATUS_TEXT.get(check.get("status"), "")})', styles["h3"]),
            ]
            if fix.get("why"):
                block.append(_p(f"Why it matters: {fix['why']}", styles["body"]))
            if fix.get("fix"):
                block.append(_p(f"How to fix: {fix['fix']}", styles["body"]))
            if fix.get("snippet"):
                block.append(Spacer(1, 3))
                block.append(_code_block(fix["snippet"], styles))
            block.append(Spacer(1, 6))
            # KeepTogether stops a heading from being orphaned at the bottom of a page.
            story.append(KeepTogether(block))

    # ---- footer text on the last page ------------------------------------
    story.append(Spacer(1, 8))
    story.append(_p(
        f"Scanned URL: {payload.get('final_url') or payload.get('url', '')}  |  "
        f"Redirects: {len(meta.get('redirects', []) or [])}  |  "
        f"Scan id: {payload.get('id', '')}",
        styles["small"],
    ))
    story.append(_p(
        "This report is produced by passive analysis: one HTTP request and one TLS handshake. "
        "It cannot detect vulnerabilities that require authentication or active testing.",
        styles["small"],
    ))

    # ---- build ------------------------------------------------------------
    doc = SimpleDocTemplate(
        str(out_path),                      # ReportLab needs a string path
        pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title=f"VulnScan Lite report - {payload.get('url', '')}",
        author="VulnScan Lite",
        subject="Passive web security health report",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)   # flowables are laid out here
    return out_path
