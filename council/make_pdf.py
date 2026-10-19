"""Render COUNCIL_REPORT.md to a paginated PDF via ReportLab.

A focused Markdown subset renderer: headings, paragraphs, bullets, ordered lists,
tables, fenced code, blockquotes, horizontal rules, and inline bold/italic/code.
Markdown stays the source of truth; this script is only presentation.

Usage:  py council/make_pdf.py
"""

from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.graphics.shapes import Circle, Drawing, Group, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    HRFlowable,
    ListFlowable,
    ListItem,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

COUNCIL_DIR = Path(__file__).resolve().parent
SRC = COUNCIL_DIR / "COUNCIL_REPORT.md"
OUT = COUNCIL_DIR / "COUNCIL_REPORT.pdf"

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#6b6b6b")
ACCENT = colors.HexColor("#7c3f2e")
RULE = colors.HexColor("#d4cfc7")
BAND = colors.HexColor("#f4f1ec")
CODEBG = colors.HexColor("#f7f5f2")

# Severity words get a colour cue in table cells.
SEVERITY_COLOURS = {
    "Critical": colors.HexColor("#9b1c1c"),
    "High": colors.HexColor("#b45309"),
    "Medium": colors.HexColor("#8a6d1f"),
}

# Diverging band palette shared by score bars and the risk heatmap.
BAND_RED = colors.HexColor("#c0392b")
BAND_AMBER = colors.HexColor("#d98a1f")
BAND_YELLOW = colors.HexColor("#c9a227")
BAND_GREEN = colors.HexColor("#4f8a4f")
BAND_GREY = colors.HexColor("#8a8a8a")
TRACK_COLORS = [
    colors.HexColor("#7c3f2e"), colors.HexColor("#3d6ea5"), colors.HexColor("#4f8a4f"),
    colors.HexColor("#8a6d1f"), colors.HexColor("#6b4f8a"), colors.HexColor("#a5533d"),
]


def score_band(value: float):
    """Map a 0-100 score to a band colour (red -> green)."""
    if value < 35:
        return BAND_RED
    if value < 55:
        return BAND_AMBER
    if value < 72:
        return BAND_YELLOW
    return BAND_GREEN


def slugify(text: str) -> str:
    plain = re.sub(r"[*`_~]", "", text)
    plain = re.sub(r"[^a-zA-Z0-9]+", "-", plain).strip("-").lower()
    return plain[:60] or "section"


class Anchor(Flowable):
    """Zero-height flowable that registers a named destination + PDF outline entry.

    Placed immediately before a heading so `<link destination=slug>` (the clickable
    TOC) and the reader's bookmark sidebar both jump to the right page.
    """

    def __init__(self, key: str, title: str, level: int = 0):
        super().__init__()
        self.key = key
        self.title = title
        self.level = level
        self.width = 0
        self.height = 0

    def draw(self):  # noqa: D102
        canv = self.canv
        canv.bookmarkPage(self.key)
        # A PDF outline cannot skip a level (0 -> 2 raises), which a document that
        # puts an H3 directly under the H1 title would otherwise do. Clamp to at most
        # one level deeper than the previous entry so any heading structure renders.
        last = getattr(canv, "_last_outline_level", -1)
        level = max(0, min(self.level, last + 1))
        # Outline titles must be plain text, not mini-HTML.
        clean = re.sub(r"<[^>]+>", "", self.title)
        canv.addOutlineEntry(clean, self.key, level=level, closed=(level > 0))
        canv._last_outline_level = level


def build_styles() -> dict[str, ParagraphStyle]:
    ss = getSampleStyleSheet()
    base = dict(fontName="Helvetica", textColor=INK, leading=14.5)
    return {
        "title": ParagraphStyle(
            "title", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=25,
            leading=30, textColor=INK, spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=ss["Normal"], fontName="Helvetica", fontSize=12.5,
            leading=17, textColor=MUTED, spaceAfter=4,
        ),
        "h1": ParagraphStyle(
            "h1", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=17,
            leading=21, textColor=ACCENT, spaceBefore=20, spaceAfter=9,
        ),
        "h2": ParagraphStyle(
            "h2", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=13,
            leading=17, textColor=INK, spaceBefore=15, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3", parent=ss["Normal"], fontName="Helvetica-BoldOblique", fontSize=11,
            leading=15, textColor=INK, spaceBefore=11, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=ss["Normal"], fontSize=9.8, alignment=TA_JUSTIFY,
            spaceAfter=7, **base,
        ),
        "bullet": ParagraphStyle(
            "bullet", parent=ss["Normal"], fontSize=9.8, spaceAfter=3.5, **base,
        ),
        "quote": ParagraphStyle(
            "quote", parent=ss["Normal"], fontName="Helvetica-Oblique", fontSize=9.8,
            leading=15, textColor=colors.HexColor("#3d3d3d"), leftIndent=14,
            rightIndent=8, spaceBefore=5, spaceAfter=8, borderPadding=0,
        ),
        "code": ParagraphStyle(
            "code", parent=ss["Code"], fontName="Courier", fontSize=8,
            leading=10.6, textColor=colors.HexColor("#24292f"),
            leftIndent=0, firstLineIndent=0, spaceBefore=0, spaceAfter=0,
        ),
        "th": ParagraphStyle(
            "th", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=8.6,
            leading=11.5, textColor=INK,
        ),
        "td": ParagraphStyle(
            "td", parent=ss["Normal"], fontName="Helvetica", fontSize=8.6,
            leading=11.5, textColor=INK,
        ),
        "footer": ParagraphStyle(
            "footer", parent=ss["Normal"], fontName="Helvetica", fontSize=7.6,
            textColor=MUTED,
        ),
        "vizcap": ParagraphStyle(
            "vizcap", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=9,
            leading=12, textColor=ACCENT, spaceBefore=4, spaceAfter=6,
        ),
        "swot": ParagraphStyle(
            "swot", parent=ss["Normal"], fontName="Helvetica", fontSize=8.6,
            leading=12.5, textColor=INK,
        ),
        "toc1": ParagraphStyle(
            "toc1", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=10.5,
            leading=17, textColor=INK, spaceBefore=3,
        ),
        "appendix": ParagraphStyle(
            "appendix", parent=ss["Normal"], fontName="Helvetica", fontSize=8.4,
            leading=11.5, textColor=colors.HexColor("#3d3d3d"), alignment=TA_JUSTIFY,
            spaceAfter=5,
        ),
        "toc2": ParagraphStyle(
            "toc2", parent=ss["Normal"], fontName="Helvetica", fontSize=9.2,
            leading=14, textColor=colors.HexColor("#4a4a4a"), leftIndent=14,
        ),
    }


def inline(text: str) -> str:
    """Markdown inline spans -> ReportLab mini-HTML. Escapes first."""
    out = html.escape(text, quote=False)

    # Code spans are STASHED before any emphasis rule runs and restored at the
    # end. Substituting them inline left their contents exposed to the `*` and
    # `_` rules, so a cell listing `report_v1.*` and `_v3.*` opened an <i> inside
    # one <font> and closed it inside another. ReportLab rejects the malformed
    # nesting and aborts the entire build.
    #
    # A code span means "render literally"; applying emphasis inside one is
    # wrong whether or not it happens to crash.
    spans: list[str] = []

    def _stash(match):
        spans.append(match.group(1))
        return f"\x00CODE{len(spans) - 1}\x00"

    out = re.sub(r"`([^`]+)`", _stash, out)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    # Strikethrough, before the single-* italic rule so ~~**x**~~ nests correctly.
    out = re.sub(r"~~(.+?)~~", r"<strike>\1</strike>", out)
    # Single-asterisk italics, not touching the bold markers already consumed.
    out = re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"<i>\1</i>", out)
    out = re.sub(r"(?<!\w)_([^_\n]+?)_(?!\w)", r"<i>\1</i>", out)
    out = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<link href="\2"><font color="#7c3f2e">\1</font></link>', out)
    # Bare URLs on their own become clickable but stay readable.
    out = re.sub(
        r"(?<![\">])(https?://[^\s<]+)",
        r'<link href="\1"><font color="#7c3f2e">\1</font></link>',
        out,
    )

    for index, literal in enumerate(spans):
        out = out.replace(
            f"\x00CODE{index}\x00",
            f'<font face="Courier" size="8.4">{literal}</font>',
        )
    return out


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def make_table(rows: list[list[str]], styles: dict, width: float) -> Table:
    header, body = rows[0], rows[1:]
    ncols = len(header)

    data = [[Paragraph(inline(c), styles["th"]) for c in header]]
    for row in body:
        cells = []
        for c in row:
            style = styles["td"]
            plain = re.sub(r"[*`]", "", c).strip()
            if plain in SEVERITY_COLOURS:
                style = ParagraphStyle(
                    f"sev{plain}", parent=styles["td"],
                    textColor=SEVERITY_COLOURS[plain], fontName="Helvetica-Bold",
                )
            cells.append(Paragraph(inline(c), style))
        # Pad ragged rows rather than letting Table raise.
        cells += [Paragraph("", styles["td"])] * (ncols - len(cells))
        data.append(cells[:ncols])

    # Narrow leading columns (indices, severities) shouldn't eat the row.
    first_vals = [re.sub(r"[*`]", "", r[0]).strip() for r in body if r]
    if first_vals and all(len(v) <= 3 for v in first_vals):
        lead = 8 * mm
        rest = (width - lead) / (ncols - 1) if ncols > 1 else width
        col_widths = [lead] + [rest] * (ncols - 1)
    else:
        col_widths = [width / ncols] * ncols

    table = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BAND),
                ("LINEBELOW", (0, 0), (-1, 0), 0.9, ACCENT),
                ("GRID", (0, 0), (-1, -1), 0.35, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fbfaf8")]),
            ]
        )
    )
    return table


# --------------------------------------------------------------------------- #
#  Visual directives:  ```viz <kind>  ...lines...  ```                          #
#  Rendered as ReportLab drawings so the report carries real dashboards,        #
#  heatmaps, matrices, SWOT quadrants and Gantt timelines, not ASCII art.       #
# --------------------------------------------------------------------------- #

_LEVELS = {"low": 0, "l": 0, "medium": 1, "med": 1, "m": 1, "moderate": 1, "high": 2, "h": 2}


def _viz_lines(raw: list[str]) -> tuple[str, list[str]]:
    """Split a viz block into (title, data-lines), dropping blanks/comments."""
    title = ""
    data: list[str] = []
    for ln in raw:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("title:"):
            title = s.split(":", 1)[1].strip()
            continue
        data.append(s)
    return title, data


def _parse_item(line: str) -> tuple[str, dict[str, str]]:
    """`Label | k=v | k=v`  ->  ("Label", {k: v}). Also accepts `Label | 42`."""
    parts = [p.strip() for p in line.split("|")]
    label = parts[0]
    kv: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k.strip().lower()] = v.strip()
        elif p:
            kv["value"] = p
    return label, kv


def _lvl(word: str) -> int:
    return _LEVELS.get(word.strip().lower(), 1)


def _caption(title: str, styles: dict) -> list:
    return [Paragraph(inline(title), styles["vizcap"])] if title else []


def _legend_table(pairs: list[tuple[str, str]], styles: dict, width: float) -> Table:
    """A compact two-column key -> description legend under a drawing."""
    data = [[Paragraph(f"<b>{html.escape(k)}</b>", styles["td"]),
             Paragraph(inline(v), styles["td"])] for k, v in pairs]
    t = Table(data, colWidths=[16 * mm, width - 16 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
    ]))
    return t


def viz_scorecard(title: str, data: list[str], styles: dict, width: float) -> list:
    rows = [_parse_item(d) for d in data]
    rows = [(lbl, kv) for lbl, kv in rows if kv.get("value")]
    rowh = 15
    top_pad = 6
    d = Drawing(width, rowh * len(rows) + top_pad)
    label_w = 46 * mm
    bar_x = label_w + 6
    bar_max = width - bar_x - 30
    for i, (label, kv) in enumerate(rows):
        try:
            val = max(0.0, min(100.0, float(re.sub(r"[^0-9.]", "", kv["value"]))))
        except ValueError:
            continue
        y = d.height - top_pad - (i + 1) * rowh + 3
        d.add(String(label_w, y + 1, label[:42], fontSize=8.2, fillColor=INK, textAnchor="end"))
        d.add(Rect(bar_x, y, bar_max, 8, fillColor=colors.HexColor("#ece8e2"),
                   strokeColor=None))
        d.add(Rect(bar_x, y, bar_max * val / 100.0, 8, fillColor=score_band(val),
                   strokeColor=None))
        d.add(String(bar_x + bar_max + 4, y + 1, f"{int(round(val))}",
                     fontSize=8.4, fillColor=INK))
    return _caption(title, styles) + [d, Spacer(1, 8)]


def viz_heatmap(title: str, data: list[str], styles: dict, width: float) -> list:
    """3x3 Likelihood (x) x Impact (y) grid; risk IDs dropped into their cell."""
    items = [_parse_item(d) for d in data]
    cell = 26 * mm
    grid_w = cell * 3
    ax = 20 * mm  # left axis gutter
    d = Drawing(width, grid_w + 16 * mm)
    base_x, base_y = ax, 12 * mm
    sev_palette = [  # by (lik+imp) sum 0..4
        BAND_GREEN, BAND_GREEN, BAND_YELLOW, BAND_AMBER, BAND_RED,
    ]
    buckets: dict[tuple[int, int], list[str]] = {}
    legend: list[tuple[str, str]] = []
    for lbl, kv in items:
        lik = _lvl(kv.get("likelihood", kv.get("l", "medium")))
        imp = _lvl(kv.get("impact", kv.get("i", "medium")))
        rid = lbl.split()[0] if lbl.split() else "?"
        buckets.setdefault((lik, imp), []).append(rid)
        rest = lbl[len(rid):].strip()
        legend.append((rid, rest or lbl))
    for xi in range(3):
        for yi in range(3):
            sev = sev_palette[xi + yi]
            x = base_x + xi * cell
            y = base_y + yi * cell
            d.add(Rect(x, y, cell, cell, fillColor=sev, strokeColor=colors.white,
                       strokeWidth=1.2, fillOpacity=0.82))
            ids = buckets.get((xi, yi), [])
            if ids:
                d.add(String(x + cell / 2, y + cell / 2 - 3, ", ".join(ids),
                             fontSize=8.5, fillColor=colors.white, textAnchor="middle"))
    labels = ["Low", "Medium", "High"]
    for i, t in enumerate(labels):
        d.add(String(base_x + i * cell + cell / 2, base_y - 5, t, fontSize=7.6,
                     fillColor=MUTED, textAnchor="middle"))
        d.add(String(base_x - 4, base_y + i * cell + cell / 2 - 3, t, fontSize=7.6,
                     fillColor=MUTED, textAnchor="end"))
    d.add(String(base_x + grid_w / 2, base_y - 12, "Likelihood ->", fontSize=8,
                 fillColor=INK, textAnchor="middle"))
    yaxis = Group(String(0, 0, "Impact ->", fontSize=8, fillColor=INK, textAnchor="middle"))
    yaxis.translate(9, base_y + grid_w / 2)
    yaxis.rotate(90)
    d.add(yaxis)
    out = _caption(title, styles) + [d, Spacer(1, 4)]
    if legend:
        out += [_legend_table(legend, styles, width), Spacer(1, 8)]
    return out


def viz_matrix(title: str, data: list[str], styles: dict, width: float) -> list:
    """2x2 Impact (y) x Effort (x) priority matrix with numbered dots + legend."""
    items = [_parse_item(d) for d in data]
    size = 78 * mm
    d = Drawing(width, size + 12 * mm)
    ox, oy = 22 * mm, 8 * mm
    d.add(Rect(ox, oy, size, size, fillColor=colors.HexColor("#faf8f5"),
               strokeColor=RULE, strokeWidth=0.6))
    d.add(Line(ox + size / 2, oy, ox + size / 2, oy + size, strokeColor=RULE, strokeWidth=0.5))
    d.add(Line(ox, oy + size / 2, ox + size, oy + size / 2, strokeColor=RULE, strokeWidth=0.5))
    quad = {(0, 1): "Quick Wins", (1, 1): "Big Bets", (0, 0): "Fill-Ins", (1, 0): "Thankless"}
    for (qx, qy), name in quad.items():
        cx = ox + qx * size / 2 + size / 4
        cy = oy + qy * size / 2 + size / 2 - 6
        d.add(String(cx, cy, name, fontSize=8.4, fillColor=colors.HexColor("#b9b2a8"),
                     textAnchor="middle"))
    # axis labels
    d.add(String(ox + size / 2, oy - 5, "Effort  (low -> high)", fontSize=8,
                 fillColor=INK, textAnchor="middle"))
    myaxis = Group(String(0, 0, "Impact (low -> high)", fontSize=8, fillColor=INK,
                          textAnchor="middle"))
    myaxis.translate(ox - 13, oy + size / 2)
    myaxis.rotate(90)
    d.add(myaxis)
    legend: list[tuple[str, str]] = []
    seen: dict[tuple[int, int], int] = {}
    for idx, (lbl, kv) in enumerate(items, 1):
        imp = _lvl(kv.get("impact", "medium"))
        eff = _lvl(kv.get("effort", "medium"))
        qx = 1 if eff == 2 else 0
        qy = 1 if imp == 2 else 0
        n = seen.get((qx, qy), 0)
        seen[(qx, qy)] = n + 1
        # spread dots within the quadrant so they don't overlap
        col = n % 3
        row = n // 3
        cx = ox + qx * size / 2 + 9 + col * 11
        cy = oy + qy * size / 2 + size / 2 - 12 - row * 11
        num = lbl.split()[0] if lbl.split() and lbl.split()[0].isdigit() else str(idx)
        d.add(Circle(cx, cy, 4.4, fillColor=ACCENT, strokeColor=colors.white, strokeWidth=0.8))
        d.add(String(cx, cy - 2.6, num, fontSize=6.6, fillColor=colors.white, textAnchor="middle"))
        rest = lbl[len(num):].strip() if lbl.startswith(num) else lbl
        legend.append((num, rest or lbl))
    out = _caption(title, styles) + [d, Spacer(1, 4)]
    if legend:
        out += [_legend_table(legend, styles, width), Spacer(1, 8)]
    return out


def viz_swot(title: str, data: list[str], styles: dict, width: float) -> list:
    """2x2 SWOT quadrants. Lines tagged S:/W:/O:/T:."""
    buckets = {"s": [], "w": [], "o": [], "t": []}
    for line in data:
        m = re.match(r"^([SWOTswot])\s*[:\-]\s*(.*)$", line)
        if m:
            buckets[m.group(1).lower()].append(m.group(2).strip())
    quad_bg = {
        "s": colors.HexColor("#eaf3ea"),  # strengths — green tint
        "w": colors.HexColor("#f6eae9"),  # weaknesses — red tint
        "o": colors.HexColor("#eaf0f6"),  # opportunities — blue tint
        "t": colors.HexColor("#f6f2e6"),  # threats — amber tint
    }

    def cell(key, heading):
        bullets = "".join(f"<br/>&bull; {inline(x)}" for x in buckets[key]) or "<br/>&mdash;"
        return Paragraph(f"<b>{heading}</b>{bullets}", styles["swot"])

    data_tbl = [[cell("s", "Strengths"), cell("w", "Weaknesses")],
                [cell("o", "Opportunities"), cell("t", "Threats")]]
    t = Table(data_tbl, colWidths=[width / 2] * 2, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), quad_bg["s"]),
        ("BACKGROUND", (1, 0), (1, 0), quad_bg["w"]),
        ("BACKGROUND", (0, 1), (0, 1), quad_bg["o"]),
        ("BACKGROUND", (1, 1), (1, 1), quad_bg["t"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 1.4, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return _caption(title, styles) + [t, Spacer(1, 9)]


def viz_gantt(title: str, data: list[str], styles: dict, width: float) -> list:
    """Roadmap bars across 5 horizon columns (30d/90d/6m/1y/3y)."""
    cols = ["30-day", "90-day", "6-month", "1-year", "3-year"]
    ncol = len(cols)
    items = [_parse_item(d) for d in data]
    rowh = 15
    ox = 44 * mm
    chart_w = width - ox - 4
    colw = chart_w / ncol
    d = Drawing(width, rowh * len(items) + 16)
    top = d.height - 12
    # header grid
    for c in range(ncol):
        x = ox + c * colw
        d.add(Line(x, 8, x, top + 4, strokeColor=RULE, strokeWidth=0.4))
        d.add(String(x + colw / 2, top + 6, cols[c], fontSize=7.2, fillColor=MUTED,
                     textAnchor="middle"))
    d.add(Line(ox + chart_w, 8, ox + chart_w, top + 4, strokeColor=RULE, strokeWidth=0.4))
    tracks: dict[str, int] = {}
    for i, (label, kv) in enumerate(items):
        try:
            start = int(float(kv.get("start", "0")))
            length = max(1, int(float(kv.get("len", kv.get("length", "1")))))
        except ValueError:
            start, length = 0, 1
        start = max(0, min(ncol - 1, start))
        length = min(length, ncol - start)
        track = kv.get("track", "")
        if track not in tracks:
            tracks[track] = len(tracks)
        color = TRACK_COLORS[tracks[track] % len(TRACK_COLORS)]
        y = top - 6 - (i + 1) * rowh + rowh
        d.add(String(ox - 4, y + 2, label[:40], fontSize=7.6, fillColor=INK, textAnchor="end"))
        d.add(Rect(ox + start * colw + 1.5, y, length * colw - 3, 9,
                   fillColor=color, strokeColor=None, fillOpacity=0.85))
    out = _caption(title, styles) + [d, Spacer(1, 4)]
    if any(k for k in tracks):
        out += [_legend_table([(k or "-", f"track: {k}") for k in tracks], styles, width),
                Spacer(1, 6)]
    return out


def viz_architecture(title: str, data: list[str], styles: dict, width: float) -> list:
    """Layered architecture diagram.

    Syntax: `Layer name | box, box, box`. Layers stack top to bottom, which is
    how the reader already thinks about a request travelling down through a
    system, and boxes within a layer sit side by side.
    """
    layers = [_parse_item(d) for d in data]
    rows = [(name, [b.strip() for b in (kv.get("value") or "").split(",") if b.strip()])
            for name, kv in layers]
    row_h = 26
    label_w = 34 * mm
    d = Drawing(width, row_h * len(rows) + 10)

    for i, (name, boxes) in enumerate(rows):
        y = d.height - (i + 1) * row_h
        d.add(String(label_w - 6, y + 9, name[:26], fontSize=8, fillColor=INK,
                     textAnchor="end"))
        if not boxes:
            continue
        span = (width - label_w) / len(boxes)
        for j, box in enumerate(boxes):
            x = label_w + j * span
            d.add(Rect(x + 2, y + 2, span - 4, row_h - 8,
                       fillColor=TRACK_COLORS[i % len(TRACK_COLORS)],
                       strokeColor=colors.white, strokeWidth=0.8, fillOpacity=0.18))
            # Truncate to what the box can actually hold. A fixed character
            # budget clipped full-width single-box layers ("...denies Post")
            # while leaving narrow ones half empty; Helvetica averages ~0.5em
            # per character, so derive the budget from the span instead.
            budget = max(8, int((span - 8) / (7.4 * 0.5)))
            d.add(String(x + span / 2, y + 10, box[:budget], fontSize=7.4,
                         fillColor=INK, textAnchor="middle"))
    return _caption(title, styles) + [d, Spacer(1, 9)]


def viz_flow(title: str, data: list[str], styles: dict, width: float) -> list:
    """Vertical flowchart. `Step text` per line; `?Decision text` for a branch.

    Vertical rather than horizontal because these flows are read on a portrait
    page and a wide flow would either overflow or shrink past legibility.
    """
    steps = [d for d in data if d.strip()]
    step_h = 30
    box_w = min(width * 0.62, 108 * mm)
    x0 = (width - box_w) / 2
    d = Drawing(width, step_h * len(steps) + 8)

    for i, raw in enumerate(steps):
        decision = raw.startswith("?")
        text = raw.lstrip("?").strip()
        y = d.height - (i + 1) * step_h
        fill = BAND_AMBER if decision else colors.HexColor("#eef2f7")
        d.add(Rect(x0, y + 4, box_w, step_h - 12, fillColor=fill,
                   strokeColor=RULE, strokeWidth=0.7,
                   fillOpacity=0.35 if decision else 1.0))
        d.add(String(width / 2, y + 11, text[:62], fontSize=7.8, fillColor=INK,
                     textAnchor="middle"))
        if i < len(steps) - 1:  # connector into the next box
            d.add(Line(width / 2, y + 4, width / 2, y - 8, strokeColor=ACCENT,
                       strokeWidth=0.9))
    return _caption(title, styles) + [d, Spacer(1, 9)]


def viz_decision(title: str, data: list[str], styles: dict, width: float) -> list:
    """Weighted decision matrix: `Option | crit=score | crit=score ...`.

    Scores are 0-10. The weighted total is computed here rather than written by
    hand, so the recommendation cannot silently disagree with its own inputs.
    """
    rows = [_parse_item(d) for d in data]
    criteria: list[str] = []
    for _name, kv in rows:
        for k in kv:
            if k not in criteria:
                criteria.append(k)

    header = ["Option", *[c.replace("_", " ").title() for c in criteria], "Total"]
    body = []
    for name, kv in rows:
        scores = []
        total = 0.0
        for c in criteria:
            try:
                v = float(kv.get(c, 0) or 0)
            except ValueError:
                v = 0.0
            total += v
            scores.append(f"{v:g}")
        body.append([name, *scores, f"**{total:g}**"])

    if body:
        best = max(range(len(body)), key=lambda i: float(body[i][-1].strip("*") or 0))
        body[best][0] = f"**{body[best][0]}**"
    return _caption(title, styles) + [
        make_table([header, *body], styles, width), Spacer(1, 9)
    ]


def viz_rice(title: str, data: list[str], styles: dict, width: float) -> list:
    """RICE prioritisation: `Item | reach=N | impact=N | confidence=N | effort=N`.

    Score = reach x impact x confidence / effort, computed here and sorted, so
    the ordering is derived from the inputs rather than asserted.
    """
    rows = []
    for line in data:
        name, kv = _parse_item(line)
        def num(key, default=1.0):
            try:
                return float(kv.get(key, default) or default)
            except ValueError:
                return default
        reach, impact = num("reach"), num("impact")
        conf, effort = num("confidence"), max(num("effort"), 0.1)
        rows.append((name, reach, impact, conf, effort, reach * impact * conf / effort))

    rows.sort(key=lambda r: r[-1], reverse=True)
    header = ["#", "Item", "Reach", "Impact", "Conf.", "Effort", "RICE"]
    body = [
        [str(i), n, f"{r:g}", f"{im:g}", f"{c:g}", f"{e:g}", f"**{s:.1f}**"]
        for i, (n, r, im, c, e, s) in enumerate(rows, 1)
    ]
    return _caption(title, styles) + [
        make_table([header, *body], styles, width), Spacer(1, 9)
    ]


VIZ = {
    "scorecard": viz_scorecard,
    "heatmap": viz_heatmap,
    "matrix": viz_matrix,
    "swot": viz_swot,
    "gantt": viz_gantt,
    "architecture": viz_architecture,
    "flow": viz_flow,
    "decision": viz_decision,
    "rice": viz_rice,
}


def render_viz(kind: str, raw: list[str], styles: dict, width: float) -> list:
    title, data = _viz_lines(raw)
    fn = VIZ.get(kind.strip().lower())
    if not fn:
        return [Preformatted("\n".join(raw), styles["code"])]
    try:
        return fn(title, data, styles, width)
    except Exception as exc:  # noqa: BLE001 — never let one bad block kill the build
        return [Paragraph(f"<i>[viz {kind} render error: {html.escape(str(exc))}]</i>",
                          styles["body"])]


def collect_headings(md: str) -> list[tuple[int, str, str]]:
    """Pre-pass: every heading as (level, text, unique-slug) for the TOC + outline."""
    out: list[tuple[int, str, str]] = []
    used: dict[str, int] = {}
    in_code = False
    for line in md.split("\n"):
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", s)
        if not m:
            continue
        level, text = len(m.group(1)), m.group(2).strip()
        base = slugify(text)
        n = used.get(base, 0)
        used[base] = n + 1
        slug = base if n == 0 else f"{base}-{n}"
        out.append((level, text, slug))
    return out


def build_toc(headings: list[tuple[int, str, str]], styles: dict) -> list:
    """A clickable table of contents (H1 + H2), internal links to heading anchors.

    Starts on its own page. Emits no trailing page break: the section heading that
    follows the [[TOC]] marker is an H1, which page-breaks itself — a trailing break
    here too would leave a blank page between them.
    """
    story: list = [PageBreak(), Paragraph("Contents", styles["h1"]), Spacer(1, 4)]
    for level, text, slug in headings:
        if level == 1 and text.lower() in ("contents", "table of contents"):
            continue
        if level > 2:
            continue
        clean = re.sub(r"[*`_~]", "", text)
        style = styles["toc1"] if level == 1 else styles["toc2"]
        # `href="#name"` is the form ReportLab turns into an intra-document jump;
        # `destination="name"` is emitted as an external file-launch annotation and
        # does not navigate.
        story.append(Paragraph(
            f'<a href="#{slug}"><font color="#1a1a1a">{html.escape(clean)}</font></a>',
            style,
        ))
    return story


def parse(md: str, styles: dict, width: float, headings: list | None = None) -> list:
    lines = md.split("\n")
    story: list = []
    i = 0
    seen_title = False

    # Regenerate heading slugs in document order, matching collect_headings exactly,
    # so each heading's anchor key equals its TOC link destination.
    headings = headings if headings is not None else collect_headings(md)
    _slug_used: dict[str, int] = {}

    # Map the heading levels actually used in this document onto contiguous outline
    # depths (a doc using only H1 and H3 becomes 0 and 1). A PDF outline cannot skip
    # a depth, and this keeps sibling sections at a consistent depth rather than
    # letting the first one after a parent clamp differently from the rest.
    used_levels = sorted({lvl for lvl, _, _ in headings if lvl <= 3})
    depth_of = {lvl: i for i, lvl in enumerate(used_levels)}

    def next_slug(text: str) -> str:
        base = slugify(text)
        n = _slug_used.get(base, 0)
        _slug_used[base] = n + 1
        return base if n == 0 else f"{base}-{n}"

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # Clickable table of contents at the [[TOC]] marker.
        if stripped == "[[TOC]]":
            story += build_toc(headings, styles)
            i += 1
            continue

        # Fenced block — either a ```viz <kind> visual, or literal code.
        if stripped.startswith("```"):
            fence = stripped[3:].strip()
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            if fence.lower().startswith("viz"):
                kind = fence[3:].strip() or "scorecard"
                # Reserve the figure's ACTUAL height, not a fixed guess. A flat
                # 40mm was smaller than a tall flowchart, so the caption printed
                # at the bottom of one page and its diagram opened the next.
                viz = render_viz(kind, buf, styles, width)
                drawn = sum(f.height for f in viz if isinstance(f, Drawing))
                need = min(drawn + 24 * mm, 200 * mm) if drawn else 40 * mm
                story += [CondPageBreak(need), *viz]
                continue
            block = Preformatted("\n".join(buf), styles["code"])
            wrap = Table([[block]], colWidths=[width], hAlign="LEFT")
            wrap.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), CODEBG),
                        ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            story += [wrap, Spacer(1, 9)]
            continue

        # Table
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(
            r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]
        ):
            rows = [split_row(stripped)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            story += [CondPageBreak(38 * mm), make_table(rows, styles, width), Spacer(1, 11)]
            continue

        # Horizontal rule
        if re.match(r"^-{3,}$", stripped):
            story += [Spacer(1, 5), HRFlowable(width="100%", thickness=0.5, color=RULE), Spacer(1, 5)]
            i += 1
            continue

        # Headings
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            level, text = len(m.group(1)), m.group(2)
            # H1-H3 get a bookmark anchor + PDF outline entry so the clickable TOC
            # and the reader's sidebar both navigate here. The anchor must come
            # AFTER any page break -- a bookmark placed before the break is drawn on
            # the previous page, so every section link would land one page early.
            anchor = (
                [Anchor(next_slug(text), text, level=depth_of.get(level, 0))]
                if level <= 3
                else []
            )
            if level == 1 and not seen_title:
                seen_title = True
                story += [*anchor, Paragraph(inline(text), styles["title"])]
            elif level == 1:
                story += [PageBreak(), *anchor, Paragraph(inline(text), styles["h1"])]
            elif level == 2:
                story += [CondPageBreak(30 * mm), *anchor, Paragraph(inline(text), styles["h1"])]
            elif level == 3:
                story += [CondPageBreak(26 * mm), *anchor, Paragraph(inline(text), styles["h2"])]
            else:
                story += [Paragraph(inline(text), styles["h3"])]
            i += 1
            continue

        # Blockquote
        if stripped.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip())
                i += 1
            para = Paragraph(inline(" ".join(buf)), styles["quote"])
            wrap = Table([[para]], colWidths=[width], hAlign="LEFT")
            wrap.setStyle(
                TableStyle(
                    [
                        ("LINEBEFORE", (0, 0), (0, -1), 2.2, ACCENT),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#faf8f5")),
                    ]
                )
            )
            story += [wrap, Spacer(1, 9)]
            continue

        # Lists
        if re.match(r"^([-*]|\d+\.)\s+", stripped):
            items = []
            ordered = bool(re.match(r"^\d+\.\s+", stripped))
            while i < len(lines):
                cur = lines[i].strip()
                m2 = re.match(r"^(?:[-*]|\d+\.)\s+(.*)$", cur)
                if not m2:
                    # Continuation line indented under the bullet.
                    if cur and lines[i].startswith(("  ", "\t")) and items:
                        items[-1] += " " + cur
                        i += 1
                        continue
                    break
                items.append(m2.group(1))
                i += 1
            flow = ListFlowable(
                [ListItem(Paragraph(inline(t), styles["bullet"]), leftIndent=15) for t in items],
                bulletType="1" if ordered else "bullet",
                bulletFontSize=8,
                bulletColor=ACCENT,
                start="1" if ordered else None,
                leftIndent=13,
            )
            story += [flow, Spacer(1, 8)]
            continue

        # Paragraph
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(
            r"^(#{1,4}\s|[-*]\s|\d+\.\s|\||>|```|-{3,}$)", lines[i].strip()
        ):
            buf.append(lines[i].strip())
            i += 1
        if buf:
            story.append(Paragraph(inline(" ".join(buf)), styles["body"]))

    return story


HEADER_TITLE = "Sentinel — AI Product Review Board"
FOOTER_NOTE = "24 July 2026 · seventh review · three-vendor $100M due diligence"


def main() -> int:
    styles = build_styles()
    md = SRC.read_text(encoding="utf-8")
    headings = collect_headings(md)

    left = right = 18 * mm
    top, bottom = 18 * mm, 17 * mm
    page_w, page_h = A4
    frame_w = page_w - left - right

    doc = BaseDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=left,
        rightMargin=right,
        topMargin=top,
        bottomMargin=bottom,
        title="Sentinel — AI Product Review Board Report",
        author="AI Product Review Board (Claude Opus 4.8 · OpenAI Codex · Antigravity Gemini 3.1 Pro)",
        subject="Three-model $100M due-diligence review of product, market, architecture and company case",
    )

    def decorate(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.6)
        canvas.setFillColor(MUTED)
        if canvas.getPageNumber() > 1:
            canvas.drawString(left, page_h - top + 6 * mm, HEADER_TITLE)
            canvas.setStrokeColor(RULE)
            canvas.setLineWidth(0.4)
            canvas.line(left, page_h - top + 4.6 * mm, page_w - right, page_h - top + 4.6 * mm)
        canvas.drawRightString(page_w - right, bottom - 7 * mm, str(canvas.getPageNumber()))
        canvas.drawString(left, bottom - 7 * mm, FOOTER_NOTE)
        canvas.restoreState()

    frame = Frame(left, bottom, frame_w, page_h - top - bottom, id="body")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=decorate)])
    doc.build(parse(md, styles, frame_w, headings))

    print(f"Wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
