"""
mapper/matrix_render.py

Renders matrix_data.py's output as an HTML/CSS grid that looks like the
real attack.mitre.org / atlas.mitre.org matrix pages -- tactic columns,
technique cells stacked under each, sub-techniques nested as an indented
strip under their parent -- colored by the technique's worst-seen alert
severity instead of left plain. Streamlit has no native tactic-matrix
widget, so this builds one div per cell and hands the whole thing to
st.components.v1.html (an iframe -- NOT st.markdown(unsafe_allow_html=True),
which Streamlit's sanitizer partially strips; a matrix this dense needs
full control over layout, not just inline spans).

Kept framework-agnostic: the same render_matrix() draws both ATT&CK and
ATLAS from matrix_data.build_matrix()'s identical shape; only the page
title/column count differ, which the caller passes in.
"""

import html

from .matrix_data import SEVERITY_COLORS

_CSS = """
<style>
  body { margin: 0; font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: transparent; }
  .matrix-wrap { display: flex; gap: 6px; overflow-x: auto; padding: 4px 2px 12px 2px; }
  .matrix-col { min-width: 168px; max-width: 168px; flex: 0 0 auto; }
  .matrix-col-header {
    font-size: 12px; font-weight: 600; color: #37474f; background: #eceff1;
    border-radius: 4px; padding: 6px 8px; margin-bottom: 4px; text-align: center;
    min-height: 32px; display: flex; align-items: center; justify-content: center;
  }
  .matrix-cell {
    font-size: 11.5px; color: #fff; border-radius: 3px; padding: 5px 7px;
    margin-bottom: 3px; line-height: 1.3; cursor: default; position: relative;
  }
  .matrix-cell.no-hit { color: #37474f; }
  .matrix-cell a { color: inherit; text-decoration: none; }
  .matrix-cell a:hover { text-decoration: underline; }
  .matrix-sub { margin-left: 10px; margin-top: 3px; border-left: 2px solid rgba(255,255,255,0.5); padding-left: 6px; }
  .matrix-more { font-size: 10.5px; color: #78909c; margin: -1px 0 4px 12px; }
  .matrix-badge {
    display: inline-block; font-size: 9.5px; font-weight: 700; background: rgba(255,255,255,0.28);
    border-radius: 8px; padding: 0 5px; margin-left: 4px;
  }
  .matrix-legend { display: flex; gap: 14px; align-items: center; margin: 2px 0 10px 2px; font-size: 12px; color: #37474f; flex-wrap: wrap; }
  .matrix-legend-swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; margin-right: 5px; vertical-align: middle; }
  .owasp-strip { display: flex; gap: 8px; flex-wrap: wrap; padding: 4px 2px 8px 2px; }
  .owasp-card {
    flex: 1 1 160px; min-width: 160px; color: #fff; border-radius: 6px; padding: 10px 12px;
    font-size: 12.5px; line-height: 1.35;
  }
  .owasp-card.no-hit { color: #37474f; }
  .owasp-card a { color: inherit; text-decoration: none; font-weight: 700; }
  .owasp-card a:hover { text-decoration: underline; }
</style>
"""


def _legend_html() -> str:
    order = ["Critical", "High", "Medium", "Low", "Informational", None]
    items = []
    for sev in order:
        label = sev or "No alert yet"
        color = SEVERITY_COLORS[sev]
        items.append(
            f'<span><span class="matrix-legend-swatch" style="background:{color}"></span>{html.escape(label)}</span>'
        )
    return f'<div class="matrix-legend">{"".join(items)}</div>'


def _cell_inner(row: dict) -> str:
    label = html.escape(row["name"])
    title = html.escape(f'{row["id"]}' + (f' -- alerts {", ".join(map(str, row["alert_ids"]))}' if row["alert_ids"] else ""))
    link = (f'<a href="{html.escape(row["url"])}" target="_blank" rel="noopener" title="{title}">{label}</a>'
            if row["url"] else label)
    badge = f'<span class="matrix-badge">{len(row["alert_ids"])}</span>' if row["alert_ids"] else ""
    return f'{link}{badge}'


def _cell_html(row: dict) -> str:
    """A technique cell, plus its sub-techniques. Untouched sub-techniques are collapsed into a
    "+N sub-techniques" line (as the real matrix pages do); sub-techniques with a hit are always
    shown. A parent with no direct hit but a hit sub-technique gets a colored left edge."""
    color = SEVERITY_COLORS[row["severity"]]
    cls = "matrix-cell" + ("" if row["severity"] else " no-hit")
    edge = (f"border-left:5px solid {SEVERITY_COLORS[row['child_severity']]};"
            if not row["severity"] and row.get("child_severity") else "")
    hit_subs = [s for s in row["subtechniques"] if s["severity"]]
    hidden = len(row["subtechniques"]) - len(hit_subs)
    sub_html = "".join(
        f'<div class="matrix-cell matrix-sub" style="background:{SEVERITY_COLORS[s["severity"]]}">{_cell_inner(s)}</div>'
        for s in hit_subs
    )
    if hidden:
        sub_html += f'<div class="matrix-more">+{hidden} sub-technique{"s" if hidden > 1 else ""}</div>'
    return f'<div class="{cls}" style="background:{color};{edge}">{_cell_inner(row)}</div>{sub_html}'


def _touched(row: dict) -> bool:
    return bool(row["severity"] or row.get("child_severity"))


def render_matrix_html(matrix: dict, hide_untouched: bool = False) -> str:
    """matrix: matrix_data.build_matrix()'s return value. Returns a full HTML document.
    hide_untouched=True drops techniques no alert mapped to, and empty columns."""
    tactic_hits = matrix.get("tactic_hits", {})
    cols_html = []
    for tactic in matrix["tactics"]:
        rows = matrix["columns"].get(tactic["id"], [])
        if hide_untouched:
            rows = [r for r in rows if _touched(r)]
            if not rows and tactic["id"] not in tactic_hits:
                continue
        rows_html = "".join(_cell_html(r) for r in rows) or (
            '<div class="matrix-cell no-hit" style="background:#f5f5f5;color:#9e9e9e;font-style:italic;">'
            '(no techniques hit)</div>')
        head_sev = tactic_hits.get(tactic["id"])
        head_style = f' style="background:{SEVERITY_COLORS[head_sev]};color:#fff"' if head_sev else ""
        cols_html.append(
            f'<div class="matrix-col"><div class="matrix-col-header"{head_style} title="{html.escape(tactic["id"])}">'
            f'{html.escape(tactic["name"])}</div>{rows_html}</div>'
        )
    if not cols_html:
        cols_html.append('<div style="color:#607d8b;font-size:13px;padding:8px">No classified alert maps to this framework yet.</div>')
    body = f'{_legend_html()}<div class="matrix-wrap">{"".join(cols_html)}</div>'
    return f"<html><head>{_CSS}</head><body>{body}</body></html>"


def render_owasp_strip_html(cards: list) -> str:
    card_html = []
    for c in cards:
        color = SEVERITY_COLORS[c["severity"]]
        cls = "owasp-card" + ("" if c["severity"] else " no-hit")
        label = html.escape(f'{c["id"]} — {c["name"]}')
        link = f'<a href="{html.escape(c["url"])}" target="_blank" rel="noopener">{label}</a>' if c["url"] else label
        badge = f'<span class="matrix-badge">{len(c["alert_ids"])} alert(s)</span>' if c["alert_ids"] else "no alerts yet"
        card_html.append(f'<div class="{cls}" style="background:{color}">{link}<br/>{badge}</div>')
    body = f'{_legend_html()}<div class="owasp-strip">{"".join(card_html)}</div>'
    return f"<html><head>{_CSS}</head><body>{body}</body></html>"
