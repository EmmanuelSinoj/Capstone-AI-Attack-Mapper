"""Shared look for the dashboard: a dark, SIEM-style console (panels, KPI tiles, severity badges, event tables).

Every page uses the same building blocks:
  header(title, subtitle, about)  page title, one-line subtitle and an "About this page" button with the method notes
  kpis([...])                     a row of KPI tiles
  panel(title, note)              a bordered panel with a title bar (use as a context manager)
  alert(level, title, text)       one item in a "needs attention" list
  chart(altair_chart)             dark chart styling
"""
from __future__ import annotations

import html
from contextlib import contextmanager

import altair as alt
import pandas as pd
import streamlit as st

BG, PANEL, PANEL2, BORDER = "#090F1B", "#101B2C", "#17263C", "#2A3C55"
TEXT, MUTED, ACCENT = "#E8EFF8", "#A0B2CA", "#5CC8FF"
GOOD, WARN, BAD, PURPLE, ORANGE = "#50D9AE", "#F5CE6A", "#FF7585", "#C0A1FF", "#FFA36A"
TONE = {"good": GOOD, "warn": WARN, "bad": BAD, "accent": ACCENT, None: TEXT}

# Event severity, SIEM style. Assigned in data.event_severity().
SEVERITY = ["Critical", "High", "Medium", "Low", "False alarm", "Info"]
SEV_COLOR = {"Critical": BAD, "High": ORANGE, "Medium": WARN, "Low": "#80B4FF", "False alarm": PURPLE, "Info": "#A0B2CA"}
FAMILY_COLOR = {"promptinject": ACCENT, "dan": PURPLE, "encoding": ORANGE, "pyrit": GOOD, "harmless": MUTED}

# Explanations use the existing metric definitions; values still come from each page.
SEVERITY_HELP = {
    "Critical": "The attack worked and the detector missed it.",
    "High": "The attack worked and the detector caught it.",
    "Medium": "The attack failed but the detector flagged it.",
    "Low": "The attack failed and was not flagged.",
    "False alarm": "A harmless customer message was flagged by the detector.",
    "Info": "Informational status or event.",
}
KPI_HELP = {
    "Attacks that worked": "Successful attacks as a share of graded attack requests, using the attack tool's grading.",
    "Critical: missed": SEVERITY_HELP["Critical"],
    "False alarms": "Harmless messages flagged by the detector as a share of harmless messages.",
    "Detection rate": "Successful attacks caught by the detector as a share of successful attacks in this selection.",
    "Failed attempts flagged": "Failed attacks flagged by the detector as a share of graded failed attacks.",
    "Not graded": "Attack rows without an attack-tool grade; excluded from graded attack metrics.",
    "Mapper false positives": "Harmless messages classified as category B, out of the sampled harmless messages.",
    "Harmless called B": "Harmless messages classified as category B at any confidence.",
    "Attacks confirmed (B)": "Sampled live attacks classified as category B: prompt injection and jailbreaking.",
    "Caught what detection missed": "Successful attacks missed by the detector that the Mapper classified as B.",
    "Mapper accuracy": "Held-out category accuracy from the Model Selection Pilot on unseen synthetic alerts.",
    "Held-out accuracy": "Held-out category accuracy from the Model Selection Pilot on unseen synthetic alerts.",
    "Classification, held-out": "Held-out category accuracy on the unseen synthetic alerts.",
    "Classification, live": "Sampled live attacks classified as B; the caption also reports harmless messages called B.",
    "Detection, successful attacks": "Successful attacks caught by the detector in valid rounds.",
    "Failed classifications": "Classification requests for which the API refused the content.",
    "Latest decision (fresh rounds)": "Latest hardening decision based on fresh attack rounds, excluding replay-only decisions.",
    "Decisions recorded": "All recorded hardening decisions, including replay tests on seen prompts.",
    "Harmless refusals": "Refusals by prompt version in the latest harmless-message utility check.",
    "Defensive effectiveness": "Fresh-round comparison of the original and hardened prompts.",
}

CSS = f"""
<style>
  .stApp {{background:{BG}; color:{TEXT};}}
  .block-container, [data-testid="stMainBlockContainer"] {{padding:3.4rem 2rem 3rem; max-width:1600px;}}
  [data-testid="stHeader"] {{background:{BG}ed; border-bottom:1px solid {BORDER}70;}}
  [data-testid="stSidebar"] {{background:#0D1625; border-right:1px solid {BORDER};}}
  [data-testid="stSidebarNav"] a {{border:1px solid transparent; border-radius:8px; transition:background .16s, border-color .16s;}}
  [data-testid="stSidebarNav"] a:hover {{background:{PANEL2}; border-color:{BORDER};}}
  [data-testid="stSidebarNav"] a[aria-current="page"] {{background:{PANEL2}; border-color:{BORDER}; box-shadow:inset 3px 0 {ACCENT};}}
  h1, h2, h3 {{letter-spacing:-.025em; color:{TEXT};}}
  .hdr {{display:flex; flex-direction:column; gap:6px; margin:0 0 6px;}}
  .hdr .t {{font-size:clamp(1.65rem,2.4vw,2.1rem); font-weight:700; line-height:1.2; margin:0; padding:0;}}
  .hdr .crumb {{order:-1; color:{ACCENT}; font-size:.68rem; font-weight:700; text-transform:uppercase; letter-spacing:.16em;}}
  .scope {{color:{MUTED}; font-size:.78rem; margin:-2px 0 12px; line-height:1.5;}}
  .scope .k {{color:{ACCENT}; font-weight:700; text-transform:uppercase; letter-spacing:.08em; font-size:.68rem; margin-right:6px;}}
  .sub {{color:{MUTED}; font-size:.9rem; line-height:1.55; max-width:80ch; margin:0 0 .5rem;}}
  .kpis {{display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,150px),1fr)); gap:12px; margin:4px 0 12px;}}
  .kpis.count-6 {{grid-template-columns:repeat(3,minmax(0,1fr));}}
  [data-testid="stColumn"] .kpis.count-3 {{grid-template-columns:repeat(2,minmax(0,1fr));}}
  [data-testid="stColumn"] .kpis.count-3 .kpi:last-child {{grid-column:1 / -1;}}
  .kpi {{position:relative; min-width:0; background:linear-gradient(145deg,{PANEL2}70,{PANEL} 65%);
         border:1px solid {BORDER}; border-top:2px solid var(--c); border-radius:10px; padding:17px 16px 15px;
         transition:transform .18s ease, border-color .18s, box-shadow .18s;}}
  .kpi:hover, .kpi:focus-visible {{transform:translateY(-3px); border-color:var(--c); box-shadow:0 10px 24px #00000030; z-index:3;}}
  .kpi .l {{display:flex; justify-content:space-between; gap:8px; align-items:flex-start; min-height:2.8em;
            color:{MUTED}; font-size:.69rem; font-weight:650; text-transform:uppercase; letter-spacing:.065em; line-height:1.4;}}
  .kpi .hint {{color:{MUTED}; font-size:.7rem; font-weight:500; text-transform:none; border:1px solid {BORDER};
               border-radius:50%; width:15px; height:15px; text-align:center; flex-shrink:0; line-height:14px;}}
  .kpi .v {{font-size:clamp(1.5rem,2.1vw,2rem); line-height:1.2; font-weight:700; margin:5px 0 9px;
            font-variant-numeric:tabular-nums; letter-spacing:-.035em; color:var(--c); overflow-wrap:anywhere;}}
  .kpi .s {{color:{MUTED}; font-size:.76rem; line-height:1.5; overflow-wrap:anywhere;}}
  .kpi .tip {{position:absolute; top:calc(100% + 8px); left:0; width:100%; box-sizing:border-box; padding:11px 13px;
              border:1px solid {BORDER}; border-radius:8px; background:{PANEL2}; color:{TEXT}; font-size:.78rem; line-height:1.5;
              box-shadow:0 8px 24px #00000050; opacity:0; visibility:hidden; pointer-events:none; transition:opacity .16s;}}
  .kpi:hover .tip, .kpi:focus-visible .tip {{opacity:1; visibility:visible; pointer-events:auto;}}
  .ptitle {{color:{TEXT}; border-bottom:1px solid {BORDER}; padding:0 0 12px; margin:0 0 4px;
             min-height:38px; box-sizing:border-box;
             display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:5px 14px;}}
  .ptitle .panel-heading {{font-size:.89rem; line-height:1.4; font-weight:650; letter-spacing:0; margin:0; padding:0;}}
  .ptitle .n {{color:{MUTED}; font-size:.73rem; line-height:1.45; font-weight:400; overflow-wrap:anywhere;}}
  [data-testid="stVerticalBlockBorderWrapper"]:has(.ptitle),
  [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .ptitle) {{
    background:{PANEL}; border-color:{BORDER} !important; border-radius:10px;
    transition:border-color .18s, box-shadow .18s;}}
  [data-testid="stVerticalBlockBorderWrapper"]:has(.ptitle):hover,
  [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .ptitle):hover {{
    border-color:#456481 !important; box-shadow:0 4px 20px #00000016;}}
  /* Stretch sibling panels to their row's height without fixing content height. */
  [data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:has(> [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"] .ptitle),
  [data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"]:has(.ptitle) {{flex:1 1 auto;}}
  .flow {{display:flex; align-items:stretch; gap:8px; margin:0 0 12px; flex-wrap:wrap;}}
  .stage {{flex:1 1 150px; min-width:0; background:{PANEL}; border:1px solid {BORDER}; border-radius:8px;
           padding:13px 14px; border-top:2px solid {ACCENT}; transition:background .18s, border-color .18s, transform .18s;}}
  .stage:hover, .stage:focus-visible {{background:{PANEL2}; border-color:{ACCENT}; transform:translateY(-2px);}}
  .stage .t {{font-weight:650; font-size:.68rem; text-transform:uppercase; letter-spacing:.1em; color:{MUTED};}}
  .stage .n {{font-size:1.3rem; font-weight:650; font-variant-numeric:tabular-nums; color:{TEXT}; margin:5px 0;}}
  .stage .d {{color:{MUTED}; font-size:.74rem; line-height:1.5; overflow-wrap:anywhere;}}
  .arrow {{align-self:center; color:{MUTED}; font-size:1rem;}}
  .al {{display:flex; gap:11px; align-items:flex-start; padding:11px 10px; border:1px solid {BORDER}; border-radius:8px;
         background:{BG}65; transition:background .16s, border-color .16s;}}
  .al:hover {{background:{PANEL2}; border-color:#456481;}}
  .badge {{display:inline-block; white-space:nowrap; text-align:center; padding:3px 8px; border-radius:5px; font-size:.69rem;
           line-height:1.4; font-weight:700; color:var(--sev); background:color-mix(in srgb,var(--sev) 12%,{BG});
           border:1px solid color-mix(in srgb,var(--sev) 40%,{BORDER}); transition:filter .16s;}}
  .badge:hover {{filter:brightness(1.2);}}
  .al .x {{font-size:.82rem; line-height:1.5; overflow-wrap:anywhere;}} .al .x .m {{display:block; color:{MUTED}; margin-top:4px;}}
  .tag {{display:inline-block; padding:3px 9px; border-radius:5px; font-size:.73rem; font-weight:500; border:1px solid {BORDER};
         margin:0 5px 5px 0; color:{TEXT}; background:{PANEL2}; overflow-wrap:anywhere; transition:border-color .16s;}}
  .tag:hover {{border-color:{ACCENT};}}
  .callout {{background:{PANEL2}; border:1px solid {BORDER}; border-left:3px solid {WARN}; border-radius:8px;
             padding:12px 14px; margin:4px 0; font-size:.85rem; line-height:1.6; transition:box-shadow .16s;}}
  .callout:hover {{box-shadow:0 3px 14px #00000025;}}
  .callout.good {{border-left-color:{GOOD};}} .callout.bad {{border-left-color:{BAD};}}
  .muted, [data-testid="stCaptionContainer"] {{color:{MUTED};}}
  [data-testid="stWidgetLabel"] p {{font-size:.79rem; font-weight:550; color:{MUTED};}}
  [data-testid="stButton"] button, [data-testid="stPopover"] button {{border-radius:8px; transition:border-color .16s, background .16s;}}
  [data-testid="stButton"] button:hover, [data-testid="stPopover"] button:hover {{border-color:{ACCENT}; background:{PANEL2};}}
  [data-testid="stExpander"] {{border-color:{BORDER}; border-radius:8px; background:{PANEL};}}
  [data-testid="stExpander"] summary:hover {{background:{PANEL2};}}
  /* The toolbar sits above this frame. Clipping it hides "Show chart" in data view. */
  [data-testid="stDataFrame"] {{border-radius:8px; overflow:visible; box-sizing:border-box;
                               border:1px solid {BORDER}; transition:border-color .16s;}}
  [data-testid="stDataFrame"]:hover {{border-color:#456481;}}
  /* Native dataframes are canvas-based; their cell hover uses the Streamlit theme.
     This selector also supports any semantic tables rendered by Streamlit. */
  [data-testid="stTable"] tbody tr:hover {{background:{PANEL2};}}
  [data-testid="stCode"] {{border:1px solid {BORDER}; border-radius:8px;}}
  [data-testid="stAlert"] {{border-radius:8px;}}
  [data-baseweb="tab"] {{font-size:.84rem;}}
  [data-baseweb="tab"]:hover {{color:{ACCENT};}}
  #vg-tooltip-element {{background:{PANEL2} !important; color:{TEXT} !important; border:1px solid {BORDER} !important;
                         border-radius:8px !important; padding:11px 14px !important; font-size:12px !important;
                         box-shadow:0 8px 28px #00000050 !important;}}
  #vg-tooltip-element td.key {{color:{MUTED} !important; padding-right:16px !important;}}
  #vg-tooltip-element td.value {{font-variant-numeric:tabular-nums; color:{TEXT} !important;}}
  .kpi:focus-visible, .stage:focus-visible {{outline:2px solid {ACCENT}; outline-offset:3px;}}
  @media (min-width:1500px) {{.kpis.count-6 {{grid-template-columns:repeat(6,minmax(0,1fr));}}}}
  @media (max-width:1100px) {{
    .kpis {{grid-template-columns:repeat(2,minmax(0,1fr));}}
    .kpi:last-child:nth-child(odd) {{grid-column:1 / -1;}}
    .kpis.count-6 .kpi:last-child {{grid-column:auto;}}
    .arrow {{display:none;}}
    [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] .ptitle) {{flex-direction:column;}}
    [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] .ptitle) > [data-testid="stColumn"] {{width:100%; flex:1 1 auto;}}
    [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] [data-testid="stMultiSelect"]) {{flex-wrap:wrap;}}
    [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] [data-testid="stMultiSelect"]) > [data-testid="stColumn"] {{flex:1 1 220px; min-width:min(100%,220px);}}
  }}
  @media (max-width:700px) {{
    .block-container, [data-testid="stMainBlockContainer"] {{padding:2.8rem 1rem 2rem;}}
    .kpis, .kpis.count-6 {{grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px;}}
    .kpi {{padding:13px 12px;}} .kpi .v {{font-size:1.5rem;}}
    .flow {{gap:8px;}} .stage {{flex-basis:130px;}}
    .al {{flex-wrap:wrap;}} .ptitle {{flex-direction:column;}}
  }}
  @media (max-width:380px) {{.kpis, .kpis.count-6 {{grid-template-columns:1fr;}}}}
  @media (prefers-reduced-motion:reduce) {{
    .stApp *, .stApp *::before, .stApp *::after {{transition:none !important; animation:none !important;}}
    .kpi:hover, .kpi:focus-visible, .stage:hover, .stage:focus-visible {{transform:none;}}
  }}
</style>
"""


def setup():
    st.markdown(CSS, unsafe_allow_html=True)


def header(title: str, subtitle: str = "", about: str = "", crumb: str = ""):
    """Page title and subtitle. The method notes go behind an 'About this page' button instead of on the page."""
    c1, c2 = st.columns([4, 1.15], vertical_alignment="bottom")
    with c1:
        st.markdown(f'<div class="hdr"><h1 class="t">{html.escape(title)}</h1>'
                    f'<span class="crumb">{html.escape(crumb)}</span></div>', unsafe_allow_html=True)
        if subtitle:
            st.markdown(f'<div class="sub">{subtitle}</div>', unsafe_allow_html=True)
    if about:
        with c2:
            with st.popover("About this page", icon=":material/info:", width="stretch"):
                st.markdown(about)


def kpis(items):
    """items: (label, value, sub, tone) tuples; tone in good / warn / bad / accent / None."""
    cards = []
    for label, value, sub, tone in items:
        explanation = KPI_HELP.get(label, SEVERITY_HELP.get(label, f"{label}: {sub}" if sub else label))
        if label.startswith("Pass the gate"):
            explanation = "Successful attacks classified as B at or above the displayed confidence threshold."
        accessible = html.escape(f"{label}: {value}. {sub or ''}. {explanation}", quote=True)
        cards.append(
            f'<div class="kpi" tabindex="0" role="group" aria-label="{accessible}" style="--c:{TONE.get(tone, TEXT)}">'
            f'<div class="l">{html.escape(label)}<span class="hint" aria-hidden="true">i</span></div>'
            f'<div class="v">{html.escape(str(value))}</div>'
            f'<div class="s">{html.escape(sub or "")}</div>'
            f'<span class="tip" aria-hidden="true">{html.escape(explanation)}</span></div>')
    st.markdown(f'<div class="kpis count-{len(cards)}">{"".join(cards)}</div>', unsafe_allow_html=True)


def pipeline(stages):
    """Present the existing (title, value, detail) stages without altering their values."""
    cards = [
        f'<div class="stage" tabindex="0" role="group" aria-label="{html.escape(f"{title}: {value}. {detail}", quote=True)}">'
        f'<div class="t">{html.escape(title)}</div><div class="n">{html.escape(str(value))}</div>'
        f'<div class="d">{html.escape(detail)}</div></div>' for title, value, detail in stages
    ]
    st.markdown('<div class="flow">' + '<span class="arrow" aria-hidden="true">›</span>'.join(cards) + '</div>',
                unsafe_allow_html=True)


@contextmanager
def panel(title: str, note: str = ""):
    with st.container(border=True):
        st.markdown(f'<div class="ptitle"><span class="panel-heading" role="heading" aria-level="2">{html.escape(title)}</span>'
                    f'<span class="n">{html.escape(note)}</span></div>',
                    unsafe_allow_html=True)
        yield


def badge(level: str) -> str:
    description = html.escape(SEVERITY_HELP.get(level, level), quote=True)
    return (f'<span class="badge" title="{description}" style="--sev:{SEV_COLOR.get(level, MUTED)}">'
            f'{html.escape(level)}</span>')


def alert(level: str, title: str, text: str = ""):
    """One row of a 'needs attention' list. title and text may contain simple HTML."""
    st.markdown(f'<div class="al">{badge(level)}<div class="x"><b>{title}</b> <span class="m">{text}</span></div></div>',
                unsafe_allow_html=True)


def callout(text: str, tone: str = "warn"):
    st.markdown(f'<div class="callout {tone}">{text}</div>', unsafe_allow_html=True)


def pct(a, b, digits=1) -> str:
    return f"{100 * a / b:.{digits}f}%" if b else "–"


def sev_style(df: pd.DataFrame, col: str = "Severity"):
    """Colour a severity column in st.dataframe."""
    def f(v):
        c = SEV_COLOR.get(v)
        return f"color:{c}; font-weight:700" if c else ""
    return df.style.map(f, subset=[col]) if col in df.columns else df


def chart(c: alt.Chart, height: int = 240) -> alt.Chart:
    # Work on a copy. Hover changes only mark emphasis, never filters or scales.
    c = _chart_hover(c.copy(deep=True))
    return (c.properties(height=height, background="transparent",
                         autosize=alt.AutoSizeParams(type="fit-x", contains="padding"),
                         padding={"left": 8, "right": 8, "top": 8, "bottom": 8})
            .configure_view(strokeOpacity=0)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER, domainColor=BORDER, tickColor=BORDER,
                            labelFont="sans-serif", titleFont="sans-serif", labelFontSize=11, titleFontSize=11,
                            titleFontWeight="normal", titlePadding=10, labelPadding=5, gridOpacity=.45,
                            gridDash=[2, 4], domainOpacity=.4, tickSize=3)
            .configure_legend(labelColor=TEXT, titleColor=MUTED, orient="bottom", labelFontSize=11,
                              labelFont="sans-serif", titleFont="sans-serif", symbolSize=64, symbolStrokeWidth=1,
                              columns=3, labelLimit=220, labelPadding=6, padding=0, offset=12, rowPadding=6, columnPadding=12,
                              titlePadding=8, gradientLength=140, gradientThickness=10)
            .configure_title(color=TEXT, font="sans-serif", fontSize=14, anchor="start")
            .configure_range(category=[ACCENT, PURPLE, GOOD, ORANGE, WARN, BAD, MUTED])
            .configure_mark(tooltip=True)
            .configure_line(strokeWidth=2.5)
            .configure_point(size=60, filled=True))


def _chart_hover(c):
    """Emphasise hovered bars, cells and arcs; preserve all chart data and encodings."""
    if isinstance(c, alt.LayerChart):
        c.layer = [_chart_hover(layer) for layer in c.layer]
    elif isinstance(c, alt.Chart):
        mark = c.mark if isinstance(c.mark, str) else getattr(c.mark, "type", None)
        if mark in {"bar", "rect", "arc", "circle", "point"}:
            hover = alt.selection_point(on="pointerover", clear="pointerout", empty=False)
            c = c.add_params(hover).encode(
                stroke=alt.condition(hover, alt.value(TEXT), alt.value(PANEL)),
                strokeWidth=alt.condition(hover, alt.value(2), alt.value(.5)))
    return c


def chart_legend(c, **overrides):
    """Adjust a legend without discarding the shared orientation, spacing or colours."""
    return c.configure_legend(**{**c.config.legend.to_dict(), **overrides})


def scope(*parts: str):
    """One muted line under the page title naming the data shown: rounds, Mapper run, versions, dates."""
    txt = " · ".join(html.escape(p) for p in parts if p)
    st.markdown(f'<div class="scope"><span class="k">Data</span> {txt}</div>', unsafe_allow_html=True)


@contextmanager
def details(label: str = "Details"):
    """Collapsed section for method and supporting views, so each page leads with its headline results."""
    with st.expander(label, icon=":material/tune:", expanded=False):
        yield


def no_data(text: str):
    st.info(text, icon=":material/hourglass_empty:")
