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

BG, PANEL, PANEL2, BORDER = "#0B1220", "#111A2E", "#16213A", "#24314A"
TEXT, MUTED, ACCENT = "#E2E8F0", "#8DA2C0", "#38BDF8"
GOOD, WARN, BAD, PURPLE, ORANGE = "#34D399", "#FBBF24", "#F87171", "#A78BFA", "#FB923C"
TONE = {"good": GOOD, "warn": WARN, "bad": BAD, "accent": ACCENT, None: TEXT}

# Event severity, SIEM style. Assigned in data.event_severity().
SEVERITY = ["Critical", "High", "Medium", "Low", "False alarm", "Info"]
SEV_COLOR = {"Critical": "#EF4444", "High": ORANGE, "Medium": WARN, "Low": "#60A5FA", "False alarm": PURPLE, "Info": "#64748B"}
FAMILY_COLOR = {"promptinject": ACCENT, "dan": PURPLE, "encoding": ORANGE, "pyrit": GOOD, "harmless": "#64748B"}

CSS = f"""
<style>
  .stApp {{background:{BG};}}
  .block-container, [data-testid="stMainBlockContainer"] {{padding-top:3.6rem; max-width:1500px;}}
  [data-testid="stHeader"] {{background:transparent;}}
  [data-testid="stSidebar"] {{background:#0A1020; border-right:1px solid {BORDER};}}
  h1, h2, h3 {{letter-spacing:-0.01em;}}
  .hdr {{display:flex; align-items:baseline; gap:14px; margin:0 0 2px;}}
  .hdr .t {{font-size:1.65rem; font-weight:700; color:{TEXT};}}
  .hdr .crumb {{color:{MUTED}; font-size:0.8rem; text-transform:uppercase; letter-spacing:.08em;}}
  .sub {{color:{MUTED}; font-size:0.9rem; margin:0 0 0.9rem;}}
  .kpis {{display:grid; grid-template-columns:repeat(auto-fit,minmax(165px,1fr)); gap:10px; margin:0 0 0.9rem;}}
  .kpi {{background:{PANEL}; border:1px solid {BORDER}; border-left:3px solid var(--c); border-radius:6px; padding:10px 14px;}}
  .kpi .l {{color:{MUTED}; font-size:0.72rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em;}}
  .kpi .v {{font-size:1.6rem; font-weight:700; margin-top:2px; font-variant-numeric:tabular-nums; color:var(--c);}}
  .kpi .s {{color:{MUTED}; font-size:0.76rem; margin-top:1px; line-height:1.3;}}
  .ptitle {{font-size:0.8rem; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:{TEXT};
            border-bottom:1px solid {BORDER}; padding:0 0 6px; margin:0 0 8px; display:flex; justify-content:space-between;}}
  .ptitle .n {{color:{MUTED}; font-weight:500; text-transform:none; letter-spacing:0;}}
  [data-testid="stVerticalBlockBorderWrapper"] {{background:{PANEL}; border-color:{BORDER} !important; border-radius:6px;}}
  .flow {{display:flex; align-items:stretch; gap:6px; margin:0 0 0.9rem; flex-wrap:wrap;}}
  .stage {{flex:1 1 140px; background:{PANEL}; border:1px solid {BORDER}; border-radius:6px; padding:8px 12px; border-top:2px solid {ACCENT};}}
  .stage .t {{font-weight:700; font-size:0.72rem; text-transform:uppercase; letter-spacing:.06em; color:{MUTED};}}
  .stage .n {{font-size:1.25rem; font-weight:700; margin:2px 0 0;}}
  .stage .d {{color:{MUTED}; font-size:0.74rem; line-height:1.3;}}
  .arrow {{align-self:center; color:{MUTED}; font-size:1.1rem;}}
  .al {{display:flex; gap:10px; align-items:flex-start; padding:7px 0; border-bottom:1px solid {BORDER};}}
  .al:last-child {{border-bottom:none;}}
  .badge {{display:inline-block; min-width:74px; text-align:center; padding:1px 8px; border-radius:4px; font-size:0.72rem;
           font-weight:700; color:#0B1220;}}
  .al .x {{font-size:0.88rem; line-height:1.35;}} .al .x .m {{color:{MUTED};}}
  .tag {{display:inline-block; padding:1px 8px; border-radius:4px; font-size:0.76rem; font-weight:600; border:1px solid {BORDER};
         margin:0 4px 4px 0; color:{TEXT}; background:{PANEL2};}}
  .callout {{background:{PANEL2}; border:1px solid {BORDER}; border-left:3px solid {WARN}; border-radius:6px; padding:8px 12px; margin:4px 0;}}
  .callout.good {{border-left-color:{GOOD};}} .callout.bad {{border-left-color:{BAD};}}
  .muted {{color:{MUTED};}}
</style>
"""


def setup():
    st.markdown(CSS, unsafe_allow_html=True)


def header(title: str, subtitle: str = "", about: str = "", crumb: str = ""):
    """Page title and subtitle. The method notes go behind an 'About this page' button instead of on the page."""
    c1, c2 = st.columns([5, 1], vertical_alignment="bottom")
    with c1:
        st.markdown(f'<div class="hdr"><span class="t">{html.escape(title)}</span>'
                    f'<span class="crumb">{html.escape(crumb)}</span></div>', unsafe_allow_html=True)
        if subtitle:
            st.markdown(f'<div class="sub">{subtitle}</div>', unsafe_allow_html=True)
    if about:
        with c2:
            with st.popover("About this page", icon=":material/info:", width="stretch"):
                st.markdown(about)


def kpis(items):
    """items: (label, value, sub, tone) tuples; tone in good / warn / bad / accent / None."""
    cards = "".join(
        f'<div class="kpi" style="--c:{TONE.get(t, TEXT)}"><div class="l">{html.escape(l)}</div>'
        f'<div class="v">{html.escape(str(v))}</div>'
        f'<div class="s">{html.escape(s or "")}</div></div>' for l, v, s, t in items)
    st.markdown(f'<div class="kpis">{cards}</div>', unsafe_allow_html=True)


@contextmanager
def panel(title: str, note: str = ""):
    with st.container(border=True):
        st.markdown(f'<div class="ptitle"><span>{html.escape(title)}</span><span class="n">{html.escape(note)}</span></div>',
                    unsafe_allow_html=True)
        yield


def badge(level: str) -> str:
    return f'<span class="badge" style="background:{SEV_COLOR.get(level, MUTED)}">{html.escape(level)}</span>'


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
    return (c.properties(height=height, background="transparent")
            .configure_view(strokeOpacity=0)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER, domainColor=BORDER, tickColor=BORDER,
                            labelFontSize=11, titleFontSize=11, titleFontWeight="normal")
            .configure_legend(labelColor=TEXT, titleColor=MUTED, orient="bottom", labelFontSize=11, symbolSize=80, columns=4, labelLimit=160)
            .configure_title(color=TEXT))


def no_data(text: str):
    st.info(text, icon=":material/hourglass_empty:")
