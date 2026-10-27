"""Shared look for the dashboard: theme colours, KPI cards, page intro, chart styling."""
from __future__ import annotations

import html

import altair as alt
import streamlit as st

BG, PANEL, BORDER = "#0F172A", "#1E293B", "#334155"
TEXT, MUTED, ACCENT = "#E2E8F0", "#94A3B8", "#38BDF8"
GOOD, WARN, BAD, PURPLE = "#34D399", "#FBBF24", "#F87171", "#A78BFA"
TONE = {"good": GOOD, "warn": WARN, "bad": BAD, "accent": ACCENT, None: TEXT}

CSS = f"""
<style>
  .block-container {{padding-top: 2.2rem; max-width: 1400px;}}
  .intro {{color:{MUTED}; font-size:0.95rem; margin:-0.4rem 0 1.2rem;}}
  .kpis {{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:0 0 1.2rem;}}
  .kpi {{background:{PANEL}; border:1px solid {BORDER}; border-radius:10px; padding:14px 16px;}}
  .kpi .l {{color:{MUTED}; font-size:0.78rem; font-weight:600; text-transform:uppercase; letter-spacing:.04em;}}
  .kpi .v {{font-size:1.75rem; font-weight:700; margin-top:4px; font-variant-numeric:tabular-nums;}}
  .kpi .s {{color:{MUTED}; font-size:0.8rem; margin-top:2px;}}
  .flow {{display:flex; align-items:stretch; gap:8px; margin:0.4rem 0 1.4rem; flex-wrap:wrap;}}
  .stage {{flex:1 1 150px; background:{PANEL}; border:1px solid {BORDER}; border-radius:10px; padding:12px 14px; border-top:3px solid {ACCENT};}}
  .stage .t {{font-weight:700; font-size:0.95rem;}}
  .stage .n {{font-size:1.4rem; font-weight:700; margin:4px 0 2px;}}
  .stage .d {{color:{MUTED}; font-size:0.8rem; line-height:1.35;}}
  .arrow {{align-self:center; color:{MUTED}; font-size:1.3rem;}}
  .callout {{background:{PANEL}; border:1px solid {BORDER}; border-left:3px solid {WARN}; border-radius:8px; padding:10px 14px; margin:6px 0;}}
  .callout.good {{border-left-color:{GOOD};}} .callout.bad {{border-left-color:{BAD};}}
  .tag {{display:inline-block; padding:1px 8px; border-radius:10px; font-size:0.78rem; font-weight:600; border:1px solid {BORDER}; margin:0 4px 4px 0;}}
  .muted {{color:{MUTED};}}
  pre.txt {{white-space:pre-wrap; background:{PANEL}; border:1px solid {BORDER}; border-radius:8px; padding:12px; font-size:0.85rem; max-height:340px; overflow:auto;}}
</style>
"""


def setup():
    st.markdown(CSS, unsafe_allow_html=True)


def intro(text: str):
    st.markdown(f'<div class="intro">{text}</div>', unsafe_allow_html=True)


def kpis(items):
    """items: (label, value, sub, tone) tuples; tone in good / warn / bad / accent / None."""
    cards = "".join(
        f'<div class="kpi"><div class="l">{html.escape(l)}</div>'
        f'<div class="v" style="color:{TONE.get(t, TEXT)}">{html.escape(str(v))}</div>'
        f'<div class="s">{html.escape(s or "")}</div></div>' for l, v, s, t in items)
    st.markdown(f'<div class="kpis">{cards}</div>', unsafe_allow_html=True)


def callout(text: str, tone: str = "warn"):
    st.markdown(f'<div class="callout {tone}">{text}</div>', unsafe_allow_html=True)


def pct(a, b, digits=1) -> str:
    return f"{100 * a / b:.{digits}f}%" if b else "–"


def chart(c: alt.Chart, height: int = 260) -> alt.Chart:
    return (c.properties(height=height, background="transparent")
            .configure_view(strokeOpacity=0)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER, domainColor=BORDER, labelFontSize=12)
            .configure_legend(labelColor=TEXT, titleColor=MUTED, orient="bottom")
            .configure_title(color=TEXT))


def no_data(text: str):
    st.info(text, icon=":material/hourglass_empty:")
