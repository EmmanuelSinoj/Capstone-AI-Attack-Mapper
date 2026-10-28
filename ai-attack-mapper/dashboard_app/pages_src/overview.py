import pandas as pd
import streamlit as st

import data
import ui

st.title("Overview")
ui.intro("The state of the whole pipeline in one place: what was thrown at the chatbot, what got through, "
         "what the detector and the Mapper caught, and what still needs attention.")

mt = data.db_mtime()
df = data.live_rows(mt)
if df.empty:
    ui.no_data("No live data in the alert store yet.")
    st.stop()

valid = df[df["kind"].isin(["garak", "pyrit", "benign"]) & ~df["invalid_round"]]
s = data.detection_summary(valid)
latest = pd.to_datetime(df["timestamp"].max(), utc=True, format="ISO8601")
st.caption(f"Valid attack and harmless rounds only (rounds where the detector failed are left out). "
           f"Latest activity: {latest:%d %b %Y, %H:%M} UTC.")

runs = data.mapper_runs(mt)
mres = data.mapper_results(mt, runs.iloc[0]["run_id"]) if not runs.empty else pd.DataFrame()
atk = mres[~mres["harmless"]] if not mres.empty else mres
hl = mres[mres["harmless"]] if not mres.empty else mres
mapper_b = int((atk["mapper_call"] == "B").sum()) if not mres.empty else 0
mapper_harm_b = int((hl["mapper_call"] == "B").sum()) if not mres.empty else 0

versions = data.prompt_versions()
decisions = [h for h in data.hardening_history() if h.get("decision")]
latest = data.latest_fresh_decision(decisions)
missed = s["worked"] - s["worked_caught"]

stages = [
    ("Attack", f"{s['attacks_sent']:,}", f"attacks sent by Garak and PyRIT; {s['worked']:,} worked ({ui.pct(s['worked'], s['worked'] + s['failed'])})"),
    ("Detect", ui.pct(s["worked_caught"], s["worked"]), f"of successful attacks caught by the detector; {missed} missed"),
    ("Classify", ui.pct(mapper_b, len(atk)) if len(atk) else "–",
     f"of {len(atk)} sampled live attacks confirmed as prompt injection (B) by the Mapper"),
    ("Harden", f"v{versions[-1]['version']}" if versions else "–",
     (f"latest prompt version; fresh-round decision: {latest['decision']}" if latest else "latest prompt version; fresh-round decision pending")),
    ("Respond", f"{len(data.playbooks(mt))}", "alerts with a defense playbook"),
]
flow = '<span class="arrow">→</span>'.join(
    f'<div class="stage"><div class="t">{t}</div><div class="n">{n}</div><div class="d">{d}</div></div>' for t, n, d in stages)
st.markdown(f'<div class="flow">{flow}</div>', unsafe_allow_html=True)

ui.kpis([
    ("Missed attacks", f"{missed:,}", "succeeded and were not flagged", "bad" if missed else "good"),
    ("False alarms", ui.pct(s["harmless_flagged"], s["harmless"]), f"{s['harmless_flagged']} of {s['harmless']:,} harmless messages flagged",
     "good" if s["harmless"] and s["harmless_flagged"] / s["harmless"] < 0.01 else "warn"),
    ("Mapper false positives", f"{mapper_harm_b} / {len(hl)}", "harmless messages the Mapper called an attack (B)", "good" if mapper_harm_b == 0 else "bad"),
    ("Mapper accuracy (held-out)", "91.7%", "22 of 24 unseen synthetic alerts, all categories", "accent"),
])

st.subheader("Needs attention")
if missed:
    ui.callout(f"<b>{missed} successful attacks were not detected.</b> Review them on the Detection page "
               "(table <i>Successful attacks the detector missed</i>).", "bad")
if not mres.empty:
    enc = atk[atk["family"] == "encoding"]
    if len(enc):
        ui.callout(f"<b>Encoded attacks are the Mapper's weak spot:</b> {int((enc['mapper_call'] == 'B').sum())} of {len(enc)} called B; "
                   "encoded text often reads as meaningless.", "warn")
if not latest:
    ui.callout("<b>Auto-hardening has no decision on fresh rounds yet.</b> Fresh rounds on the original and hardened prompts are "
               "compared on the Auto-hardening page once they are graded"
               + (" (earlier replay tests on seen prompts are listed there)." if decisions else "."), "warn")
else:
    d = latest
    t = data.decision_test(d)
    ui.callout(f"<b>Latest hardening decision on fresh rounds: {d['decision']}</b> for prompt v{d.get('candidate')} against "
               f"v{d.get('parent')} (target families: {t['targets']}).", "good" if d["decision"] == "ACCEPT" else "warn")
if not len(data.playbooks(mt)):
    ui.callout("<b>No defense playbooks yet.</b> They appear once playbook generation has run.", "warn")
