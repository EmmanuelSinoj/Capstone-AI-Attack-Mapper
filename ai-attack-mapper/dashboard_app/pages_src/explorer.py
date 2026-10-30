import pandas as pd
import streamlit as st

import alert_view
import data
import ui

ABOUT = """
**What this page shows.** Search the events and follow a single alert end to end: what was sent, what the chatbot replied,
whether the attack worked, what the detector and the Mapper said, and the recommended response.

**Severity**: Critical = attack worked and was missed; High = worked and caught; Medium = failed but flagged;
Low = failed and not flagged; False alarm = harmless message flagged.

**Technique** filters on the framework IDs the Mapper assigned (ATLAS, OWASP LLM Top 10, ATT&CK); the same view is
reachable from Classification, Browse by technique.

**Source** switches between live alerts (attack and harmless rounds) and the synthetic alerts with their answer key.
**Rounds** filters on whole sessions (all tools run together) or individual rounds. The Mapper column comes from the
Mapper run chosen in the sidebar; alerts that run did not cover show "Not classified".

Rounds where the detector failed are left out. The sidebar time range and prompt-version filter apply to live alerts. The table shows up to 2,000 events;
type an alert id to open any alert directly.
"""
ui.header("Alert explorer", "Search events and trace each alert from request to response.", ABOUT, "Investigate")

mt = data.db_mtime()
run = data.selected_run()
scope_slot = st.empty()
allrows = data.explorer_rows(mt, run)
if allrows.empty:
    ui.no_data("No alerts in the alert store yet.")
    st.stop()
df = pd.concat([data.window(allrows[allrows["source"] == "live"]), allrows[allrows["source"] == "synthetic"]], ignore_index=True)

h0, h1, h2 = st.columns([1, 2.6, 2.4], gap="small")
source = h0.selectbox("Source", ["Live", "Synthetic", "Both"])
live_df = df[df["source"] == "live"]
sessions = sorted(live_df["session"].dropna().unique(), reverse=True)
rounds = sorted(live_df["run_id"].dropna().unique(), reverse=True)
round_opts = [f"session:{x}" for x in sessions] + rounds
rsel = h1.multiselect("Rounds", round_opts, placeholder="All rounds", disabled=source == "Synthetic",
                      format_func=lambda r: f"Session {r[8:]} (all tools)" if r.startswith("session:") else r)

f0, f1, f2, f3, f4 = st.columns([1.1, 1.2, 1, 1.15, 1.5], gap="small")
sev = f0.multiselect("Severity", ui.SEVERITY, placeholder="Any")
outcome = f1.selectbox("Outcome", ["Any", "Attack worked", "Attack failed", "Harmless message"])
det = f2.selectbox("Detector", ["Any", "Caught", "Missed"])
fams = sorted(df.loc[~df["harmless"], "family"].unique())
fam = f3.selectbox("Attack family", ["Any"] + fams)
calls = ["Any", "Classified by the Mapper"] + sorted(c for c in df["mapper_call"].unique() if c != "Not classified")
call = f4.selectbox("Mapper", calls, index=1 if (df["mapper_call"] != "Not classified").any() else 0)
FW = (("ATLAS", "atlas", "mapper_atlas"), ("OWASP LLM", "owasp_llm", "mapper_owasp"), ("ATT&CK", "attack", "mapper_attck"))
techs = {}
for _, key, col in FW:
    for i in sorted({t for v in df[col].dropna() for t in data.ids(v)}):
        techs[i] = alert_view.technique_label(key, i)
tech = h2.multiselect("Technique", list(techs), format_func=lambda i: techs[i], placeholder="Any")
q = st.text_input("Open alert by ID", placeholder="e.g. 31673")

v = df[~df["invalid_round"]]
if source != "Both":
    v = v[v["source"] == source.lower()]
if rsel and source != "Synthetic":
    want_s = {r[8:] for r in rsel if r.startswith("session:")}
    want_r = {r for r in rsel if not r.startswith("session:")}
    v = v[(v["source"] == "synthetic") | v["session"].isin(want_s) | v["run_id"].isin(want_r)]
if sev:
    v = v[v["severity"].isin(sev)]
if outcome == "Attack worked":
    v = v[~v["harmless"] & (v["attack_succeeded"] == 1)]
elif outcome == "Attack failed":
    v = v[~v["harmless"] & (v["attack_succeeded"] == 0)]
elif outcome == "Harmless message":
    v = v[v["harmless"]]
if det != "Any":
    v = v[v["caught"] == (det == "Caught")]
if fam != "Any":
    v = v[v["family"] == fam]
if call == "Classified by the Mapper":
    v = v[v["mapper_call"] != "Not classified"]
elif call != "Any":
    v = v[v["mapper_call"] == call]
if tech:
    want = set(tech)
    v = v[v.apply(lambda r: bool(want & {t for _, _, col in FW for t in data.ids(r[col])}), axis=1)]

if "truth" not in v.columns:
    v = v.assign(truth=None)
table = v[["id", "ts", "severity", "run_id", "family", "probe_id", "attack_succeeded", "caught", "truth", "mapper_call", "mapper_confidence"]].copy()
syn_mask = v["source"] == "synthetic"
table["ts"] = table["ts"].dt.strftime("%d %b %H:%M:%S")
table.loc[v["harmless"], "family"] = "harmless"
table["attack_succeeded"] = table["attack_succeeded"].map({1: "worked", 0: "failed"}).fillna("–")
table["caught"] = table["caught"].map({True: "caught", False: "missed"})
table.loc[syn_mask, ["caught", "run_id", "probe_id"]] = "–"
table["truth"] = table["truth"].fillna("–")
table = table.rename(columns={"id": "Alert", "ts": "Time (UTC)", "severity": "Severity", "run_id": "Round", "family": "Family", "probe_id": "Probe", "attack_succeeded": "Attack",
                              "caught": "Detector", "truth": "Answer key", "mapper_call": "Mapper", "mapper_confidence": "Confidence"}).sort_values("Alert", ascending=False)
if source == "Live":
    table = table.drop(columns=["Answer key"])
elif source == "Synthetic":
    table = table.drop(columns=["Time (UTC)", "Severity", "Round", "Family", "Probe", "Attack", "Detector"])
lv_n, sy_n = int((v["source"] == "live").sum()), int(syn_mask.sum())
with scope_slot.container():
    ui.scope(f"{lv_n:,} live alerts" if source != "Synthetic" else "", f"{sy_n:,} synthetic alerts" if source != "Live" else "",
             data.scope_versions(v[v["source"] == "live"]) if source != "Synthetic" else "",
             data.scope_dates() if source != "Synthetic" else "", f"Mapper run {run}" if run else "latest Mapper result per alert")
if source == "Synthetic":
    sv = v[v["mapper_call"] != "Not classified"]
    ok = int((sv["mapper_call"] == sv["truth"]).sum())
    ui.kpis([("Synthetic alerts", f"{sy_n}", "with an answer key", None),
             ("Classified in this run", f"{len(sv)}", f"Mapper run {run}" if run else "latest result", "accent"),
             ("Match the answer key", ui.pct(ok, len(sv)), f"{ok} of {len(sv)}", "good"),
             ("Do not match", f"{len(sv) - ok}", "open them below", "bad" if len(sv) - ok else "good")])
else:
    sc = v["severity"].value_counts()
    ui.kpis([(lvl, f"{int(sc.get(lvl, 0)):,}", "events", {"Critical": "bad", "High": "warn", "False alarm": "warn"}.get(lvl))
             for lvl in ["Critical", "High", "Medium", "Low", "False alarm"]])
with ui.panel("Events", f"{len(table):,} matching events · select a row to inspect"):
    ev = st.dataframe(ui.sev_style(table.head(2000).reset_index(drop=True)), hide_index=True, width="stretch", height=320,
                      on_select="rerun", selection_mode="single-row",
                      column_config={"Confidence": st.column_config.NumberColumn(format="%.2f")})

alert_id = None
if q.strip().isdigit():
    alert_id = int(q.strip())
elif ev and ev.selection and ev.selection.rows:
    alert_id = int(table.head(2000).iloc[ev.selection.rows[0]]["Alert"])
if alert_id is None:
    st.stop()

lvl = df.loc[(df["id"] == alert_id) & (df["source"] == "live"), "severity"]
alert_view.render(mt, alert_id, lvl.iloc[0] if len(lvl) else None, run_id=run)
