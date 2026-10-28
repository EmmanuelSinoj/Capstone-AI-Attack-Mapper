import html

import pandas as pd
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** Search the events and follow a single alert end to end: what was sent, what the chatbot replied,
whether the attack worked, what the detector and the Mapper said, and the recommended response.

**Severity**: Critical = attack worked and was missed; High = worked and caught; Medium = failed but flagged;
Low = failed and not flagged; False alarm = harmless message flagged.

Rounds where the detector failed are left out. The sidebar time range applies. The table shows up to 2,000 events;
type an alert id to open any alert directly.
"""
ui.header("Alert explorer", "Search security events and open one to see the full chain.", ABOUT, "Investigate")

mt = data.db_mtime()
df = data.window(data.explorer_rows(mt))
if df.empty:
    ui.no_data("No live alerts in the alert store yet.")
    st.stop()

f0, f1, f2, f3, f4 = st.columns(5)
sev = f0.multiselect("Severity", ui.SEVERITY, placeholder="Any")
outcome = f1.selectbox("Outcome", ["Any", "Attack worked", "Attack failed", "Harmless message"])
det = f2.selectbox("Detector", ["Any", "Caught", "Missed"])
fams = sorted(df.loc[~df["harmless"], "family"].unique())
fam = f3.selectbox("Attack family", ["Any"] + fams)
calls = ["Any", "Classified by the Mapper"] + sorted(c for c in df["mapper_call"].unique() if c != "Not classified")
call = f4.selectbox("Mapper", calls, index=1 if (df["mapper_call"] != "Not classified").any() else 0)
q = st.text_input("Alert id (opens it directly)", placeholder="e.g. 31673")

v = df[~df["invalid_round"]]
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

table = v[["id", "ts", "severity", "run_id", "family", "probe_id", "attack_succeeded", "caught", "mapper_call", "mapper_confidence"]].copy()
table["ts"] = table["ts"].dt.strftime("%d %b %H:%M:%S")
table.loc[v["harmless"], "family"] = "harmless"
table["attack_succeeded"] = table["attack_succeeded"].map({1: "worked", 0: "failed"}).fillna("–")
table["caught"] = table["caught"].map({True: "caught", False: "missed"})
table = table.rename(columns={"id": "Alert", "ts": "Time (UTC)", "severity": "Severity", "run_id": "Round", "family": "Family", "probe_id": "Probe", "attack_succeeded": "Attack",
                              "caught": "Detector", "mapper_call": "Mapper", "mapper_confidence": "Confidence"}).sort_values("Alert", ascending=False)
sc = v["severity"].value_counts()
ui.kpis([(lvl, f"{int(sc.get(lvl, 0)):,}", "events", {"Critical": "bad", "High": "warn", "False alarm": "warn"}.get(lvl))
         for lvl in ["Critical", "High", "Medium", "Low", "False alarm"]])
with ui.panel("Events", f"{len(table):,} match · select a row to open it"):
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

a = data.alert(mt, alert_id)
if a is None:
    st.warning(f"Alert {alert_id} not found.")
    st.stop()

harmless = (a.get("probe_id") or "").startswith(data.HARMLESS)
worked = a.get("attack_succeeded")
caught = bool((a.get("category") or "").strip())
d = data.parse_detector(a.get("detector"))
tags = [f"Round {a.get('run_id') or '–'}", f"Probe {a.get('probe_id') or '–'}", f"Prompt v{a.get('system_prompt_version') or '?'}"]
lvl = df.loc[df["id"] == alert_id, "severity"]
st.markdown(f"### Alert {alert_id}  " + (ui.badge(lvl.iloc[0]) + " " if len(lvl) else "") + "".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags), unsafe_allow_html=True)

c1, c2 = st.columns([3, 2])
with c1, ui.panel("Request and reply"):
    st.markdown("**Sent to the chatbot**")
    st.code(a.get("input") or "", language=None, wrap_lines=True)
    st.markdown("**Chatbot reply**")
    st.code(a.get("output") or "", language=None, wrap_lines=True)
with c2, ui.panel("Verdicts"):
    if harmless:
        ui.callout("Harmless customer message: " + ("<b>flagged by the detector (false alarm)</b>" if caught else "not flagged (correct)"),
                   "bad" if caught else "good")
    else:
        ui.callout("Attack " + ("<b>worked</b>: the chatbot complied" if worked == 1 else "<b>failed</b>: the chatbot resisted" if worked == 0
                                else "not graded yet"), "bad" if worked == 1 else "good")
        ui.callout("Detector: " + ("<b>caught</b>" if caught else "<b>missed</b>") +
                   f" · pattern rule: {d['heuristic_rule'] or 'none'} · judge model: {d['judge_label'] or '–'}",
                   "good" if caught else ("bad" if worked == 1 else "warn"))
    mp = a.get("mapper")
    st.markdown("**Mapper classification**")
    if not mp:
        st.caption("Not classified by the Mapper.")
    elif not mp.get("valid_json"):
        ui.callout(f"Classification failed: {html.escape(str(mp.get('error') or 'no valid reply'))}", "warn")
    else:
        cat = mp.get("predicted_category") or "No attack (out of scope)"
        conf = mp.get("confidence")
        sev = None
        try:
            from mapper.severity import severity_from_fields
            sev = severity_from_fields(mp.get("predicted_category"), mp.get("sub_cluster"), mp.get("adversarial"), conf,
                                       in_scope=bool(mp.get("in_scope"))).get("severity")
        except Exception:  # noqa: BLE001
            pass
        gate = mp.get("predicted_category") == "B" and conf is not None and conf >= data.GATE_THRESHOLD
        ui.kpis([("Category", cat, mp.get("sub_cluster") or "", "accent"),
                 ("Confidence", f"{conf:.2f}" if conf is not None else "–", "passes the hardening gate" if gate else "below the gate or not B",
                  "good" if gate else None),
                 ("Severity", sev or "–", mp.get("lifecycle_phase") or "", "bad" if sev in ("High", "Critical") else None)])
        try:
            from mapper import framework_reference as fw
        except ImportError:
            fw = None
        for label, key, col in (("ATLAS", "atlas", "atlas_technique"), ("OWASP LLM", "owasp_llm", "owasp_category"),
                                ("ATT&CK", "attack", "attck_technique")):
            lst = data.ids(mp.get(col))
            if not lst:
                continue
            parts = []
            for i in lst:
                r = fw.lookup(key, i) if fw else None
                name = f" {html.escape(r.name)}" if r and r.resolved and r.name else ""
                parts.append(f'<a href="{r.url}" target="_blank">{html.escape(i)}</a>{name}' if r and r.url else html.escape(i) + name)
            st.markdown(f"<span class='muted'>{label}:</span> " + " · ".join(parts), unsafe_allow_html=True)
        if mp.get("rationale"):
            st.markdown(f'<div class="callout good" style="border-left-color:{ui.ACCENT}"><b>Rationale.</b> {html.escape(mp["rationale"])}</div>',
                        unsafe_allow_html=True)
        st.caption(f"Source: {mp.get('source')}")

with ui.panel("Response"):
    pb = a.get("playbook")
    if pb:
        import json
        try:
            p = json.loads(pb)
        except ValueError:
            p = {"summary": pb}
        st.markdown(f"{html.escape(str(p.get('summary', '')))}")
        for i, stp in enumerate(p.get("containment_steps") or [], 1):
            st.markdown(f"{i}. {stp}")
        if p.get("recommended_control"):
            st.caption(f"Recommended control: {p['recommended_control']}")
    else:
        st.caption("No playbook for this alert yet.")
    st.caption("Hardening applied to this alert's attack: " + ("yes" if a.get("hardening_applied") else "no"))
