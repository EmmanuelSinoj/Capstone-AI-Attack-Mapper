import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

ABOUT = f"""
**What this page shows.** The automated response to confirmed live prompt-injection attacks: countermeasure rules added to
the chatbot's system prompt as new versions, and the accept or reject decision for each version.

1. **Gate:** the attack worked, its family is known, and (optionally) the Mapper calls it B with confidence ≥ {data.GATE_THRESHOLD}.
2. **Harden:** one fixed rule per attack family is appended; the result is saved as a new, inactive prompt version.
3. **Verify:** the original and hardened prompts face the same fresh attacks (prompts present in both rounds) and the same
   1,380 harmless messages.
4. **Decide:** ACCEPT only if attack success drops with non-overlapping 95% intervals in each family the new version has a
   rule for (`decide.py --target-families`), no other family gets worse, and harmless refusals rise by at most 2 points
   (upper bound). Families without a rule are only checked for regression. A person then switches the version on, with rollback.

**Test types.** Replay tests use the 60 original attacks and their paraphrases, which the hardening was built from, so they
only show consistency. The decision that counts is the one on fresh rounds (prompts not seen during hardening).

**Attack success by prompt version** pools whole rounds, which sample different prompts; the fair comparison is the decision,
which uses only prompts sent to both versions.

**Reading the results.** A version is only worth activating after ACCEPT on fresh rounds; replay tests show consistency only.
The number of rules each version adds is shown on its entry under System prompt versions.

**Details** holds attack success by prompt version.
"""

ui.header("Auto-hardening", "Prompt versions, attack success and accept/reject decisions.", ABOUT, "Respond")

mt = data.db_mtime()
versions = data.prompt_versions()
history = data.hardening_history()
decisions = [h for h in history if h.get("decision")]
latest = data.latest_fresh_decision(decisions)
util = data.utility_checks()
active = data.active_prompt_version()
ui.scope(f"{len(versions)} prompt versions", f"{len(decisions)} recorded decisions", "hardening history and stored prompt versions")
ui.kpis([
    ("Prompt versions", f"{len(versions)}", (f"latest v{versions[-1]['version']}" if versions else "none found")
     + (f", active v{active}" if active is not None else ", active unknown (testbed not reachable)"), "accent"),
    ("Latest decision (fresh rounds)", latest["decision"] if latest else "Pending",
     f"v{latest.get('candidate')} vs v{latest.get('parent')}" if latest else "after the fresh attack rounds",
     {"ACCEPT": "good", "REJECT": "bad"}.get(latest["decision"], "warn") if latest else "warn"),
    ("Decisions recorded", f"{len(decisions)}", f"{sum(not data.decision_test(d)['fresh'] for d in decisions)} replay tests on seen prompts", None),
    ("Harmless refusals", " → ".join(f"{v}" for k, v in util[-1].items() if k.startswith("v")) if util else "–",
     f"of {util[-1]['messages']:,} messages, latest check" if util else "no check found", None),
])

with ui.panel("Decisions", "auto_hardening/history.jsonl"):
    if not decisions:
        ui.no_data("No accept/reject decision recorded yet.")
    else:
        mark = {True: "pass", False: "fail", None: "not run"}
        rows = [{"Verdict": d["decision"], "Candidate": f"v{d.get('candidate')}", "Parent": f"v{d.get('parent')}",
                 "Test": data.decision_test(d)["kind"], "Variants": data.decision_test(d)["variants"],
                 "Target families": data.decision_test(d)["targets"],
                 **{k.replace("_", " ").capitalize(): mark.get(v, v) for k, v in (d.get("checks") or {}).items()}}
                for d in reversed(decisions)]
        tbl = pd.DataFrame(rows)

        def color(v):
            return {"ACCEPT": f"color:{ui.GOOD}; font-weight:700", "REJECT": f"color:{ui.BAD}; font-weight:700",
                    "INCONCLUSIVE": f"color:{ui.WARN}; font-weight:700", "fail": f"color:{ui.BAD}",
                    "Replay test (seen prompts)": f"color:{ui.MUTED}"}.get(v, "")
        st.dataframe(tbl.style.map(color), hide_index=True, width="stretch")

with ui.panel("System prompt versions", f"{len(versions)} versions"):
    if not versions:
        ui.no_data("No prompt versions found (testbed/prompts).")
    for v in reversed(versions):
        with st.expander(f"v{v['version']} · {len(v['rules'])} added rule(s)", expanded=v is versions[-1]):
            if v["rules"]:
                st.markdown("**Added rules**")
                for r in v["rules"]:
                    st.markdown(f"- {r.split('.', 1)[1].strip() if '.' in r else r}")
            st.markdown("**Full prompt**")
            st.code(v["text"], language=None, wrap_lines=True)

with ui.details():
    df = data.live_rows(mt)
    g = df[(df["kind"] == "garak") & ~df["harmless"] & df["attack_succeeded"].notna()] if not df.empty else df
    with ui.panel("Attack success by prompt version", "Garak rounds, all prompts"):
        if g.empty:
            ui.no_data("No graded Garak rounds yet.")
        else:
            t = g.groupby(["version", "family"]).agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index()
            t["rate"] = t["worked"] / t["requests"]
            t["Version"] = "v" + t["version"].astype(int).astype(str)
            bars = alt.Chart(t).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
                x=alt.X("family:N", title=None, axis=alt.Axis(labelAngle=0)),
                xOffset="Version:N",
                y=alt.Y("rate:Q", title="Share that worked", axis=alt.Axis(format="%")),
                color=alt.Color("Version:N", title="Prompt version", scale=alt.Scale(range=[ui.ACCENT, ui.PURPLE, ui.GOOD, ui.ORANGE, ui.WARN, ui.BAD,
                                                                          "#8CA9FF", "#73DFE4", "#E6A8DB", ui.MUTED])),
                tooltip=[alt.Tooltip("Version:N", title="Prompt version"), alt.Tooltip("family:N", title="Family"),
                         alt.Tooltip("requests:Q", title="Requests", format=","), alt.Tooltip("rate:Q", title="Worked", format=".1%")])
            st.altair_chart(ui.chart(bars, 240), width="stretch")
