import pandas as pd
import streamlit as st

import data
import ui

st.title("Auto-hardening")
ui.intro("When an attack works and the Mapper confirms it, a countermeasure rule for that attack family is added to the "
         "chatbot's system prompt as a new version. A new version is switched on only if fresh, unseen attacks drop clearly, "
         "every attack family is covered, and normal customer messages are not refused more often.")

st.markdown(f"""
1. **Gate:** the attack worked, its family is known, and the Mapper calls it B with confidence ≥ {data.GATE_THRESHOLD}.
2. **Harden:** one fixed rule per attack family is appended; the result is saved as a new, inactive prompt version.
3. **Verify:** the original and hardened prompts face the same fresh attacks (prompts present in both rounds) and the same 1,380 harmless messages.
4. **Decide:** ACCEPT only if attack success drops with non-overlapping 95% intervals, no family gets worse, and harmless refusals rise by at most 2 points (upper bound). A person then switches the version on, with rollback.
""")

mt = data.db_mtime()
versions = data.prompt_versions()
history = data.hardening_history()
decisions = [h for h in history if h.get("decision")]
util = data.utility_checks()
ui.kpis([
    ("Prompt versions", f"{len(versions)}", f"latest v{versions[-1]['version']}" if versions else "none found", None),
    ("Rules in latest version", f"{len(versions[-1]['rules'])}" if versions else "–", "added countermeasure rules", None),
    ("Latest decision", decisions[-1]["decision"] if decisions else "Pending",
     f"v{decisions[-1].get('candidate')} vs v{decisions[-1].get('parent')}" if decisions else "after the fresh attack rounds",
     {"ACCEPT": "good", "REJECT": "bad"}.get(decisions[-1]["decision"], "warn") if decisions else "warn"),
    ("Harmless refusals", " → ".join(f"{v}" for k, v in util[-1].items() if k.startswith("v")) if util else "–",
     f"of {util[-1]['messages']:,} messages, latest check" if util else "no check found", None),
])

st.subheader("Attack success by prompt version")
df = data.live_rows(mt)
g = df[(df["kind"] == "garak") & ~df["harmless"] & df["attack_succeeded"].notna()] if not df.empty else df
if g.empty:
    ui.no_data("No graded Garak rounds yet.")
else:
    t = (g.groupby(["version", "family"]).agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index())
    t["rate"] = t["worked"] / t["requests"]
    piv = t.pivot(index="family", columns="version", values="rate")
    piv.columns = [f"v{int(c)}" for c in piv.columns]
    st.dataframe(piv.reset_index().rename(columns={"family": "Attack family"}), hide_index=True, width="stretch",
                 column_config={c: st.column_config.NumberColumn(format="percent") for c in piv.columns})
    st.caption("Share of Garak requests that worked, per prompt version. Rounds sample different prompts, so the fair comparison "
               "is the decision below, which uses only prompts sent to both versions.")

st.subheader("Decisions")
if not decisions:
    ui.no_data("No accept/reject decision recorded yet (auto_hardening/history.jsonl).")
else:
    mark = {True: "pass", False: "fail", None: "not run"}
    rows = [{"Verdict": d["decision"], "Candidate": f"v{d.get('candidate')}", "Parent": f"v{d.get('parent')}",
             **{k.replace("_", " ").capitalize(): mark.get(v, v) for k, v in (d.get("checks") or {}).items()}}
            for d in reversed(decisions)]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

st.subheader("System prompt versions")
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

if util:
    st.subheader("Harmless-message checks")
    st.dataframe(pd.DataFrame(util), hide_index=True, width="stretch")
