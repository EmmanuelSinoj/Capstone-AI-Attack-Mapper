"""
mapper/build_framework_reference.py

Rebuilds mapper/data/framework_reference_data.json from the official
upstream sources. Run this again whenever MITRE ATT&CK/ATLAS publish a new
version, or the OWASP Top 10 for LLM Applications gets a new edition --
the data file itself is checked into the repo and used at runtime, so
classification never depends on live network access; this script is only
for refreshing that snapshot.

Sources:
  - ATT&CK Enterprise (STIX bundle, official):
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
  - ATLAS (official), current v6 format:
    https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml
    (a pointer to the dated release file, e.g. ATLAS-2026.09.yaml). Do NOT use
    the old dist/ATLAS.yaml -- MITRE froze it at format 5.6.0 and it is
    missing newer techniques (AML.T0110.001, AML.T0115.x, AML.T0130,
    AML.T0132, ...) that the prompt and Shadi's answer key (data v2026.09) use.
  - OWASP Top 10 for LLM Applications: no machine-readable export exists,
    so the OWASP_LLM_TOP_10 table below is hand-maintained against the
    *2026* edition specifically (confirmed against the project's own
    Taxonomy & Framework Reference Tables doc and prompt.py, which both
    already use the 2026 numbering -- LLM03 is Excessive Agency, LLM04 is
    Supply Chain, etc. This is NOT the 2023/2025 numbering, where those
    same names sit at different IDs -- don't "fix" this table against an
    older OWASP list without checking which edition prompt.py is using
    first).

Usage (from the repo root, needs `requests` and `pyyaml`):
    python3 -m mapper.build_framework_reference
"""

import json
import os

import requests
import yaml

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ATLAS_BASE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/"
ATLAS_LATEST = "ATLAS-latest.yaml"
OUT_PATH = os.path.join(os.path.dirname(__file__), "data", "framework_reference_data.json")

# ATLAS IDs retired in 2026 and what replaced them (the v6 export has no revoked-by
# relationships, so this is kept by hand; same mapping the prompt states).
ATLAS_RETIRED = {"AML.T0019": "AML.T0115.000", "AML.T0058": "AML.T0115.001", "AML.T0104": "AML.T0115.002"}

OWASP_LLM_TOP_10 = {
    "LLM01": {"name": "Prompt Injection", "description": "Untrusted input can override the model's intended instructions or behavior."},
    "LLM02": {"name": "Sensitive Information Disclosure", "description": "The model or its pipeline can leak private, memorized, or retrieved data."},
    "LLM03": {"name": "Excessive Agency", "description": "An agent given more autonomy or tool access than it needs can be abused to take unauthorized actions."},
    "LLM04": {"name": "Supply Chain", "description": "Compromised base models, packages, or registries in the LLM supply chain introduce risk."},
    "LLM05": {"name": "Data and Model Poisoning", "description": "Tampered training, fine-tuning, or embedding data can implant harmful model behavior."},
    "LLM06": {"name": "Unbounded Consumption", "description": "Uncapped resource use lets an attacker drive up cost, latency, or exhaust shared capacity."},
    "LLM07": {"name": "Misinformation", "description": "Confidently wrong model output can lead to flawed downstream decisions or actions."},
    "LLM08": {"name": "Hidden Context Exposure", "description": "Non-user-facing context -- system prompts, policy text, tool schemas -- can be exposed to an attacker."},
    "LLM09": {"name": "Vector and Embedding Weaknesses", "description": "Weaknesses in embeddings or vector stores can be exploited to poison or leak retrieval results."},
    "LLM10": {"name": "Improper Output Handling", "description": "Insufficiently validated model output passed downstream can enable injection or execution attacks."},
}
for _id in OWASP_LLM_TOP_10:
    OWASP_LLM_TOP_10[_id]["url"] = "https://genai.owasp.org/llm-top-10/"


def _fetch_attack() -> dict:
    """
    Returns (id_table, matrix) where id_table is the flat id->name/description/
    url lookup (unchanged from before), and matrix is {"tactics": [...ordered
    column list...], "technique_tactics": {technique_id: [tactic_id, ...]}} --
    added for dashboard_app.py's visual matrix (mapper/matrix_data.py), which
    needs to group techniques under tactic columns the same way
    attack.mitre.org's own matrix page does.

    Column order comes from the x-mitre-matrix object's tactic_refs (the
    actual displayed order on the real site, not alphabetical). A
    technique's tactic membership comes from its kill_chain_phases
    (phase_name matches a tactic's x_mitre_shortname) -- a technique can
    legitimately appear in more than one tactic column, same as the real
    matrix.
    """
    data = requests.get(ATTACK_URL, timeout=120).json()
    objs = data["objects"]

    id_table = {}
    tactics_by_stixid = {}
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] not in ("attack-pattern", "x-mitre-tactic"):
            continue
        ext_id, url = None, None
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id, url = ref["external_id"], ref["url"]
                break
        if not ext_id:
            continue
        desc = (o.get("description") or "").split("\n")[0][:300]
        id_table[ext_id] = {"name": o["name"], "description": desc, "url": url}
        if o["type"] == "x-mitre-tactic":
            tactics_by_stixid[o["id"]] = {"id": ext_id, "name": o["name"], "shortname": o["x_mitre_shortname"]}

    matrix_obj = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics_ordered = [tactics_by_stixid[tid] for tid in matrix_obj["tactic_refs"] if tid in tactics_by_stixid]
    shortname_to_tacticid = {t["shortname"]: t["id"] for t in tactics_ordered}
    # Drop "shortname", it was only needed to build the lookup above.
    tactics_ordered = [{"id": t["id"], "name": t["name"]} for t in tactics_ordered]

    technique_tactics = {}
    for o in objs:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext_id = next((r["external_id"] for r in o.get("external_references", [])
                       if r.get("source_name") == "mitre-attack"), None)
        if not ext_id:
            continue
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        technique_tactics[ext_id] = [shortname_to_tacticid[p] for p in phases if p in shortname_to_tacticid]

    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), None)

    # Revoked techniques -> their replacement (e.g. T1656 Impersonation -> T1684.001 in v20,
    # T1562.001 -> T1685). Labels written against an older ATT&CK release (Shadi's key uses a
    # few) still score correctly because scoring maps both sides through this table.
    stix_to_ext = {}
    for o in objs:
        if o["type"] == "attack-pattern":
            ext = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if ext:
                stix_to_ext[o["id"]] = ext
    revoked = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            old, new = stix_to_ext.get(o["source_ref"]), stix_to_ext.get(o["target_ref"])
            if old and new and old != new:
                revoked[old] = new
    return id_table, {"tactics": tactics_ordered, "technique_tactics": technique_tactics,
                      "version": version, "revoked": revoked}


def _fetch_atlas() -> dict:
    """
    Same split as _fetch_attack(): (id_table, matrix), from the v6 format.

    v6 layout: `tactics` and `techniques` are dicts keyed by id; tactic
    membership and column order live in `relationships`:
      - relationships[<technique id>]["achieves"] -> the tactic(s) it sits under
      - relationships["ATLAS-matrix"]["sequences"] -> tactic column order ("position")
    Every technique, sub-techniques included, has its own "achieves" entry.
    """
    latest = requests.get(ATLAS_BASE_URL + ATLAS_LATEST, timeout=60).text
    if len(latest) < 200 and latest.strip().endswith(".yaml"):
        # ATLAS-latest.yaml is a symlink in the repo; over raw.githubusercontent it
        # comes back as the target's file name, so follow it once.
        latest = requests.get(ATLAS_BASE_URL + latest.strip(), timeout=60).text
    data = yaml.safe_load(latest)
    rels = data["relationships"]

    id_table = {}
    for tid, t in data["techniques"].items():
        desc = (t.get("description") or "").split("\n")[0][:300]
        id_table[tid] = {"name": t["name"], "description": desc, "url": f"https://atlas.mitre.org/techniques/{tid}"}
    for tid, t in data["tactics"].items():
        id_table[tid] = {"name": t["name"], "description": (t.get("description") or "").split("\n")[0][:300],
                         "url": f"https://atlas.mitre.org/tactics/{tid}"}

    order = sorted(rels["ATLAS-matrix"]["sequences"], key=lambda r: r["position"])
    tactics_ordered = [{"id": r["target"], "name": data["tactics"][r["target"]]["name"]} for r in order]
    technique_tactics = {
        tid: [r["target"] for r in rels.get(tid, {}).get("achieves", [])]
        for tid in data["techniques"]
    }
    version = data.get("collection", {}).get("version")
    return id_table, {"tactics": tactics_ordered, "technique_tactics": technique_tactics, "version": version}


def main():
    attack_ids, attack_matrix = _fetch_attack()
    atlas_ids, atlas_matrix = _fetch_atlas()
    out = {
        "attack": attack_ids,
        "atlas": atlas_ids,
        "owasp_llm": OWASP_LLM_TOP_10,
        "attack_tactics": attack_matrix["tactics"],
        "attack_technique_tactics": attack_matrix["technique_tactics"],
        "atlas_tactics": atlas_matrix["tactics"],
        "atlas_technique_tactics": atlas_matrix["technique_tactics"],
        "attack_revoked": attack_matrix["revoked"],
        "atlas_revoked": ATLAS_RETIRED,
        "versions": {"attack": attack_matrix.get("version"), "atlas": atlas_matrix.get("version"),
                     "owasp_llm": "2026"},
    }
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(
        f"Wrote {OUT_PATH}: attack={len(out['attack'])} atlas={len(out['atlas'])} "
        f"owasp_llm={len(out['owasp_llm'])} attack_tactics={len(out['attack_tactics'])} "
        f"atlas_tactics={len(out['atlas_tactics'])}"
    )


if __name__ == "__main__":
    main()
