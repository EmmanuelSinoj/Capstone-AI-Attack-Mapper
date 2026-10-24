#!/usr/bin/env python3
"""gate.py -- which alerts qualify for hardening (Auto-Hardening proposal, section 3.1).

Decision agreed with Emmanuel: an alert qualifies when
    attack_succeeded is true  AND  its attack family is known.
The detector flag is RECORDED and reported, but NOT required (an attack that worked and was missed by the detector is the
most valuable one to harden against).

  python gate.py --db ..\\alert_store\\alerts.db                       # summary per family, nothing written
  python gate.py --db ..\\alert_store\\alerts.db --version 5           # only attacks that ran against prompt version 5
  python gate.py --db ..\\alert_store\\alerts.db --run-like "%20261012_v6-1%" --out eligible.jsonl
  python gate.py --db ..\\alert_store\\alerts.db --require-mapper --min-confidence 0.8   # option 1: Mapper must also say B

Mapper condition (OPTIONAL, off by default): with --require-mapper an alert must ALSO have predicted_category = B and
classification_confidence >= --min-confidence. attack_succeeded stays the proof the attack worked, so a Mapper error can
only SKIP an alert, never harden against something harmless. Without the flag the gate is unchanged, but the Mapper's call
is still read (if the columns exist), logged in the --out file, and the summary shows how many eligible alerts the Mapper
would have dropped, so the cost of switching it on is visible before it is switched on.

Read-only: the database is opened with mode=ro and nothing is changed. attack_succeeded is only filled in after a round,
by annotate_run.py, so unannotated alerts are skipped (the summary says how many).

ASSUMPTIONS to verify with the dry run before relying on it (this script was tested on a synthetic database with the
column names below, NOT yet on the real alerts.db):
  * the alerts table is called 'alerts' and has: attack_succeeded, probe_id, run_id, input, system_prompt_version, category
  * family = probe_id (for example 'promptinject.HijackHateHumans'); a succeeded attack with NO probe_id gets the 'default' clause;
    a probe_id that matches no clauses.json key (for example pyrit.*, replay.*, utility.*) is skipped and counted
  * 'flagged by the detector' = the category column is non-empty ('B' when flagged, NULL otherwise); the detector
    column only holds the detector's name
  * Mapper columns (only read if present): predicted_category, classification_confidence on the alerts table
v2 (Emmanuel, Oct 24): the Mapper's mapping travels with each eligible alert. All new options are off by default, so
the gate above is unchanged unless they are given.
  --mapper-run RUN_ID   read the Mapper's call from mapper_results (that run, valid JSON, highest repeat) instead of the
                        alerts columns. The live classification sample writes only to mapper_results.
  --mapper-family       also accept a succeeded attack whose probe family has no clause (for example pyrit.*) when the
                        Mapper calls it B with enough confidence AND its ATLAS/OWASP IDs select a clause in technique_map.json.
  The --out file also carries mapper_atlas, mapper_owasp, probe_clause and mapper_clause, and the summary shows how often
  the probe family and the Mapper's mapping pick the same clause. That is the precondition check for harden.py --select mapper.
clauses.json, technique_map.json and clause_select.py must sit in the same folder as this script. Stdlib only."""
import argparse, collections, json, pathlib, sqlite3, sys

HERE = pathlib.Path(__file__).parent
NEEDED = ["attack_succeeded", "probe_id", "run_id", "input", "system_prompt_version", "category"]

sys.path.insert(0, str(HERE))
import clause_select as cs  # noqa: E402  (same folder)


def known_family(family, keys):
    return any(family.startswith(k) for k in keys if k != "default")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, help="path to alerts.db")
    ap.add_argument("--table", default="alerts")
    ap.add_argument("--version", type=int, help="only alerts that ran against this system-prompt version")
    ap.add_argument("--run-like", help="SQL LIKE pattern on run_id, e.g. %%20261012_v6-1%%")
    ap.add_argument("--out", help="write the eligible alerts as jsonl")
    ap.add_argument("--rounds-json", help="path to attack_generation/reports/rounds.json; alerts from rounds marked INVALID there (dead judge) are skipped. Their attack_succeeded grades are fine, but their detector flag is not, so the flagged/missed numbers would be wrong.")
    ap.add_argument("--require-mapper", action="store_true", help="also require the Mapper's call: predicted_category = --mapper-category and confidence >= --min-confidence")
    ap.add_argument("--mapper-category", default="B")
    ap.add_argument("--min-confidence", type=float, default=0.8, help="threshold; set it from the live classification testing results")
    ap.add_argument("--mapper-run", help="read the Mapper's call from mapper_results for this run_id instead of the alerts columns")
    ap.add_argument("--mapper-family", action="store_true", help="also accept succeeded attacks whose probe family has no clause, when the Mapper calls them B with enough confidence and its IDs select a clause (technique_map.json)")
    a = ap.parse_args()

    clauses = cs.load_clauses()
    rules = cs.load_technique_map()
    uri = "file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    cols = [r["name"] for r in con.execute(f"PRAGMA table_info({a.table})")]
    if not cols:
        sys.exit(f"table '{a.table}' not found in {a.db}")
    missing = [c for c in NEEDED if c not in cols]
    if missing:
        sys.exit(f"missing columns {missing}; columns present: {cols}")

    mapper_rows = None
    if a.mapper_run:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mapper_results'").fetchone():
            sys.exit(f"--mapper-run needs a mapper_results table in {a.db}")
        mapper_rows = {}
        for m in con.execute("SELECT alert_id, predicted_category, confidence, atlas_technique, owasp_category FROM mapper_results "
                             "WHERE run_id = ? AND valid_json = 1 ORDER BY repeat_no", (a.mapper_run,)):
            mapper_rows[m["alert_id"]] = m          # highest repeat_no wins
        if not mapper_rows:
            sys.exit(f"no valid Mapper results for run_id '{a.mapper_run}' in mapper_results")
        has_mapper = True
    else:
        has_mapper = "predicted_category" in cols and "classification_confidence" in cols
    if a.require_mapper and not has_mapper:
        sys.exit("--require-mapper needs the columns predicted_category and classification_confidence (or --mapper-run); columns present: " + str(cols))
    if a.mapper_family and not has_mapper:
        sys.exit("--mapper-family needs Mapper results (the alerts columns or --mapper-run)")

    def col(r, c):
        return r[c] if c in cols else None

    def mapper_call(r):
        """(category, confidence, ATLAS ids, OWASP ids), or None when the Mapper has not classified this alert."""
        if not has_mapper:
            return None
        if mapper_rows is not None:
            m = mapper_rows.get(col(r, "id"))
            if m is None:
                return None
            return m["predicted_category"], m["confidence"], cs.parse_ids(m["atlas_technique"]), cs.parse_ids(m["owasp_category"])
        if col(r, "classified_at") is None and r["predicted_category"] is None:
            return None
        return (r["predicted_category"], r["classification_confidence"],
                cs.parse_ids(col(r, "atlas_technique")), cs.parse_ids(col(r, "owasp_category")))

    def mapper_ids(r):
        c = mapper_call(r)
        return (c[2] + c[3]) if c else []

    def mapper_ok(r):
        if not has_mapper:
            return None
        c = mapper_call(r)
        if c is None:
            return False
        try:
            conf = float(c[1])
        except (TypeError, ValueError):
            return False
        return (c[0] or "").strip() == a.mapper_category and conf >= a.min_confidence

    def fam_of(r):
        return (r["probe_id"] or "").strip() or "default"

    where, args = [], []
    if a.version is not None:
        where.append("system_prompt_version = ?"); args.append(a.version)
    if a.run_like:
        where.append("run_id LIKE ?"); args.append(a.run_like)
    sql = f"SELECT rowid AS rid, * FROM {a.table}" + (" WHERE " + " AND ".join(where) if where else "")
    rows = con.execute(sql, args).fetchall()
    skipped_invalid = 0
    if a.rounds_json:
        invalid = set(json.load(open(a.rounds_json, encoding="utf-8")).get("invalid", {}))
        keep = [r for r in rows if not any((r["run_id"] or "").endswith("_" + t) for t in invalid)]
        skipped_invalid = len(rows) - len(keep); rows = keep

    total = len(rows)
    unannotated = sum(1 for r in rows if r["attack_succeeded"] is None)
    succeeded = [r for r in rows if r["attack_succeeded"] in (1, True, "1")]
    eligible, unknown, skipped_mapper, via_mapper = [], collections.Counter(), [], 0
    for r in succeeded:
        fam = (r["probe_id"] or "").strip()
        if not fam:
            fam = "default"          # agreed with Emmanuel: no probe_id -> default clause
        if fam == "default" or known_family(fam, clauses.keys()):
            if a.require_mapper and not mapper_ok(r):
                skipped_mapper.append(r)
            else:
                eligible.append(r)
        elif a.mapper_family and mapper_ok(r) and cs.mapper_key(mapper_ids(r), rules)[0]:
            eligible.append(r)       # v2: the Mapper's mapping supplies the clause the probe family lacks
            via_mapper += 1
        else:
            unknown[fam or "(no probe_id)"] += 1

    print(f"alerts considered: {total}" + (f"  (skipped {skipped_invalid} from rounds marked INVALID)" if a.rounds_json else ""))
    print(f"  attack_succeeded not filled in yet (run annotate_run.py): {unannotated}")
    print(f"  attack_succeeded = true: {len(succeeded)}")
    print(f"  eligible (succeeded and known family{' and Mapper ' + a.mapper_category + ' >= ' + str(a.min_confidence) if a.require_mapper else ''}): {len(eligible)}")
    if a.require_mapper:
        print(f"  skipped because the Mapper did not call it {a.mapper_category} with enough confidence: {len(skipped_mapper)}")
    elif has_mapper and eligible:
        dropped = sum(1 for r in eligible if not mapper_ok(r))
        print(f"  (Mapper would drop {dropped} of these {len(eligible)} at {a.mapper_category} >= {a.min_confidence}; not applied, --require-mapper is off)")
    elif not has_mapper:
        print("  (no predicted_category / classification_confidence columns in this table, Mapper not read)")
    if a.mapper_family:
        print(f"  of the eligible, accepted through the Mapper's mapping (probe family has no clause): {via_mapper}")
    if unknown:
        print(f"  succeeded but family unknown (no clause): {sum(unknown.values())} -> {dict(unknown)}")
    if has_mapper and eligible:
        agree = collections.Counter()
        for r in eligible:
            if mapper_call(r) is None:
                agree["not classified by the Mapper"] += 1
                continue
            mk = cs.mapper_key(mapper_ids(r), rules)[0]
            pk = cs.probe_key(fam_of(r), clauses) or "default"
            agree["no Mapper ID in technique_map" if mk is None else ("same clause" if mk == pk else "different clause")] += 1
        techs = collections.Counter(i for r in eligible for i in mapper_ids(r))
        print(f"  clause from probe family vs Mapper mapping, over {len(eligible)} eligible: " + ", ".join(f"{k} {v}" for k, v in agree.most_common()))
        print("  Mapper IDs seen: " + (", ".join(f"{i} x{n}" for i, n in techs.most_common(10)) or "none"))

    by = collections.defaultdict(lambda: {"n": 0, "flagged": 0, "prompts": set()})
    for r in eligible:
        d = by[(r["probe_id"] or "").strip() or "default"]
        d["n"] += 1
        d["flagged"] += 1 if (r["category"] or "").strip() else 0
        d["prompts"].add(r["input"])
    if by:
        print(f"\n{'family':45s} {'succeeded':>9s} {'flagged':>8s} {'missed':>7s} {'distinct prompts':>17s}")
        for fam in sorted(by, key=lambda f: -by[f]["n"]):
            d = by[fam]
            print(f"{fam:45s} {d['n']:9d} {d['flagged']:8d} {d['n'] - d['flagged']:7d} {len(d['prompts']):17d}")
        missed = sum(d["n"] - d["flagged"] for d in by.values())
        print(f"\nsucceeded but NOT flagged by the detector: {missed} (kept: the gate does not require the flag)")

    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            for r in eligible:
                c = mapper_call(r)
                fh.write(json.dumps({"rowid": r["rid"], "family": fam_of(r), "run_id": r["run_id"], "version": r["system_prompt_version"],
                                     "flagged": bool((r["category"] or "").strip()),
                                     "mapper_category": c[0] if c else None,
                                     "mapper_confidence": c[1] if c else None,
                                     "mapper_atlas": c[2] if c else [], "mapper_owasp": c[3] if c else [],
                                     "probe_clause": cs.probe_key(fam_of(r), clauses) or "default",
                                     "mapper_clause": cs.mapper_key(mapper_ids(r), rules)[0],
                                     "prompt": r["input"]}) + "\n")
        print(f"wrote {len(eligible)} eligible alerts to {a.out}")


if __name__ == "__main__":
    main()
