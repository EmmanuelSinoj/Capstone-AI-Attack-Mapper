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
clauses.json must sit in the same folder as this script. Stdlib only."""
import argparse, collections, json, pathlib, sqlite3, sys

HERE = pathlib.Path(__file__).parent
NEEDED = ["attack_succeeded", "probe_id", "run_id", "input", "system_prompt_version", "category"]


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
    a = ap.parse_args()

    clauses = json.load(open(HERE / "clauses.json", encoding="utf-8"))
    uri = "file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    cols = [r["name"] for r in con.execute(f"PRAGMA table_info({a.table})")]
    if not cols:
        sys.exit(f"table '{a.table}' not found in {a.db}")
    missing = [c for c in NEEDED if c not in cols]
    if missing:
        sys.exit(f"missing columns {missing}; columns present: {cols}")

    has_mapper = "predicted_category" in cols and "classification_confidence" in cols
    if a.require_mapper and not has_mapper:
        sys.exit("--require-mapper needs the columns predicted_category and classification_confidence; columns present: " + str(cols))

    def mapper_ok(r):
        if not has_mapper:
            return None
        try:
            conf = float(r["classification_confidence"])
        except (TypeError, ValueError):
            return False
        return (r["predicted_category"] or "").strip() == a.mapper_category and conf >= a.min_confidence

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
    eligible, unknown, skipped_mapper = [], collections.Counter(), []
    for r in succeeded:
        fam = (r["probe_id"] or "").strip()
        if not fam:
            fam = "default"          # agreed with Emmanuel: no probe_id -> default clause
        if fam == "default" or known_family(fam, clauses.keys()):
            if a.require_mapper and not mapper_ok(r):
                skipped_mapper.append(r)
            else:
                eligible.append(r)
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
    if unknown:
        print(f"  succeeded but family unknown (no clause): {sum(unknown.values())} -> {dict(unknown)}")

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
                fh.write(json.dumps({"rowid": r["rid"], "family": (r["probe_id"] or "").strip() or "default", "run_id": r["run_id"], "version": r["system_prompt_version"],
                                     "flagged": bool((r["category"] or "").strip()),
                                     "mapper_category": r["predicted_category"] if has_mapper else None,
                                     "mapper_confidence": r["classification_confidence"] if has_mapper else None, "prompt": r["input"]}) + "\n")
        print(f"wrote {len(eligible)} eligible alerts to {a.out}")


if __name__ == "__main__":
    main()
