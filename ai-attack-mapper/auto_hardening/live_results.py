#!/usr/bin/env python3
"""live_results.py -- turn the Garak rows of live rounds in alerts.db into the results file decide.py reads.

  python live_results.py --db ..\\alert_store\\alerts.db --runs garak_20261028_v6-1 garak_20261029_v6-1 ^
      --seen ..\\attack_generation\\replay_sets\\replay_set_v6-trial.json ..\\attack_generation\\replay_sets\\paraphrases_v6-trial.json ^
      --rounds-json ..\\attack_generation\\reports\\rounds.json --out live_results.jsonl
  python decide.py --parent 1 --candidate 5 --results live_results.jsonl --variants fresh --utility utility_1_5_<stamp>.csv

One row per logged request: family = probe_id, id = a short hash of the prompt text (Garak sends each prompt several times, so the
repeats of one attack share an id and decide.py counts them as ONE attack), success = attack_succeeded (Garak's own grading, written
by annotate_run.py), version = system_prompt_version of that row. Rows whose attack_succeeded is still NULL are written with
ok = false, so decide.py counts them as failed requests per version instead of losing them: run annotate_run.py for each round first.
The script STOPS if any row is still ungraded (the pairing below keeps only prompts with a graded row in every version, so a prompt
that is fully ungraded in one round would vanish together with its failed rows). --allow-ungraded overrides this.
PAIRED (default when the runs cover 2+ prompt versions): Garak samples different prompts each round (Oct 4 vs Oct 5: only 162 of
~290 promptinject prompts were in both), so only prompts that appear in EVERY version's round are kept. Then every version is
tested on the same attacks. The summary shows how many prompts were dropped per family. --all-prompts turns this off.
variant: 'seen' if the exact prompt text is in one of the --seen replay sets (the 60 originals, the 116 paraphrases), else 'fresh'.
Without --seen every row is 'live'. Use decide.py --variants fresh for the held-out test; 'seen' rows only show consistency with the replay.
Only run ids starting with garak_ are accepted: PyRIT has 4 objectives and a rule-based scorer, too small and weak for the rule.
Rounds marked INVALID in rounds.json (--rounds-json) only lose their detector flag, not the Garak grading, so they are allowed with a warning.
Read-only (mode=ro). Stdlib only."""
import argparse, collections, hashlib, json, pathlib, sqlite3, sys


def texts(path):
    data = json.load(open(path, encoding="utf-8"))
    out = set()
    if isinstance(data, dict):
        for v in data.values():
            out.update(t.strip() for t in v if isinstance(t, str))
    else:
        out.update(i["text"].strip() for i in data if isinstance(i, dict) and "text" in i)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--runs", nargs="+", required=True, help="garak_<round> run ids, one per prompt version")
    ap.add_argument("--seen", nargs="*", default=[], help="replay set / paraphrase json files whose prompts count as already seen")
    ap.add_argument("--rounds-json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--allow-ungraded", action="store_true", help="carry on even if some rows have no attack_succeeded yet (the failed share can then be undercounted)")
    ap.add_argument("--all-prompts", action="store_true", help="do not restrict to prompts that appear in every version's round")
    a = ap.parse_args()
    bad = [r for r in a.runs if not r.startswith("garak_")]
    if bad:
        sys.exit(f"only garak_ run ids are accepted, got: {bad}")
    seen = set()
    for p in a.seen:
        seen |= texts(p)
    invalid = {}
    if a.rounds_json:
        invalid = json.load(open(a.rounds_json, encoding="utf-8")).get("invalid", {})
    con = sqlite3.connect("file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro", uri=True)
    rows_out, null_n, per_run, null_run = [], 0, collections.Counter(), collections.Counter()
    for run in a.runs:
        tok = run.split("_", 1)[1]
        if tok in invalid:
            print(f"WARNING: round {tok} is marked INVALID ({invalid[tok].get('reason', '')[:80]}...). Garak grades are still used; flags are not.")
        n = 0
        for inp, succ, ver, pid in con.execute("SELECT input, attack_succeeded, system_prompt_version, probe_id FROM alerts WHERE run_id = ? ORDER BY id", (run,)):
            n += 1
            rid = hashlib.sha1((inp or "").encode("utf-8")).hexdigest()[:12]
            var = ("seen" if (inp or "").strip() in seen else "fresh") if a.seen else "live"
            if succ is None:
                null_n += 1; null_run[run] += 1
            rows_out.append({"family": pid or "unknown", "id": rid, "ok": succ is not None,
                             "success": None if succ is None else int(succ), "variant": var, "version": ver, "run_id": run})
        if n == 0:
            print(f"WARNING: no rows for run id {run}")
        per_run[run] = n
    if null_n and not a.allow_ungraded:
        sys.exit(f"{null_n} rows have no attack_succeeded yet: {dict(null_run)}. Run annotate_run.py for those rounds first "
                 f"(or pass --allow-ungraded). Nothing written.")
    versions = sorted({r["version"] for r in rows_out}, key=str)
    if not a.all_prompts and len(versions) >= 2:
        ids_by_v = {v: {r["id"] for r in rows_out if r["version"] == v and r["ok"]} for v in versions}
        common = set.intersection(*ids_by_v.values())
        before = collections.defaultdict(lambda: collections.defaultdict(set))
        for r in rows_out:
            before[r["family"].split(".")[0]][r["version"]].add(r["id"])
        rows_out = [r for r in rows_out if r["id"] in common]
        print(f"paired: kept prompts that appear in all of v{', v'.join(map(str, versions))}")
        for f in sorted(before):
            kept = len({r["id"] for r in rows_out if r["family"].split(".")[0] == f})
            sizes = ", ".join(f"v{v} {len(before[f][v])}" for v in versions)
            print(f"  {f:14s} distinct prompts {sizes} -> in all versions {kept}")
    elif len(versions) < 2:
        print(f"note: the runs cover only version(s) {versions}; nothing to pair")
    with open(a.out, "w", encoding="utf-8") as fh:
        for r in rows_out:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows_out)} rows to {a.out}  (rows per run: {dict(per_run)}; not graded yet, written as failed: {dict(null_run) or 0})")
    if null_n:
        print("  -> run annotate_run.py for those rounds, then run this again")
    for v in versions:
        for var in sorted({r["variant"] for r in rows_out}):
            sel = [r for r in rows_out if r["version"] == v and r["variant"] == var and r["ok"]]
            if sel:
                succ = sum(r["success"] for r in sel)
                print(f"  v{v} {var:6s}: {len({r['id'] for r in sel})} distinct prompts, {len(sel)} graded requests, {100 * succ / len(sel):.1f}% succeeded")
    fam = collections.Counter(r["family"].split(".")[0] for r in rows_out)
    print("  families:", dict(fam))


if __name__ == "__main__":
    main()
