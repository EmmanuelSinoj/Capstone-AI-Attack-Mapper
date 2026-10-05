#!/usr/bin/env python3
"""annotate_run.py -- after a Garak run, fill probe_id and attack_succeeded on that run's alert rows.
(PLAN_run_probe_ids.md.) Garak's REST generator sends only the prompt, so the probe name and Garak's own grading are
joined back from Garak's files:
  <prefix>.report.jsonl  attempts: prompt text -> probe_classname      (probe_id = e.g. promptinject.HijackHateHumans)
  <prefix>.hitlog.jsonl  generations Garak's detectors judged SUCCESSFUL (prompt, output)
Row matching: input == attempt prompt text. attack_succeeded = 1 if (input, output) is in the hit log, else 0 (Garak graded
it and it did not work). Rows with no matching attempt are LEFT ALONE and listed -- never guessed.
This WRITES to alerts.db, so run it inside the testbed container (SQLite writes over a host mount fail):

  docker compose run --rm --no-deps -v "${PWD}/live_attack_path/attack_generation:/app/attack_generation:ro" testbed \
      python3 /app/attack_generation/annotate_run.py <round token>       (PowerShell, from the project root)

Dry run first (changes nothing):  add --dry-run.
Testing on an OLD session without run ids:  --legacy-day 2026-10-02 --report-prefix <path without .report.jsonl> --dry-run
PyRIT rows already carry probe_id live; their attack_succeeded comes from the PyRIT scorer (separate step)."""
import argparse, collections, glob, json, os, re, sqlite3, sys


def ptext(p):
    try: return p["turns"][-1]["content"]["text"]
    except Exception: return p if isinstance(p, str) else None


def otext(o):
    if isinstance(o, dict): return o.get("text")
    return o if isinstance(o, str) else None


LO_RE = re.compile(r"lo=(-inf|-?[\d.]+)")


def judge_status(c, round_token):
    """(total, valid, bad, reason). A row has a valid judge score if its detector string holds a finite log-odds above -1e8
    (or -inf for an empty prompt). The failure value -1e9, 'judge:unavailable' and a missing judge field are all BAD.
    Added 2026-10-05: round 20261005_v6-2 was logged with a dead judge (-1e9 on every row) and nothing flagged it."""
    total = valid = 0
    for (det,) in c.execute("SELECT detector FROM alerts WHERE run_id LIKE ?", ("%_" + round_token,)):
        total += 1; m = LO_RE.search(det or "")
        if m and (m.group(1) == "-inf" or float(m.group(1)) > -1e8): valid += 1
    return total, valid, total - valid


def invalid_marker(reports_dir, round_token):
    try:
        return json.load(open(os.path.join(reports_dir, "rounds.json"), encoding="utf-8")).get("invalid", {}).get(round_token, {}).get("reason")
    except Exception:
        return None


def judge_verdict(c, a):
    """Print the judge-score status for the round; return True if the round is INVALID."""
    if not a.round or a.legacy_day: return False
    total, valid, bad = judge_status(c, a.round); marker = invalid_marker(a.reports_dir, a.round)
    print(f"JUDGE SCORES for round {a.round}: {total} rows, {valid} with a valid judge score, {bad} without (failure value -1e9 / unavailable / missing)")
    if bad or marker:
        print(f"ROUND STATUS: INVALID -- {bad} of {total} rows have no judge score." + (f" Marked invalid in rounds.json: {marker}" if marker else ""))
        print("  Flag rates (stored categories, reports) are NOT valid for this round and must not be quoted or used for the Mapper tests.")
        print("  The success grades written by this script come from Garak/PyRIT's own grading and remain valid.")
        return True
    print("ROUND STATUS: judge scores complete (no round-level problem found).")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("round", nargs="?", help="Round token, e.g. 20261006_v6-1 (annotates run garak_<round>).")
    ap.add_argument("--db", default="/app/alert_store/alerts.db")
    ap.add_argument("--reports-dir", default="/app/attack_generation/reports")
    ap.add_argument("--system-prompt", default="/app/system_prompt.txt")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--legacy-day", default=None, help="Select rows by timestamp date (YYYY-MM-DD) instead of run_id; needs --report-prefix.")
    ap.add_argument("--report-prefix", default=None, help="Garak report prefix path (no extension); default from the run's .runinfo.json.")
    a = ap.parse_args()
    if not a.round and not a.legacy_day: ap.error("give a round token (or --legacy-day with --report-prefix)")

    if a.report_prefix:
        prefix = a.report_prefix; run_id = None
    else:
        run_id = f"garak_{a.round}"
        info = None
        for f in glob.glob(os.path.join(a.reports_dir, "*.runinfo.json")):
            j = json.load(open(f, encoding="utf-8"))
            if j.get("run_id") == run_id: info = j
        prefix = os.path.join(a.reports_dir, info["report_prefix"].replace("\\","/").split("/")[-1]) if info else None
        if not info: print(f"NOTE: no Garak run for round {a.round} (no runinfo for {run_id}); only PyRIT / replay rows will be annotated.")
    probe, attempts = {}, {}
    for l in (open(prefix + ".report.jsonl", encoding="utf-8") if prefix else []):
        try: r = json.loads(l)
        except ValueError: continue
        if r.get("entry_type") == "attempt":
            t = ptext(r.get("prompt"))
            if t is not None: probe[t] = r.get("probe_classname")
    hits = set()
    if prefix and os.path.exists(prefix + ".hitlog.jsonl"):
        for l in open(prefix + ".hitlog.jsonl", encoding="utf-8"):
            try: r = json.loads(l)
            except ValueError: continue
            hits.add((ptext(r.get("prompt")), otext(r.get("output"))))
    print(f"Garak files: {len(probe)} distinct attempt prompts, {len(hits)} successful generations in the hit log")

    c = sqlite3.connect(("file:%s?mode=ro" % a.db) if (a.dry_run or a.legacy_day) else a.db, uri=bool(a.dry_run or a.legacy_day))
    if a.legacy_day:
        rows = c.execute("SELECT id, input, output FROM alerts WHERE source='live' AND timestamp LIKE ?", (a.legacy_day + "%",)).fetchall()
    else:
        rows = c.execute("SELECT id, input, output FROM alerts WHERE run_id=?", (run_id,)).fetchall()
    stats = collections.Counter(); fam = collections.defaultdict(lambda: [0, 0]); upd = []; unmatched = []
    for i, inp, out in rows:
        pid = probe.get(inp)
        if pid is None: stats["unmatched"] += 1; unmatched.append(i); continue
        ok = 1 if (inp, out) in hits else 0
        stats["matched"] += 1; stats["succeeded"] += ok; f = pid.split(".")[0]; fam[f][0] += 1; fam[f][1] += ok
        upd.append((pid, ok, i))
    print(f"Rows selected: {len(rows)}  matched: {stats['matched']}  unmatched (left alone): {stats['unmatched']}  graded successful: {stats['succeeded']}")
    for f, (n, s) in sorted(fam.items()): print(f"  {f:<14} {n:>5} rows  {s:>4} successful")
    if unmatched: print("  unmatched alert ids (first 20):", unmatched[:20])
    # PyRIT rows of the same round: probe_id was set live; attack_succeeded comes from pyrit_scorer.py
    pupd = []
    if a.round and not a.legacy_day:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import pyrit_scorer
        try: sp = pyrit_scorer.load_system_prompt(a.system_prompt)
        except OSError: sp = ""
        prun = f"pyrit_{a.round}"; obj = {}
        for f in glob.glob(os.path.join(a.reports_dir, "pyrit_run_*.json")):
            j = json.load(open(f, encoding="utf-8"))
            if j.get("run_id") == prun:
                for r in j.get("results", []): obj[r["probe_id"]] = r["objective"]
        prow = c.execute("SELECT id, probe_id, output FROM alerts WHERE run_id=?", (prun,)).fetchall()
        kinds = collections.Counter(); won = 0
        for i, pid, out in prow:
            if pid not in obj: print(f"  PyRIT row {i}: no objective for probe_id {pid!r} (left alone)"); continue
            ok, kind = pyrit_scorer.grade(obj[pid], out, sp); won += ok; kinds[kind] += 1; pupd.append((ok, i))
        print(f"PyRIT {prun}: {len(prow)} rows, graded {len(pupd)}, successful {won}  (rules: {dict(kinds)}; no_refusal is a weak heuristic)")
    # Replay rows (replay_runner.py): grades live in reports/<run_id>.results.jsonl; match alert rows by (prompt, reply)
    rupd = []
    if a.round and not a.legacy_day:
        for rid in [r[0] for r in c.execute("SELECT DISTINCT run_id FROM alerts WHERE run_id LIKE ?", (f"replayv%_{a.round}",)).fetchall()]:
            rf = os.path.join(a.reports_dir, rid + ".results.jsonl")
            if not os.path.exists(rf): print(f"  {rid}: no results file {rf} (left alone)"); continue
            grades = {}
            for l in open(rf, encoding="utf-8"):
                try: j = json.loads(l)
                except ValueError: continue
                grades[(j["prompt"], j["output"])] = int(j["success"])
            rrows = c.execute("SELECT id, input, output FROM alerts WHERE run_id=?", (rid,)).fetchall()
            m = [(grades[(inp, out)], i) for i, inp, out in rrows if (inp, out) in grades]
            won = sum(x for x, _ in m); rupd += m
            print(f"Replay {rid}: {len(rrows)} rows, matched {len(m)}, successful {won}" + ("" if len(m) == len(rrows) else f"  ({len(rrows)-len(m)} unmatched, left alone)"))
    if a.dry_run or a.legacy_day:
        print("DRY RUN: nothing written."); return 3 if judge_verdict(c, a) else 0
    c.executemany("UPDATE alerts SET probe_id=?, attack_succeeded=? WHERE id=?", upd)
    c.executemany("UPDATE alerts SET attack_succeeded=? WHERE id=?", pupd + rupd); c.commit()
    print(f"Updated {len(upd)} Garak rows, {len(pupd)} PyRIT rows and {len(rupd)} replay rows.")
    return 3 if judge_verdict(c, a) else 0


if __name__ == "__main__":
    sys.exit(main())
