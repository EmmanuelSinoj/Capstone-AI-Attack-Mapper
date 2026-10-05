#!/usr/bin/env python3
"""worked_definitions.py -- one row per definition of a "worked" attack, with how many v6 flagged.
Session = alert rows whose timestamp starts with --day; Garak run = --prefix (report + hit log in attack_generation/reports).
  (a) prompt appears in ANY Garak hit log (all sessions)        [what detection_report.py did before --round]
  (b) prompt appears in THIS run's hit log
  (c) (prompt, reply) pair appears in THIS run's hit log        [what annotate_run.py stores as attack_succeeded]
'Flagged' = v6 as it runs live: exact patterns on the prompt OR on the reply OR system-prompt leak OR judge log-odds >= T on the prompt.
'Prompt-only' = patterns on the prompt OR judge only (what the round summary printed on 4 Oct)."""
import argparse, glob, hashlib, json, os, re, sqlite3, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
from detection import heuristics  # noqa: E402
ap = argparse.ArgumentParser()
ap.add_argument("--db", required=True); ap.add_argument("--reports", required=True); ap.add_argument("--prefix", required=True)
ap.add_argument("--day", default="2026-10-02"); ap.add_argument("--threshold", type=float, default=9.1)
ap.add_argument("--system-prompt", required=True); ap.add_argument("--cache", default=os.path.join(HERE, "judge_rescore_cache.jsonl"))
ap.add_argument("--hitlogs-until", help="for (a): only hit logs whose name stamp (e.g. 20261002T151835Z) is <= this; default all")
ap.add_argument("--dump", help="write the worked-and-missed rows (definition c) to this JSON file")
a = ap.parse_args()
key = lambda t: hashlib.sha1(t.encode("utf-8", "replace")).hexdigest()
cache = {}
for l in open(a.cache, encoding="utf-8"):
    try: d = json.loads(l); cache[d["k"]] = d["lo"]
    except Exception: pass
sysprompt = re.sub(r"^#.*\n?", "", open(a.system_prompt, encoding="utf-8").read(), count=1).strip()
tx = lambda p: p["turns"][-1]["content"]["text"]
def hits_of(path):
    s, pairs = set(), set()
    for l in open(path, encoding="utf-8"):
        try: d = json.loads(l); p = tx(d["prompt"])
        except Exception: continue
        s.add(p); o = d.get("output"); pairs.add((p, o.get("text") if isinstance(o, dict) else o))
    return s, pairs
any_hit = set()
for f in glob.glob(os.path.join(a.reports, "*.hitlog.jsonl")):
    stamp = os.path.basename(f).split("_")[-1].split(".")[0]
    if not a.hitlogs_until or stamp <= a.hitlogs_until: any_hit |= hits_of(f)[0]
run_hit, run_pairs = hits_of(os.path.join(a.reports, os.path.basename(a.prefix) + ".hitlog.jsonl"))
conn = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
rows = conn.execute("SELECT id,input,output,detector FROM alerts WHERE timestamp LIKE ?", (a.day + "%",)).fetchall()
LO = re.compile(r"lo=(-?[\d.]+)"); memo = {}
def pat(t):
    if t not in memo: memo[t] = heuristics.check(t or "")
    return memo[t]
recs = []
for i, inp, out, det in rows:
    pf, _ = pat(inp); rf, _ = pat(out or ""); leak = heuristics._check_system_prompt_leak(out or "", sysprompt)
    lo = cache.get(key(inp))
    if lo is None:
        m = LO.search(det or ""); lo = float(m.group(1)) if m else None
    j = lo is not None and lo >= a.threshold
    recs.append(dict(id=i, inp=inp, out=out, lo=lo, full=bool(pf or rf or leak or j), ponly=bool(pf or j), nolo=lo is None))
print(f"session {a.day}: {len(recs)} rows; judge score missing for {sum(r['nolo'] for r in recs)}; flagged (full v6 rule) {sum(r['full'] for r in recs)} = {100*sum(r['full'] for r in recs)/len(recs):.1f}%")
defs = [("(a) prompt in ANY hit log" + (f" (up to {a.hitlogs_until})" if a.hitlogs_until else " (all, incl. later runs)"), lambda r: r["inp"] in any_hit),
        ("(b) prompt in THIS run's hit log", lambda r: r["inp"] in run_hit),
        ("(c) (prompt, reply) pair in THIS run's hit log", lambda r: (r["inp"], r["out"]) in run_pairs)]
print(f"\n{'definition':<50}{'worked':>8}{'flagged':>9}{'missed':>8}{'share flagged':>15}{'prompt-only flagged':>22}")
for name, f in defs:
    w = [r for r in recs if f(r)]; fl = sum(r["full"] for r in w); po = sum(r["ponly"] for r in w)
    print(f"{name:<50}{len(w):>8}{fl:>9}{len(w)-fl:>8}{100*fl/len(w):>14.1f}%{po:>14} ({100*po/len(w):.1f}%)")
if a.dump:
    w = [r for r in recs if defs[2][1](r) and not r["full"]]
    json.dump([{k: r[k] for k in ("id", "inp", "out", "lo")} for r in w], open(a.dump, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"\nwrote {len(w)} worked-and-missed rows (definition c) to {a.dump}")
