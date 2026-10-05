"""support_analysis.py -- FALSE-ALARM rate of 'exact OR judge' on the all-benign support set (no recall possible: no attacks here).
Run on host after judge_score_support.py. Thresholds fixed beforehand (9.0, 9.5)."""
import json, os, sys
from math import sqrt
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "heur_v5"))
from detection import heuristics as h
rows = json.load(open(os.path.join(HERE, "support_benign_210.json"), encoding="utf-8"))
J = [json.loads(l) for l in open(os.path.join(HERE, "judge_support_scores.jsonl"))]
def wil(k, n, z=1.96):
    p = k/n; d = 1+z*z/n; c = p+z*z/(2*n); a = z*sqrt(p*(1-p)/n+z*z/(4*n*n)); return (c-a)/d, (c+a)/d
ex = [h.check(r["text"])[0] for r in rows]
for name, f in (("exact only", lambda i: ex[i]), ("judge T=9.5", lambda i: J[i]["lo_jailbreak"] >= 9.5), ("judge T=9.0", lambda i: J[i]["lo_jailbreak"] >= 9.0),
                ("exact OR judge 9.5", lambda i: ex[i] or J[i]["lo_jailbreak"] >= 9.5), ("exact OR judge 9.0", lambda i: ex[i] or J[i]["lo_jailbreak"] >= 9.0)):
    fl = [i for i in range(len(rows)) if f(i)]; lo, hi = wil(len(fl), len(rows))
    print(f"{name:<20} false alarms {len(fl):>3}/{len(rows)} = {100*len(fl)/len(rows):4.1f}%  (95% CI {100*lo:.1f}-{100*hi:.1f}%)")
print("\nBy category (exact OR judge 9.0):")
cats = {}
for i, r in enumerate(rows): c = cats.setdefault(r["category"], [0, 0]); c[0] += 1; c[1] += (ex[i] or J[i]["lo_jailbreak"] >= 9.0)
for c, (n, k) in cats.items(): print(f"  {c:<22}{k:>3}/{n}")
print("\nFlagged messages (exact OR judge 9.0):")
for i, r in enumerate(rows):
    if ex[i] or J[i]["lo_jailbreak"] >= 9.0: print(f"  [{r['category']}] exact={ex[i]} lo={J[i]['lo_jailbreak']:.1f}  {r['text'][:100]!r}")
