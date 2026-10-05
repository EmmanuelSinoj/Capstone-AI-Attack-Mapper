"""verify_live_detection.py -- run INSIDE the testbed container. Proves the LIVE code path
(detection.heuristics + detection.judge.check_interaction) gives the same decisions as the
saved evaluation scores, with fuzzy off. Uses the 570 short prompts + the first 150 training
prompts only (never the locked 300).
  docker compose exec testbed python3 /app/detection/eval_judge/verify_live_detection.py"""
import json, os, sys
from detection import heuristics, judge
D = os.path.dirname(os.path.abspath(__file__))
L = lambda f: [json.loads(x) for x in open(os.path.join(D, f), encoding="utf-8")]
T = judge.JUDGE_THRESHOLD
print("JUDGE_THRESHOLD =", T)
items = []  # (text, saved_lo, saved_exact, label)
JS = {(r["set"], r["i"]): r for r in L("judge_short_scores.jsonl")}
ES = {(r["set"], r["i"]): r for r in L("exact_short_scores.jsonl")}
for name in ("labeled_prompts_500", "stress_prompts"):
    for i, d in enumerate(json.load(open(os.path.join(D, name + ".json"), encoding="utf-8"))):
        items.append((d["text"], JS[(name, i)]["lo_jailbreak"], ES[(name, i)]["exact"], d["label"]))
tr = json.load(open(os.path.join(D, "jailbreakhub_1000_train.json"), encoding="utf-8"))
JT = {r["i"]: r for r in L("judge_train_scores_v2.jsonl")}; HT = {r["i"]: r for r in L("heuristics_v5_train_scores.jsonl")}
for i in range(150):
    items.append((tr[i].get("text") or tr[i].get("prompt"), JT[i]["lo_jailbreak"], HT[i]["exact"], JT[i]["label"]))
maxdiff = 0.0; decision_mismatch = 0; unavailable = 0; tp = fp = 0; na = nb = 0
for text, lo_saved, exact_saved, label in items:
    flagged_j, detail, conf = judge.check_interaction(text, "")
    if detail == "judge_unavailable":
        unavailable += 1; continue
    lo_live = float(detail.split("lo=")[1].rstrip(")"))
    maxdiff = max(maxdiff, abs(lo_live - lo_saved))
    h_flag, _, _ = heuristics.check_interaction(text, "")
    live = h_flag or flagged_j
    saved = exact_saved or lo_saved >= T
    decision_mismatch += live != saved
    if label == "attack": na += 1; tp += live
    else: nb += 1; fp += live
print(f"checked {len(items)-unavailable}/{len(items)} (unavailable: {unavailable})")
print(f"max |lo_live - lo_saved| = {maxdiff:.4f}   (GPU/float noise only; expect < 0.01)")
print(f"decision mismatches vs saved scores: {decision_mismatch}")
print(f"live rule on these items: caught {tp}/{na}, normal flagged {fp}/{nb}")
print("PASS" if (unavailable == 0 and decision_mismatch == 0 and maxdiff < 0.05) else "CHECK ABOVE")
