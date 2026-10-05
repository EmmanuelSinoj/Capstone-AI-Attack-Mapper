"""judge_score_support.py -- score support_benign_210.json with the production judge (log-odds). Writes judge_support_scores.jsonl.
  docker compose exec testbed python3 /app/detection/eval_judge/judge_score_support.py"""
import json, os, sys, time
sys.path.insert(0, "/app"); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import judge  # noqa: E402
import judge_scoring  # noqa: E402
HERE = os.path.dirname(os.path.abspath(__file__))
clf = judge._get_pipeline()
if clf is None: raise RuntimeError("Judge failed to load; see testbed logs.")
rows = json.load(open(os.path.join(HERE, "support_benign_210.json"), encoding="utf-8")); t0 = time.time()
with open(os.path.join(HERE, "judge_support_scores.jsonl"), "w") as out:
    for i, r in enumerate(rows):
        out.write(json.dumps({"i": i, "category": r["category"], **judge_scoring.score_text(r["text"], clf, judge._MAX_LENGTH)}) + "\n")
print(f"Scored {len(rows)} prompts in {time.time()-t0:.0f}s")
