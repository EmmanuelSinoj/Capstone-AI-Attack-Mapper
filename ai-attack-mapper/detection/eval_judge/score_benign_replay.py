"""score_benign_replay.py -- (container, GPU) score benign_replay_set.json with the production judge.
  docker compose exec testbed python3 /app/detection/eval_judge/score_benign_replay.py
Writes benign_replay/benign_replay_scores.jsonl  {id, lo_jailbreak, ...}. Offline stand-in for the live replay: same judge,
same windows; the LIVE replay (through /chat) is what the report uses."""
import json, os, sys, time
sys.path.insert(0, "/app"); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import judge  # noqa: E402
import judge_scoring  # noqa: E402
HERE = os.path.dirname(os.path.abspath(__file__)); D = os.path.join(HERE, "benign_replay")
clf = judge._get_pipeline()
if clf is None: raise RuntimeError("Judge failed to load; see testbed logs.")
rows = json.load(open(os.path.join(D, "benign_replay_set.json"), encoding="utf-8")); t0 = time.time()
with open(os.path.join(D, "benign_replay_scores.jsonl"), "w", encoding="utf-8") as out:
    for r in rows:
        out.write(json.dumps({"id": r["id"], **judge_scoring.score_text(r["text"], clf, judge._MAX_LENGTH)}) + "\n")
print(f"Scored {len(rows)} messages in {time.time()-t0:.0f}s")
