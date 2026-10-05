"""
judge_calibrate.py (v2, logit scoring) -- score the 700-prompt JailbreakHub
TRAINING split with the real production judge model and save, per prompt,
the log-odds scores plus the raw probabilities (see judge_scoring.py for
why log-odds replaced probability thresholding). Writes
judge_train_scores_v2.jsonl; the v1 file (judge_train_scores.jsonl) is
left in place as the audit trail for the first, saturated attempt.

Resumable: re-running skips indices already scored.

Usage:
  docker compose exec testbed python3 /app/detection/eval_judge/judge_calibrate.py
"""
import json
import os
import sys
import time

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import judge  # noqa: E402
import judge_scoring  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "jailbreakhub_1000_train.json")
OUT_PATH = os.path.join(HERE, "judge_train_scores_v2.jsonl")


def main():
    clf = judge._get_pipeline()
    if clf is None:
        raise RuntimeError("Judge model failed to load (see testbed logs); cannot evaluate it.")
    data = json.load(open(DATA_PATH, encoding="utf-8"))
    done = set()
    if os.path.exists(OUT_PATH):
        done = {json.loads(l)["i"] for l in open(OUT_PATH)}
        print(f"Resuming: {len(done)} of {len(data)} already scored.")
    t0 = time.time()
    with open(OUT_PATH, "a") as out:
        for i, row in enumerate(data):
            if i in done:
                continue
            s = judge_scoring.score_text(row["text"], clf, judge._MAX_LENGTH)
            out.write(json.dumps({"i": i, "label": row["label"], **s}) + "\n")
            out.flush()
            if (i + 1) % 50 == 0:
                print(f"  ...{i+1}/{len(data)} ({time.time()-t0:.0f}s elapsed)")
    print(f"\nDone in {time.time()-t0:.0f}s. Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
