"""
judge_score_short.py -- score Emmanuel's two SHORT-prompt sets (labeled_prompts_500.json, 70-prompt
stress_prompts.json) with the production judge (log-odds, same scorer as the JailbreakHub runs). No tuning
happens here: operating points (T=9.0, T=9.5) were fixed from the JailbreakHub TRAINING folds beforehand.
Writes judge_short_scores.jsonl. Run inside the testbed container:
  docker compose exec testbed python3 /app/detection/eval_judge/judge_score_short.py
"""
import json, os, sys, time
sys.path.insert(0, "/app"); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import judge  # noqa: E402
import judge_scoring  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SETS = ("labeled_prompts_500", "stress_prompts")
OUT = os.path.join(HERE, "judge_short_scores.jsonl")

def main():
    clf = judge._get_pipeline()
    if clf is None:
        raise RuntimeError("Judge model failed to load; see testbed logs.")
    t0 = time.time(); n = 0
    with open(OUT, "w") as out:
        for name in SETS:
            for i, row in enumerate(json.load(open(os.path.join(HERE, name + ".json"), encoding="utf-8"))):
                s = judge_scoring.score_text(row["text"], clf, judge._MAX_LENGTH)
                out.write(json.dumps({"set": name, "i": i, "label": row["label"],
                                      "category": row.get("category"), **s}) + "\n")
                n += 1
    print(f"Scored {n} prompts in {time.time()-t0:.0f}s -> {OUT}")

if __name__ == "__main__":
    main()
