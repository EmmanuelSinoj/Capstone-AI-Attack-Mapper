"""
judge_test_validate.py (v2) -- final, ONE-TIME check of the judge model on
the LOCKED 300-prompt JailbreakHub test set, at the thresholds locked by
judge_kfold_validate.py (chosen_thresholds.json). No sweeping, no tuning.

By default only rules with meets_fp_target=true are tested. Pass
--include-unmet to also report rules that could not meet the false-alarm
target on training data (clearly labelled as such) -- deciding that is a
human call, not an automatic fallback.

Per-prompt test scores are written to judge_test_scores.jsonl BEFORE any
metric is computed, so a crash can't lose them and the later combined
(heuristics OR judge) test can reuse them without re-scoring.

Reports confusion matrix, recall (95% Wilson CI), precision, accuracy and
false-alarm rate.

Usage:
  docker compose exec testbed python3 /app/detection/eval_judge/judge_test_validate.py [--include-unmet]
"""
import json
import os
import sys
import time
from math import sqrt

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import judge  # noqa: E402
import judge_scoring  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "jailbreakhub_1000_test.json")
THRESHOLDS_PATH = os.path.join(HERE, "chosen_thresholds.json")
SCORES_OUT = os.path.join(HERE, "judge_test_scores.jsonl")


def wilson_ci(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - a) / d, (c + a) / d)


def main():
    include_unmet = "--include-unmet" in sys.argv
    if not os.path.exists(THRESHOLDS_PATH):
        raise FileNotFoundError("Run judge_kfold_validate.py first (writes chosen_thresholds.json).")
    chosen = json.load(open(THRESHOLDS_PATH))
    to_test = {r: c for r, c in chosen.items() if c["meets_fp_target"] or include_unmet}
    if not to_test:
        print("No rule met the <= 10% false-alarm target on training data, and "
              "--include-unmet was not given. Nothing tested. Test set remains unseen.")
        return

    clf = judge._get_pipeline()
    if clf is None:
        raise RuntimeError("Judge model failed to load -- see testbed logs.")
    data = json.load(open(DATA_PATH, encoding="utf-8"))
    print(f"Scoring {len(data)} LOCKED test prompts (run this once)...")
    t0 = time.time()
    scored = []
    with open(SCORES_OUT, "w") as out:
        for i, row in enumerate(data):
            s = judge_scoring.score_text(row["text"], clf, judge._MAX_LENGTH)
            rec = {"i": i, "label": row["label"], **s}
            scored.append(rec)
            out.write(json.dumps(rec) + "\n")
            if (i + 1) % 100 == 0:
                print(f"  ...{i+1}/{len(data)} ({time.time()-t0:.0f}s)")
    print(f"Done in {time.time()-t0:.0f}s. Saved {SCORES_OUT}\n")

    for rule, c in to_test.items():
        th, field = c["threshold"], c["field"]
        tp = fp = tn = fn = 0
        for r in scored:
            flagged = r[field] >= th
            atk = r["label"] == "attack"
            if flagged and atk: tp += 1
            elif flagged and not atk: fp += 1
            elif not flagged and not atk: tn += 1
            else: fn += 1
        n = tp + fp + tn + fn
        rec_ = tp / (tp + fn) if tp + fn else 0.0
        prec = tp / (tp + fp) if tp + fp else 0.0
        acc = (tp + tn) / n if n else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        lo, hi = wilson_ci(tp, tp + fn)
        tag = "" if c["meets_fp_target"] else "  [DID NOT MEET <=10% FP TARGET ON TRAINING]"
        print(f"=== FINAL RESULT: rule={rule}, T={th} (log-odds){tag} ===")
        print("              Pred: Attack  Pred: Benign")
        print(f"Actual Attack {tp:>12}  {fn:>12}")
        print(f"Actual Benign {fp:>12}  {tn:>12}")
        print(f"\nRecall:     {100*rec_:.1f}%  (95% Wilson CI {100*lo:.1f}%-{100*hi:.1f}%, n={tp+fn} attacks)")
        print(f"Precision:  {100*prec:.1f}%")
        print(f"Accuracy:   {100*acc:.1f}%")
        print(f"FP rate:    {100*fpr:.1f}%\n")


if __name__ == "__main__":
    main()
