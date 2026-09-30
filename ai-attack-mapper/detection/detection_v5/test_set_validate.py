"""
test_set_validate.py -- final, one-time check on the LOCKED 300-prompt
test set, at the threshold already chosen from training data (0.65).

This is deliberately NOT a threshold sweep. The whole point of keeping
this 300-prompt split separate from the 700-prompt training set is that
it never gets used to pick anything -- it only ever confirms a decision
already made elsewhere (see kfold_validate.py, which does the sweeping,
on training data only). Running this file, looking at the result, and
then trying a different threshold here to get a better-looking number
would defeat the entire purpose of having a held-out set.

Scores all 300 prompts fresh (parallelized across CPU cores, same
approach as calibrate_locally.py), applies the single threshold below,
and reports a confusion matrix plus recall/precision/accuracy.

Usage:
    python test_set_validate.py

Needs jailbreakhub_1000_test.json in the same folder as
jailbreakhub_1000_train.json (the shared detection/ root).
"""
import json
import os
import sys
import time
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

THRESHOLD = 0.65  # the value validated in kfold_validate.py; not a free parameter here
DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jailbreakhub_1000_test.json")


def score_one(row):
    from detection import heuristics as h
    rx, _ = h.check(row["text"])
    sc = h.detect_prompt_injection_using_heuristic_on_input(row["text"])
    return {"label": row["label"], "exact": rx, "fuzzy": sc}


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Could not find {DATA_PATH}. jailbreakhub_1000_test.json should "
            "sit at the shared detection/ root, alongside jailbreakhub_1000_train.json."
        )
    data = json.load(open(DATA_PATH, encoding="utf-8"))
    n_workers = cpu_count()
    print(f"Scoring {len(data)} LOCKED test prompts across {n_workers} CPU cores "
          f"(this file is only ever run once per version -- see the note above)...")
    t0 = time.time()
    with Pool(n_workers) as pool:
        results = list(pool.imap(score_one, data, chunksize=4))
    print(f"Done in {time.time()-t0:.0f}s.\n")

    tp = fp = tn = fn = 0
    for row, r in zip(data, results):
        flagged = r["exact"] or r["fuzzy"] >= THRESHOLD
        is_attack = r["label"] == "attack"
        if flagged and is_attack: tp += 1
        elif flagged and not is_attack: fp += 1
        elif not flagged and not is_attack: tn += 1
        else: fn += 1

    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    print(f"FINAL RESULT on the locked test set, threshold={THRESHOLD}")
    print()
    print(f"              Pred: Attack   Pred: Benign")
    print(f"Actual Attack     {tp:>4}          {fn:>4}")
    print(f"Actual Benign     {fp:>4}          {tn:>4}")
    print()
    print(f"Recall:    {100*recall:.1f}%")
    print(f"Precision: {100*precision:.1f}%")
    print(f"Accuracy:  {100*accuracy:.1f}%")


if __name__ == "__main__":
    main()
