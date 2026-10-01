"""
kfold_validate.py -- 5-fold stratified cross-validation on the training split.

Reads the already-scored training data (train_scores_v5_calibration.jsonl,
produced by calibrate_locally.py) and checks how stable a given threshold's
recall/precision is, without needing to re-score anything -- scoring is the
slow part; this just re-slices already-computed scores.

Splits the 700 training prompts into 5 equal, stratified groups (each
keeping the same attack/benign ratio as the whole set). Five rounds, each
one testing on a different group. Averages the five results and reports
the spread between them -- a small spread means the result is stable, a
large one means it's sensitive to which prompts happen to be in the test
slice, and the point estimate alone would be misleading.

The untouched 300-prompt test set is NEVER used here -- this only
validates using the training data, exactly as agreed.

Usage:
    python kfold_validate.py                # default threshold 0.65
    python kfold_validate.py --threshold 0.70
    python kfold_validate.py --folds 10     # more folds, smaller each
"""
import argparse
import json
import os
import random
from math import sqrt

HERE = os.path.dirname(os.path.abspath(__file__))
SCORES_PATH = os.path.join(HERE, "train_scores_v5_calibration.jsonl")


def evaluate(subset, threshold):
    tp = fp = tn = fn = 0
    for r in subset:
        flagged = r["exact"] or r["fuzzy"] >= threshold
        is_attack = r["label"] == "attack"
        if flagged and is_attack: tp += 1
        elif flagged and not is_attack: fp += 1
        elif not flagged and not is_attack: tn += 1
        else: fn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return recall, precision


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threshold", type=float, default=None,
                    help="check only this one threshold (default: sweep all candidate thresholds)")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if not os.path.exists(SCORES_PATH):
        raise FileNotFoundError(
            f"Could not find {SCORES_PATH}. Run calibrate_locally.py first "
            "to produce the scored training data."
        )
    rows = [json.loads(l) for l in open(SCORES_PATH)]
    rows.sort(key=lambda r: r["i"])  # deterministic order regardless of how the
    # scoring file was written -- calibrate_locally.py scores prompts across
    # parallel workers, so rows can land in the file in a different order on
    # different machines/runs even though every prompt's score is identical.
    # Sorting by original index first means the fold split (and therefore each
    # individual fold's numbers) comes out the same everywhere; only the
    # AVERAGE was guaranteed to match before this fix.
    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] == "benign"]

    rng = random.Random(args.seed)
    rng.shuffle(attacks)
    rng.shuffle(benign)

    print(f"Training pool: {len(rows)} prompts ({len(attacks)} attack, {len(benign)} benign)")

    # Build the fold assignment ONCE, then reuse it for every threshold --
    # this is what makes the thresholds comparable to each other: each one
    # is checked against the exact same 5-way split, not a fresh random one.
    folds = [attacks[i::args.folds] + benign[i::args.folds] for i in range(args.folds)]

    thresholds = [args.threshold] if args.threshold is not None else \
        [0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]

    print(f"Folds: {args.folds} | Thresholds: {thresholds}\n")

    print(f"{'Threshold':<11}", end="")
    for i in range(args.folds):
        print(f"{'Fold ' + str(i+1) + ' recall':>14}", end="")
    print(f"{'AVG recall':>13}{'AVG precision':>15}")

    for th in thresholds:
        fold_recalls, fold_precisions = [], []
        for test_fold in folds:
            recall, precision = evaluate(test_fold, th)
            fold_recalls.append(recall)
            fold_precisions.append(precision)
        avg_r = sum(fold_recalls) / args.folds
        avg_p = sum(fold_precisions) / args.folds
        std_r = sqrt(sum((r - avg_r) ** 2 for r in fold_recalls) / args.folds)

        print(f"{th:<11.2f}", end="")
        for r in fold_recalls:
            print(f"{100*r:>13.1f}%", end="")
        print(f"{100*avg_r:>11.1f}%{100*avg_p:>14.1f}%   (+/-{100*std_r:.1f}%)")

    print("\n(Validated on TRAINING data only, same 5-way split reused for every")
    print(" threshold above so they're directly comparable. The untouched")
    print(" 300-prompt test set is checked separately, exactly once, elsewhere,")
    print(" using whichever threshold this sweep supports -- currently 0.65,")
    print(" matching v4.)")


if __name__ == "__main__":
    main()
