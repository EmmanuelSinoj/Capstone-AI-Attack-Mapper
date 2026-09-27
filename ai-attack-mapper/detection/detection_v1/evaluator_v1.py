import json
import os
from collections import defaultdict
from heuristic_scanner import scan_input
from rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input as raw_rebuff_score

# Resolve the shared prompt list relative to THIS script's location, not
# the current working directory -- so this runs correctly whether you
# call it as `python evaluator_v1.py` from inside detection_v1/, or as
# `python detection_v1/evaluator_v1.py` from the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "..", "labeled_prompts_500.json")

CANDIDATE_THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]


def stratified_split(data, train_frac, seed=42):
    import random
    rng = random.Random(seed)
    by_label = defaultdict(list)
    for row in data:
        by_label[row["label"]].append(row)
    train, test = [], []
    for label, rows in by_label.items():
        rows = rows[:]
        rng.shuffle(rows)
        cut = int(len(rows) * train_frac)
        train.extend(rows[:cut])
        test.extend(rows[cut:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def get_raw_scores(data):
    scored = []
    for row in data:
        r = scan_input(row["text"])
        exact_flagged = any(m in ("regex", "substring") for m in r["matched_by"])
        rebuff_score = raw_rebuff_score(row["text"])
        scored.append({**row, "exact_flagged": exact_flagged, "rebuff_score": rebuff_score})
    return scored


def evaluate_at_threshold(scored_data, threshold):
    tp = fp = tn = fn = 0
    for row in scored_data:
        flagged = row["exact_flagged"] or (row["rebuff_score"] >= threshold)
        is_attack = row["label"] == "attack"
        if flagged and is_attack: tp += 1
        elif flagged and not is_attack: fp += 1
        elif not flagged and not is_attack: tn += 1
        else: fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Could not find labeled_prompts_500.json at {DATA_PATH}. "
            "This file should sit one level up from this script (at the "
            "repo's detection/ root), shared across all three versions."
        )
    with open(DATA_PATH) as f:
        data = json.load(f)

    train, test = stratified_split(data, 0.70)
    print(f"Loaded {len(data)} prompts from {DATA_PATH}")
    print(f"Split: {len(train)} tuning / {len(test)} held-out test\n")

    train_scored = get_raw_scores(train)
    test_scored = get_raw_scores(test)

    print("=== V1 (Emmanuel's original: LLM Guard Regex+BanSubstrings+Rebuff) ===")
    print("=== Threshold sweep on TUNING split ===")
    print(f"{'Thresh':>7} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7}")
    results = [evaluate_at_threshold(train_scored, t) for t in CANDIDATE_THRESHOLDS]
    for r in results:
        print(f"{r['threshold']:>7.2f} {r['tp']:>4} {r['fp']:>4} {r['tn']:>4} {r['fn']:>4} "
              f"{r['precision']:>7.3f} {r['recall']:>7.3f} {r['f1']:>7.3f}")

    best = max(results, key=lambda r: r["f1"])
    print(f"\nBest by F1: threshold={best['threshold']:.2f}")

    final = evaluate_at_threshold(test_scored, best["threshold"])
    print(f"HELD-OUT test at that threshold: precision={final['precision']:.3f} "
          f"recall={final['recall']:.3f} f1={final['f1']:.3f}")

    at65 = evaluate_at_threshold(test_scored, 0.65)
    print(f"\nHELD-OUT test at threshold=0.65: precision={at65['precision']:.3f} recall={at65['recall']:.3f}")

    benign_scores = [r["rebuff_score"] for r in train_scored if r["label"] == "benign"]
    attack_scores_missed = [r["rebuff_score"] for r in train_scored if r["label"] == "attack" and not r["exact_flagged"]]
    print(f"\nHighest benign score: {max(benign_scores):.3f}")
    print(f"Lowest attack score (not caught by regex/substring): {min(attack_scores_missed):.3f}")

    zero_attacks = [r for r in test_scored if r["label"] == "attack" and r["rebuff_score"] == 0 and not r["exact_flagged"]]
    print(f"\n=== Zero-score attacks in held-out test ===")
    for r in zero_attacks:
        print(f"  {r['category']:<20} | {r['text']}")
    print(f"Total: {len(zero_attacks)}")


if __name__ == "__main__":
    main()
