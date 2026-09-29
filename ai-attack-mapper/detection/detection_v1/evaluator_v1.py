import json
import logging
import os
try:                                   # silence LLM Guard's per-prompt debug lines
    import structlog
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
except Exception:
    pass
import heuristic_scanner as _v1
from rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input as raw_rebuff_score

# Resolve the shared prompt list relative to THIS script's location, not
# the current working directory -- so this runs correctly whether you
# call it as `python evaluator_v1.py` from inside detection_v1/, or as
# `python detection_v1/evaluator_v1.py` from the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "..", "labeled_prompts_500.json")

CANDIDATE_THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]


def get_raw_scores(data):
    scored = []
    for row in data:
        exact_flagged = ((not _v1._input_regex_scanner.scan(row["text"])[1])
                         or (not _v1._input_substring_scanner.scan(row["text"])[1]))
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
    with open(DATA_PATH, encoding="utf-8") as f:
        data = json.load(f)

    print(f"Loaded {len(data)} prompts from {DATA_PATH}")
    print("All prompts are used as the test set (no train/test split): nothing is fitted to them.\n")

    scored = get_raw_scores(data)

    print("=== V1 (Emmanuel's original: LLM Guard Regex+BanSubstrings+Rebuff) ===")
    print("=== Threshold sweep on all prompts ===")
    print(f"{'Thresh':>7} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7}")
    results = [evaluate_at_threshold(scored, t) for t in CANDIDATE_THRESHOLDS]
    for r in results:
        print(f"{r['threshold']:>7.2f} {r['tp']:>4} {r['fp']:>4} {r['tn']:>4} {r['fn']:>4} "
              f"{r['precision']:>7.3f} {r['recall']:>7.3f} {r['f1']:>7.3f}")

    at65 = evaluate_at_threshold(scored, 0.65)
    print(f"\nResult at the fixed threshold 0.65: TP={at65['tp']} FP={at65['fp']} TN={at65['tn']} FN={at65['fn']} "
          f"precision={at65['precision']:.3f} recall={at65['recall']:.3f} f1={at65['f1']:.3f}")

    benign_scores = [r["rebuff_score"] for r in scored if r["label"] == "benign"]
    attack_scores_missed = [r["rebuff_score"] for r in scored if r["label"] == "attack" and not r["exact_flagged"]]
    print(f"\nHighest benign score: {max(benign_scores):.3f}")
    print(f"Lowest attack score (not caught by regex/substring): {min(attack_scores_missed):.3f}")

    zero_attacks = [r for r in scored if r["label"] == "attack" and r["rebuff_score"] == 0 and not r["exact_flagged"]]
    print(f"\n=== Zero-score attacks (all prompts) ===")
    for r in zero_attacks:
        print(f"  {r['category']:<20} | {r['text']}")
    print(f"Total: {len(zero_attacks)}")


if __name__ == "__main__":
    main()
