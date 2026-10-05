"""build_label_audit.py -- builds a BLIND labeling sheet (100 JailbreakHub TRAINING prompts) so teammates can estimate how noisy the
dataset's attack/benign labels are. Sampled from the TRAIN split only (keeps the spent test set out of it), seed 7, in four cells:
  40 dataset-'benign' that the judge flags (lo>=9.0)  -> the 'false alarms' we want to audit
  20 dataset-'benign' the judge does NOT flag
  20 dataset-'attack' the judge flags
  20 dataset-'attack' the judge misses
Labelers see ONLY the prompt text (no dataset label, no judge verdict, no cell). Rows are shuffled. The key stays separate."""
import csv, json, os, random
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "..", "label_audit")
data = json.load(open(os.path.join(HERE, "jailbreakhub_1000_train.json"), encoding="utf-8"))
J = {r["i"]: r for r in map(json.loads, open(os.path.join(HERE, "judge_train_scores_v2.jsonl")))}
cells = {("benign", True): 40, ("benign", False): 20, ("attack", True): 20, ("attack", False): 20}
rng = random.Random(7); picked = []
for (lab, flagged), n in cells.items():
    pool = [i for i in sorted(J) if J[i]["label"] == lab and (J[i]["lo_jailbreak"] >= 9.0) == flagged]
    for i in rng.sample(pool, n): picked.append((i, lab, flagged))
rng.shuffle(picked)
os.makedirs(OUT, exist_ok=True)
hdr = ["id", "prompt_text", "LABEL (ATTACK_CLEAR / ATTACK_BORDERLINE / NOT_ATTACK / UNSURE)", "what_is_it_trying_to_do (short)", "notes"]
for who in ("A", "B"):
    with open(os.path.join(OUT, f"labeling_sheet_{who}.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(hdr)
        for n, (i, _, _) in enumerate(picked, 1): w.writerow([f"P{n:03d}", data[i]["text"], "", "", ""])
with open(os.path.join(OUT, "audit_key_DO_NOT_SHARE.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["id", "train_index", "dataset_label", "judge_flagged_T9.0", "judge_log_odds"])
    for n, (i, lab, fl) in enumerate(picked, 1): w.writerow([f"P{n:03d}", i, lab, fl, f"{J[i]['lo_jailbreak']:.2f}"])
print("wrote sheets for", len(picked), "prompts to", os.path.abspath(OUT))
