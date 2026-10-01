"""exact_score_short.py -- run Emmanuel's v5 EXACT patterns only (heuristics.check; fuzzy matcher NOT used) on the
short-prompt sets. Host-side, no GPU. Writes exact_short_scores.jsonl."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "heur_v5"))
from detection import heuristics as h
with open(os.path.join(HERE, "exact_short_scores.jsonl"), "w") as out:
    for name in ("labeled_prompts_500", "stress_prompts"):
        for i, row in enumerate(json.load(open(os.path.join(HERE, name + ".json"), encoding="utf-8"))):
            flagged, matches = h.check(row["text"])
            out.write(json.dumps({"set": name, "i": i, "label": row["label"], "exact": flagged, "matches": matches}) + "\n")
print("wrote exact_short_scores.jsonl")
