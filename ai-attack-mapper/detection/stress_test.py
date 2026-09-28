"""
stress_test.py -- usage:  python stress_test.py <version_folder> <threshold>   (works for v1-v4)
e.g.  python stress_test.py detection_v4 0.65

Runs one version against stress_prompts.json (natural benign prompts using
risky verbs like "act as / tell me / show me", plus attack phrasings that
were NOT taken from the 500-prompt templates or from any version's phrase
lists). Kept separate from labeled_prompts_500.json on purpose, so the
three-way comparison on the 500 stays fair.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
version_dir, threshold = sys.argv[1], float(sys.argv[2])
vpath = os.path.join(HERE, version_dir)
sys.path.insert(0, vpath)

# v1 has a flat layout (heuristic_scanner.py, no `detection` package);
# v2/v3/v4 use the nested `detection` package. Support both.
if os.path.exists(os.path.join(vpath, "heuristic_scanner.py")):
    from heuristic_scanner import scan_input
    from rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input as _rebuff
    def exact_and_score(text):
        r = scan_input(text)
        return any(m in ("regex", "substring") for m in r["matched_by"]), _rebuff(text)
else:
    from detection import heuristics as h
    def exact_and_score(text):
        rx, _ = h.check(text)
        return rx, h.detect_prompt_injection_using_heuristic_on_input(text)

data = json.load(open(os.path.join(HERE, "stress_prompts.json")))
fp, caught, missed = [], [], []
for row in data:
    rx, s = exact_and_score(row["text"])
    flagged = rx or s >= threshold
    if row["label"] == "benign" and flagged: fp.append((s, row["text"]))
    if row["label"] == "attack":
        (caught if flagged else missed).append((s, row["text"]))
nb = sum(r["label"] == "benign" for r in data); na = len(data) - nb
print(f"{version_dir} @ {threshold}")
print(f"  Normal prompts wrongly flagged: {len(fp)} of {nb}")
print(f"  Novel attacks caught:           {len(caught)} of {na}")
if "-v" in sys.argv:
    print("  False positives:"); [print(f"    {s:.3f} | {t}") for s, t in fp]
