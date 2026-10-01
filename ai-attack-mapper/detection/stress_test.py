"""
stress_test.py -- score one detection version on one labeled dataset.

usage:
    python stress_test.py <version_folder> <threshold | sweep> [dataset.json] [-v]

examples:
    python stress_test.py detection_v4 0.65                      # one threshold, stress set
    python stress_test.py detection_v4 sweep                     # thresholds 0.50 to 0.90, stress set
    python stress_test.py detection_v4 sweep labeled_prompts_500.json
    python stress_test.py detection_v2 0.65 jailbreakhub_short.json

Works for detection_v1 to detection_v4. With no arguments it runs detection_v4 at 0.65
on stress_prompts.json.

Each prompt is scored once. The fuzzy score does not depend on the threshold, so
"sweep" costs the same as a single run: it just counts the results at every
threshold. The "patterns only" row shows what the exact-match patterns catch with
the fuzzy matcher switched off. Use a sweep to LOOK at the trade-off, not to pick
a threshold from the same data you then report.

-v lists the false positives in single-threshold mode.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    sys.stdout.reconfigure(errors="replace")   # unusual characters print as ? instead of crashing
except Exception:
    pass
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
version_dir = os.path.basename(os.path.normpath(_args[0])) if len(_args) > 0 else "detection_v4"
mode = _args[1] if len(_args) > 1 else "0.65"
sweep = mode.lower() == "sweep"
threshold = 0.65 if sweep else float(mode)
dataset = _args[2] if len(_args) > 2 else "stress_prompts.json"

vpath = os.path.join(HERE, version_dir)
sys.path.insert(0, vpath)

# v1 has a flat layout (heuristic_scanner.py, no `detection` package);
# v2/v3/v4 use the nested `detection` package. Support both.
if os.path.exists(os.path.join(vpath, "heuristic_scanner.py")):
    import heuristic_scanner as _v1
    from rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input as _rebuff
    def exact_and_score(text):
        exact = (not _v1._input_regex_scanner.scan(text)[1]) or (not _v1._input_substring_scanner.scan(text)[1])
        return exact, _rebuff(text)
else:
    from detection import heuristics as h
    def exact_and_score(text):
        rx, _ = h.check(text)
        return rx, h.detect_prompt_injection_using_heuristic_on_input(text)

_path = dataset if os.path.exists(dataset) else os.path.join(HERE, dataset)
data = json.load(open(_path, encoding="utf-8"))

# Score every prompt once: (label, words, exact-match flag, fuzzy score, text)
scored = []
for i, row in enumerate(data, 1):
    rx, sc = exact_and_score(row["text"])
    scored.append((row["label"], len(row["text"].split()), rx, sc, row["text"]))
    if i % 10 == 0:
        print(f"  ...scored {i}/{len(data)}", file=sys.stderr, flush=True)

nb = sum(1 for r in scored if r[0] == "benign")
na = len(scored) - nb


def evaluate(th):
    fp, caught = [], 0
    buckets = {"short": {"benign": [0, 0], "attack": [0, 0]}, "long": {"benign": [0, 0], "attack": [0, 0]}}
    for label, w, rx, sc, text in scored:
        flagged = rx or sc >= th
        b = buckets["short" if w <= 100 else "long"][label]
        b[1] += 1
        b[0] += int(flagged)
        if label == "benign" and flagged:
            fp.append((sc, text))
        if label == "attack" and flagged:
            caught += 1
    return fp, caught, buckets


def pct(x, n):
    return f"{100 * x / n:.0f}%" if n else "n/a"


name = os.path.basename(_path)
if sweep:
    print(f"{version_dir} on {name} ({na} attacks, {nb} normal)")
    print(f"{'threshold':<16}{'normal wrongly flagged':>24}{'attacks caught':>18}{'recall':>9}{'precision':>11}")
    rows = [("patterns only", 1.01)] + [(f"{t:.2f}", t) for t in (round(0.5 + 0.05 * i, 2) for i in range(9))]
    for label, th in rows:
        fp, caught, _ = evaluate(th)
        prec = pct(caught, caught + len(fp))
        print(f"{label:<16}{f'{len(fp)} of {nb}':>24}{f'{caught} of {na}':>18}{pct(caught, na):>9}{prec:>11}")
else:
    fp, caught, buckets = evaluate(threshold)
    print(f"{version_dir} @ {threshold} on {name}")
    print(f"  Normal prompts wrongly flagged: {len(fp)} of {nb}")
    print(f"  Attacks caught:                 {caught} of {na}")
    if na and nb:
        print(f"  Recall {100 * caught / na:.1f}%   Precision " +
              (f"{100 * caught / (caught + len(fp)):.1f}%" if caught + len(fp) else "n/a"))
    for label, key in (("up to 100 words", "short"), ("over 100 words", "long")):
        b = buckets[key]
        if b["benign"][1] or b["attack"][1]:
            print(f"    {label:<16} normal flagged {b['benign'][0]}/{b['benign'][1]}, attacks caught {b['attack'][0]}/{b['attack'][1]}")
    if "-v" in sys.argv:
        print("  False positives:")
        for sc, t in fp:
            print(f"    {sc:.3f} | {t[:110]}")
