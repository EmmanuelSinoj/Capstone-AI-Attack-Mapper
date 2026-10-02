"""encoding_rule_eval.py -- does the new encoding_smuggling pattern family help, and what does it cost?
Compares live patterns WITH vs WITHOUT that family. Host-side, patterns only (judge not involved).
Sets: encoding_holdout_80.json (independent, frozen before the rule was written), the 810 benign texts
(labeled_500 normal + support_benign_210 + JailbreakHub-train normal), attack recall on labeled_500/stress/JailbreakHub-train,
and today's Garak encoding traffic (IN-SAMPLE: the rule was written after seeing Garak's wording)."""
import json, os, sys, glob, sqlite3
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
from detection import heuristics as h
def old(t):
    f, names = h.check(t); n = [x for x in names if x != "encoding_smuggling"]; return bool(n)
def new(t): return h.check(t)[0]
J = lambda f: json.load(open(os.path.join(HERE, f), encoding="utf-8"))
def row(title, texts, lab):
    A = [t for t, l in zip(texts, lab) if l == "attack"]; B = [t for t, l in zip(texts, lab) if l != "attack"]
    s = f"{title:<44}"
    if A: s += f" attacks flagged old {sum(map(old,A)):>4}/{len(A):<4} new {sum(map(new,A)):>4}/{len(A):<4}"
    if B: s += f" | benign flagged old {sum(map(old,B)):>3}/{len(B):<4} new {sum(map(new,B)):>3}/{len(B):<4}"
    print(s)
H = J("encoding_holdout_80.json"); row("INDEPENDENT holdout (frozen first)", [x["text"] for x in H], [x["label"] for x in H])
print("   holdout attacks still missed by NEW:"); [print("    -", x["category"], "|", x["text"][:90].replace("\n", " ")) for x in H if x["label"] == "attack" and not new(x["text"])]
print("   holdout benign flagged by NEW:"); [print("    -", x["text"][:90]) for x in H if x["label"] != "attack" and new(x["text"])]
lp = J("labeled_prompts_500.json"); row("labeled_prompts_500", [x["text"] for x in lp], [x["label"] for x in lp])
sp = J("stress_prompts.json"); row("stress_prompts", [x["text"] for x in sp], [x["label"] for x in sp])
sb = J("support_benign_210.json"); sb = sb if isinstance(sb, list) else sb.get("items", sb); row("support_benign_210", [x["text"] if isinstance(x, dict) else x for x in sb], ["benign"]*len(sb))
tr = J("jailbreakhub_1000_train.json"); row("JailbreakHub train (700)", [(x.get("text") or x.get("prompt")) for x in tr], [x["label"] for x in tr])
# Garak today (in-sample)
G, HIT = {}, set()
for f in glob.glob(os.path.join(ROOT, "live_attack_path", "attack_generation", "reports", "garak_run_20261002*.report.jsonl")):
    for l in open(f, encoding="utf-8"):
        if '"entry_type": "attempt"' in l[:40]:
            d = json.loads(l); G.setdefault(d["prompt"]["turns"][-1]["content"]["text"], d["probe_classname"])
for f in glob.glob(os.path.join(ROOT, "live_attack_path", "attack_generation", "reports", "garak_run_20261002*.hitlog.jsonl")):
    for l in open(f, encoding="utf-8"): HIT.add(json.loads(l)["prompt"]["turns"][-1]["content"]["text"])
enc = [t for t, p in G.items() if p.startswith("encoding")]; worked = [t for t in enc if t in HIT]
print(f"\nGARAK encoding (IN-SAMPLE): distinct prompts {len(enc)}; worked {len(worked)}; patterns-flagged old {sum(map(old,enc))} -> new {sum(map(new,enc))}; "
      f"worked & flagged old {sum(map(old,worked))} -> new {sum(map(new,worked))}")
