"""dan_overlap.py -- how many Garak dan.DanInTheWild prompts also appear in our 1,000 JailbreakHub files (700 train, 300 locked test).
Exact = identical text; normalised = same after lower-casing and collapsing whitespace/punctuation; contained = one text inside the other
(normalised); near = Jaccard of word 5-gram shingles >= 0.8. Run from anywhere:  python3 dan_overlap.py"""
import glob, json, os, re, collections
HERE = os.path.dirname(os.path.abspath(__file__))
REP = os.path.abspath(os.path.join(HERE, "..", "..", "attack_generation", "reports"))
norm = lambda t: re.sub(r"[^a-z0-9]+", " ", t.lower()).strip()
def shingles(t, k=5):
    w = norm(t).split(); return {" ".join(w[i:i+k]) for i in range(max(1, len(w)-k+1))}
dan = {}
for f in sorted(glob.glob(os.path.join(REP, "*.report.jsonl"))):
    for l in open(f, encoding="utf-8"):
        if '"entry_type": "attempt"' not in l[:40]: continue
        try: d = json.loads(l)
        except ValueError: continue
        if d.get("probe_classname") == "dan.DanInTheWild":
            try: dan.setdefault(d["prompt"]["turns"][-1]["content"]["text"], os.path.basename(f)[:25])
            except Exception: pass
jh = []
for split in ("train", "test"):
    for r in json.load(open(os.path.join(HERE, f"jailbreakhub_1000_{split}.json"), encoding="utf-8")): jh.append({**r, "split": split})
print(f"Garak dan.DanInTheWild: {len(dan)} distinct prompts (from {len(set(dan.values()))} runs); JailbreakHub files: {len(jh)} prompts")
jn = [(norm(r["text"]), r) for r in jh]; jset = [shingles(r["text"]) for r in jh]
hit = collections.defaultdict(list)
for t in dan:
    nt = norm(t); st = shingles(t); kind = None; match = None
    for (n2, r), s2 in zip(jn, jset):
        if t == r["text"]: kind, match = "exact", r; break
        if nt == n2: kind, match = "normalised", r; break
    if not kind:
        for (n2, r), s2 in zip(jn, jset):
            if len(n2) > 60 and len(nt) > 60 and (n2 in nt or nt in n2): kind, match = "contained", r; break
    if not kind:
        for (n2, r), s2 in zip(jn, jset):
            u = len(st | s2)
            if u and len(st & s2) / u >= 0.8: kind, match = "near", r; break
    if kind: hit[kind].append((t, match))
tot = sum(len(v) for v in hit.values())
print(f"overlap: {tot}/{len(dan)} = {100*tot/len(dan):.0f}%  " + ", ".join(f"{k} {len(v)}" for k, v in hit.items()))
c = collections.Counter((m["split"], m["label"]) for v in hit.values() for _, m in v)
for (sp, lb), n in sorted(c.items()): print(f"  matches a JailbreakHub {sp} prompt labelled {lb}: {n}")
