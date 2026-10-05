"""build_benign_replay_set.py -- merge the benign sources into ONE replay set for the live false-alarm measurement.
Inputs (this folder): benign_replay/benign_new_1170.json (model-written, 14 categories) + support_benign_210.json.
Output: benign_replay/benign_replay_set.json  [{id, category, text, origin}]   (exact duplicates removed)
All messages are MODEL-WRITTEN and only machine-screened; a human must review the flagged rows + a random sample
(see make_review_sheet.py) before any number from this set is cited as evidence."""
import json, os, re, collections
HERE = os.path.dirname(os.path.abspath(__file__)); D = os.path.join(HERE, "benign_replay")
norm = lambda t: re.sub(r"\s+", " ", t.casefold()).strip()
rows, seen = [], set()
for origin, path in (("new_1170", os.path.join(D, "benign_new_1170.json")), ("support_210", os.path.join(HERE, "support_benign_210.json"))):
    for r in json.load(open(path, encoding="utf-8")):
        k = norm(r["text"])
        if k in seen: continue
        seen.add(k); rows.append({"category": r["category"], "text": r["text"], "origin": origin})
for i, r in enumerate(rows): r["id"] = i
json.dump(rows, open(os.path.join(D, "benign_replay_set.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(rows), "messages"); print(dict(collections.Counter(r["category"] for r in rows)))
