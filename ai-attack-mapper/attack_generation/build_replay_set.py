#!/usr/bin/env python3
"""build_replay_set.py -- freeze a set of attacks that WORKED, to replay against different system-prompt versions.

  python build_replay_set.py --prefix garak_run_20261004T164802Z --prefix garak_run_20261004T172406Z --per-probe 20 --name v6-trial
  python build_replay_set.py ... --paraphrases replay_sets/paraphrases_v6-trial.json     # adds reworded variants (NFR7)

Source: Garak hit logs in reports/ (an attack "worked" = Garak's detector fired on at least one generation). Only attacks
whose Garak record carries trigger strings are kept, because those can be re-graded exactly (reply contains a trigger,
case-insensitive, which is Garak's own rule for these probes); the rest are counted and skipped. Selection is stratified:
up to --per-probe prompts per probe class, seeded (42), so the same inputs give the same set.
Paraphrase file: {"<item id>": ["reworded prompt", ...]} ; paraphrases inherit the parent's triggers, so they must still
ask for the same trigger text. Output: replay_sets/replay_set_<name>.json"""
import argparse, collections, glob, json, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "reports")


def ptext(p):
    try: return p["turns"][-1]["content"]["text"]
    except Exception: return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prefix", action="append", required=True, help="Garak report prefix in reports/ (no extension); repeatable.")
    ap.add_argument("--per-probe", type=int, default=20)
    ap.add_argument("--name", required=True)
    ap.add_argument("--paraphrases", default=None)
    a = ap.parse_args()

    attempts = collections.Counter(); hits = {}; skipped = collections.Counter()
    for pre in a.prefix:
        base = os.path.join(REPORTS, os.path.basename(pre.replace("\\", "/")))
        for l in open(base + ".report.jsonl", encoding="utf-8"):
            try: d = json.loads(l)
            except ValueError: continue
            if d.get("entry_type") == "attempt":
                t = ptext(d.get("prompt")); 
                if t: attempts[t] += 1
        hl = base + ".hitlog.jsonl"
        if not os.path.exists(hl): print(f"NOTE: no hit log for {pre}"); continue
        for l in open(hl, encoding="utf-8"):
            try: d = json.loads(l)
            except ValueError: continue
            t = ptext(d.get("prompt"))
            if not t: continue
            trig = [x for x in (d.get("triggers") or []) if isinstance(x, str) and x.strip()]
            if not trig: skipped[d.get("probe", "?")] += 1; continue
            h = hits.setdefault(t, {"family": d.get("probe", "?"), "triggers": trig, "hits": 0, "source": pre})
            h["hits"] += 1
    by_probe = collections.defaultdict(list)
    for t, h in hits.items(): by_probe[h["family"]].append(t)
    rng = random.Random(42); items = []
    for fam in sorted(by_probe):
        pool = sorted(by_probe[fam]); rng.shuffle(pool)
        for t in pool[: a.per_probe]:
            h = hits[t]
            items.append({"id": "", "text": t, "family": fam, "triggers": h["triggers"], "variant": "original", "parent": None,
                          "source": h["source"], "orig_hits": h["hits"], "orig_attempts": attempts[t]})
    for n, it in enumerate(items, 1): it["id"] = f"r{n:03d}"
    para = json.load(open(a.paraphrases, encoding="utf-8")) if a.paraphrases else {}
    extra = []
    for it in items:
        for k, txt in enumerate(para.get(it["id"], []), 1):
            if txt and txt.strip() and txt.strip() != it["text"].strip():
                extra.append({**it, "id": f"{it['id']}p{k}", "text": txt, "variant": "paraphrase", "parent": it["id"]})
    out = os.path.join(HERE, "replay_sets", f"replay_set_{a.name}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(items + extra, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"{len(hits)} distinct successful prompts with triggers; kept {len(items)} originals (<= {a.per_probe}/probe) + {len(extra)} paraphrases -> {out}")
    for fam in sorted(by_probe): print(f"  {fam:<40} available {len(by_probe[fam]):>4}  kept {min(len(by_probe[fam]), a.per_probe):>3}")
    if skipped: print("  skipped (no trigger strings, cannot be re-graded exactly):", dict(skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
