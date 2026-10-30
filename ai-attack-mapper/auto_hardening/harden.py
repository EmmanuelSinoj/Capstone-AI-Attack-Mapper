#!/usr/bin/env python3
"""harden.py -- Auto-Hardening (v1 Aneeq; v2 Emmanuel, Oct 24: reads gate.py output, clause chosen by probe family or Mapper).

Loop: attacks that still worked against prompt version N  ->  countermeasure clauses per attack family
      ->  stored as a NEW numbered system-prompt version (not activated)  ->  replay old vs new.

  python harden.py --results ../attack_generation/reports/replayv1_<token>.results.jsonl --base 1            # dry run, prints the plan
  python harden.py --results ... --base 1 --apply                                                         # stores the new version via POST /prompts
  python harden.py --results ... --base 1 --apply --llm                                                   # clause text refined by local Ollama (still reviewed by you)

v2 -- harden from the gate's output, so only attacks that passed the gate get a clause:
  python gate.py --db ..\\alert_store\\alerts.db --version 1 --run-like "%20261027%" --out eligible.jsonl [--require-mapper --mapper-run <run>]
  python harden.py --eligible eligible.jsonl --base 1                                                     # clause per probe family (same as v1)
  python harden.py --eligible eligible.jsonl --base 1 --select mapper                                     # clause from the Mapper's ATLAS/OWASP IDs
  --select mapper looks the Mapper's IDs up in technique_map.json and falls back to the probe family, then 'default'.
  It prints how often the two methods agree; check that before relying on it (if the Mapper gives every attack the same IDs,
  it cannot tell countermeasures apart and the probe family should stay the selector).

Design rules (v1):
- Only families with at least one successful attack in --results get a clause; the clause set is deterministic (clauses.json),
  so every change is explainable and reviewable. --llm only rewrites wording of those clauses, never adds new ones.
- Never activates a version. Evaluation = attack_generation/replay_runner.py on the frozen set, old vs new (the printed command).
- Nothing here touches detection (patterns and cutoff are frozen).
- Limit: a clause that blocks a trigger string is not proof of a safer model; replay grading is by trigger substring.
"""
import argparse, collections, json, pathlib, sys, urllib.request

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import clause_select as cs  # noqa: E402
TESTBED = "http://localhost:8000"
OLLAMA = "http://localhost:11434"


def http(method, url, body=None, timeout=200):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def load_results(path):
    rs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    return [r for r in rs if r.get("ok")]


def clause_for(family, clauses):
    key = cs.probe_key(family, clauses) or "default"
    return key, clauses[key]


def load_eligible(path, base):
    """Rows from gate.py --out for one prompt version."""
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    keep = [r for r in rows if r.get("version") == base]
    if not keep:
        found = sorted({str(r.get("version")) for r in rows})
        sys.exit(f"no eligible rows for version {base} in {path} (versions present: {', '.join(found) or 'none'})")
    return keep


def llm_refine(clause, examples):
    prompt = ("Rewrite this system-prompt rule so it is short, firm and unambiguous. Keep its meaning. "
              "Do not add new rules. Output only the rule text.\n\nRULE:\n" + clause +
              "\n\nATTACKS IT MUST STOP (for context only):\n" + "\n---\n".join(e[:300] for e in examples[:2]))
    out = http("POST", OLLAMA + "/api/generate", {"model": "llama3:8b", "prompt": prompt, "stream": False})["response"].strip()
    return out if 20 <= len(out) <= 600 else clause


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--results", help="v1 input: replayv<N>_<round>.results.jsonl from replay_runner.py")
    src.add_argument("--eligible", help="v2 input: eligible.jsonl written by gate.py --out")
    ap.add_argument("--select", choices=["probe", "mapper"], default="probe", help="how a clause is chosen (mapper needs --eligible)")
    ap.add_argument("--base", type=int, required=True, help="system-prompt version those results came from")
    ap.add_argument("--min-successes", type=int, default=1)
    ap.add_argument("--apply", action="store_true", help="store the new version (default: dry run)")
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--set", default="replay_sets/replay_set_v6-trial.json")
    a = ap.parse_args()

    clauses = cs.load_clauses()
    if a.select == "mapper" and not a.eligible:
        sys.exit("--select mapper needs --eligible (the Mapper's IDs come from gate.py --out)")
    chosen, summary = [], {}
    if a.results:
        rs = [r for r in load_results(a.results) if r.get("version") == a.base]
        if not rs:
            sys.exit(f"no usable rows for version {a.base} in {a.results}")
        tot, win, ex = collections.Counter(), collections.Counter(), collections.defaultdict(list)
        for r in rs:
            tot[r["family"]] += 1
            if r["success"]:
                win[r["family"]] += 1; ex[r["family"]].append(r["prompt"])
        print(f"baseline v{a.base}: {sum(win.values())}/{len(rs)} attacks succeeded")
        for fam in sorted(win, key=lambda f: -win[f]):
            if win[fam] < a.min_successes: continue
            key, text = clause_for(fam, clauses)
            if a.llm: text = llm_refine(text, ex[fam])
            print(f"  {fam}: {win[fam]}/{tot[fam]} succeeded -> clause '{key}'")
            if text not in [c[1] for c in chosen]: chosen.append((key, text))
        summary = {"families": {f: [win[f], tot[f]] for f in win}}
    else:
        rules = cs.load_technique_map()
        rs = load_eligible(a.eligible, a.base)
        per, ex, how, agree = collections.Counter(), collections.defaultdict(list), collections.Counter(), collections.Counter()
        fams = collections.defaultdict(collections.Counter)
        for r in rs:
            ids = cs.parse_ids(r.get("mapper_atlas")) + cs.parse_ids(r.get("mapper_owasp"))
            key, via = cs.select(r["family"], ids, a.select, clauses, rules)
            per[key] += 1; ex[key].append(r["prompt"]); fams[key][r["family"]] += 1
            how[via.split(":")[0].split(" ")[0]] += 1
            mk = cs.mapper_key(ids, rules)[0]
            pk = cs.probe_key(r["family"], clauses) or "default"
            agree["no Mapper ID in technique_map" if mk is None else ("same clause" if mk == pk else "different clause")] += 1
        print(f"v{a.base}: {len(rs)} eligible attacks from {a.eligible}, clause chosen by '{a.select}'")
        print("  chosen via: " + ", ".join(f"{k} {v}" for k, v in how.most_common()))
        print("  probe family vs Mapper mapping: " + ", ".join(f"{k} {v}" for k, v in agree.most_common()))
        for key in sorted(per, key=lambda k: -per[k]):
            if per[key] < a.min_successes: continue
            text = clauses[key]
            if a.llm: text = llm_refine(text, ex[key])
            top = ", ".join(f"{f} {n}" for f, n in fams[key].most_common(3))
            print(f"  clause '{key}': {per[key]} attacks ({top})")
            if text not in [c[1] for c in chosen]: chosen.append((key, text))
        summary = {"clause_counts": dict(per), "chosen_via": dict(how), "agreement": dict(agree)}
    if not chosen:
        sys.exit("nothing succeeded; no clause needed")

    path = HERE.parent / "testbed" / "prompts" / f"system_prompt_v{a.base}.txt"
    base = "".join(l for l in open(path, encoding="utf-8") if not l.startswith("# version:")).strip()
    new = base + "\n\n" + "\n".join(f"{i}. {t}" for i, (_, t) in enumerate(chosen, 1))
    print("\n--- proposed system prompt ---\n" + new + "\n------------------------------")
    if not a.apply:
        print("dry run: nothing stored. Re-run with --apply to store as a new version."); return
    res = http("POST", TESTBED + "/prompts", {"text": new, "activate": False})
    v = res["version"]
    log = HERE / "history.jsonl"
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"base": a.base, "new": v, **summary, "clauses": [k for k, _ in chosen], "select": a.select,
                             "llm": a.llm, "source": a.results or a.eligible}) + "\n")
    print(f"stored as version {v} (not activated). Evaluate old vs new:")
    print(f"  cd ../attack_generation && python replay_runner.py --set {a.set} --versions {a.base},{v} --repeats 3 --new-round")


if __name__ == "__main__":
    main()
