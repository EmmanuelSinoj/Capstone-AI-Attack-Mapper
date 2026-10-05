"""rescore_judge.py -- run INSIDE the testbed container (needs the GPU judge).

Scores every DISTINCT prompt in the Alert Store with the live judge (detection.judge.score_prompt,
i.e. the same log-odds the live rule thresholds) and caches the result, so detection_report.py can show
exactly where the judge fires -- including for the ~14k interactions logged BEFORE the log-odds rule existed.
Resumable: re-running only scores prompts missing from the cache.

  docker compose exec testbed python3 /app/detection/reporting/rescore_judge.py
"""
import hashlib, json, os, sqlite3, sys, time
from detection import judge

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "judge_rescore_cache.jsonl")
DB = os.environ.get("ALERT_DB", "/app/alert_store/alerts.db")
key = lambda t: hashlib.sha1(t.encode("utf-8", "replace")).hexdigest()

done = set()
if os.path.exists(CACHE):
    for l in open(CACHE, encoding="utf-8"):
        try: done.add(json.loads(l)["k"])
        except Exception: pass
conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
texts = sorted({r[0] for r in conn.execute("SELECT input FROM alerts")}, key=len)
todo = [t for t in texts if key(t) not in done]
print(f"{len(texts)} distinct prompts, {len(done)} cached, {len(todo)} to score (JUDGE_THRESHOLD={judge.JUDGE_THRESHOLD})")
t0 = time.time(); bad = 0
with open(CACHE, "a", encoding="utf-8") as out:
    for n, t in enumerate(todo, 1):
        s = judge.score_prompt(t)
        if s is None:
            bad += 1; continue
        out.write(json.dumps({"k": key(t), "lo": s[0] if s[0] > -1e8 else -99.0, "p": s[1]}) + "\n")
        if n % 200 == 0:
            out.flush(); print(f"  {n}/{len(todo)}  {n/(time.time()-t0):.1f}/s  failures={bad}", flush=True)
print(f"done. failures={bad}. cache: {CACHE}")
