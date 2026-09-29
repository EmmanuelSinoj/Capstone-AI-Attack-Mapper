"""
calibrate_locally.py (parallel version)

Same as the sequential version, but scores prompts across multiple CPU
cores at once using multiprocessing. Each prompt's score is completely
independent of every other prompt, so this produces IDENTICAL results to
the sequential version, just faster -- nothing about the detection logic
changes, only how many prompts get scored at the same time.

Speedup depends on how many CPU cores your machine has. Check with:
    import multiprocessing; print(multiprocessing.cpu_count())
A typical laptop (4-8 cores) should see roughly a 3-6x speedup over the
sequential version, not a full Nx, since there's some overhead in
splitting work across processes.

Run from inside the v5/ folder, same as before:
    python calibrate_locally.py
"""
import json, os, sys, time
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jailbreakhub_1000_train.json")
OUT_PATH = "train_scores_v5_calibration.jsonl"


def score_one(args):
    # Imported inside the worker function, not at module level -- each
    # worker process needs its own import, this is required for
    # multiprocessing to work correctly on Windows.
    from detection import heuristics as h
    i, row = args
    rx, _ = h.check(row["text"])
    sc = h.detect_prompt_injection_using_heuristic_on_input(row["text"])
    return {"i": i, "label": row["label"], "exact": rx, "fuzzy": sc, "words": len(row["text"].split())}


def main():
    data = json.load(open(DATA_PATH, encoding="utf-8"))
    done = set()
    if os.path.exists(OUT_PATH):
        done = {json.loads(l)["i"] for l in open(OUT_PATH)}
        print(f"Resuming: {len(done)} of {len(data)} already scored.")

    todo = [(i, row) for i, row in enumerate(data) if i not in done]
    if not todo:
        print("Already fully scored.")
    else:
        n_workers = cpu_count()
        print(f"Scoring {len(todo)} prompts across {n_workers} CPU cores...")
        t0 = time.time()
        with open(OUT_PATH, "a") as out:
            with Pool(n_workers) as pool:
                for n, result in enumerate(pool.imap_unordered(score_one, todo, chunksize=4), 1):
                    out.write(json.dumps(result) + "\n")
                    out.flush()
                    if n % 20 == 0:
                        elapsed = time.time() - t0
                        rate = n / elapsed
                        eta = (len(todo) - n) / rate if rate > 0 else 0
                        print(f"  ...{n}/{len(todo)}  ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)")
        print(f"\nDone in {time.time()-t0:.0f}s.")

    print("\nCalibrating thresholds per word-count band...\n")
    rows = [json.loads(l) for l in open(OUT_PATH)]
    bins = [(0, 50), (50, 150), (150, 10**9)]
    for lo, hi in bins:
        b = [r for r in rows if lo <= r["words"] < hi]
        ben = [r for r in b if r["label"] == "benign"]
        atk = [r for r in b if r["label"] == "attack"]
        print(f"{lo}-{hi if hi < 10**9 else '+'} words  (n={len(ben)} benign, {len(atk)} attack)")
        print(f"  {'threshold':<10}{'FP rate':>10}{'recall':>10}")
        for th in (0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90):
            fp = sum(1 for r in ben if r["exact"] or r["fuzzy"] >= th)
            tp = sum(1 for r in atk if r["exact"] or r["fuzzy"] >= th)
            fp_rate = 100 * fp / len(ben) if ben else 0
            tp_rate = 100 * tp / len(atk) if atk else 0
            print(f"  {th:<10.2f}{fp_rate:>9.1f}%{tp_rate:>9.1f}%")
        print()


if __name__ == "__main__":
    main()
