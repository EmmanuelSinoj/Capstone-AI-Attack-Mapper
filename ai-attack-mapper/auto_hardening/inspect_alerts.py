#!/usr/bin/env python3
"""inspect_alerts.py -- READ-ONLY survey of alerts.db: what is logged, how to tell attack rows from benign rows, and how
each column is filled. Answers the "how do live alerts look" questions with counts instead of memory.

  python inspect_alerts.py --db ..\\alert_store\\alerts.db
  python inspect_alerts.py --db ..\\alert_store\\alerts.db --samples 3      # also print a few example rows per traffic kind

Opens the database with mode=ro; nothing is changed. 'Traffic kind' is a guess from the run_id text before its first digit
(for example replayv, utilv, garak_run_) so rows from different tools separate; rows with no run_id are one kind.
Paste the whole output back; it contains alert text only when --samples is used (prompts are cut to 80 characters).
Stdlib only."""
import argparse, collections, pathlib, re, sqlite3, sys


def kind(run_id):
    if not run_id:
        return "(no run_id)"
    k = re.sub(r"\d.*$", "", str(run_id)).strip("_- ")
    return k or "(numeric run_id)"


def blank(v):
    return v is None or str(v).strip() == ""


def show(title, counter, limit=15):
    print(f"\n{title}")
    for k, v in counter.most_common(limit):
        print(f"  {v:7d}  {k}")
    if len(counter) > limit:
        print(f"  ... {len(counter) - limit} more")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--table", default="alerts")
    ap.add_argument("--samples", type=int, default=0)
    a = ap.parse_args()

    con = sqlite3.connect("file:" + pathlib.Path(a.db).resolve().as_posix() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")]
    print("tables and views:", tables)
    cols = [r["name"] for r in con.execute(f"PRAGMA table_info({a.table})")]
    if not cols:
        sys.exit(f"table '{a.table}' not found")
    print(f"\n{a.table} columns ({len(cols)}): {cols}")
    rows = con.execute(f"SELECT * FROM {a.table}").fetchall()
    print(f"rows: {len(rows)}")
    if not rows:
        return

    def g(r, c):
        return r[c] if c in cols else None

    # 1/2: what is logged, and how attack rows differ from benign rows
    by_kind = collections.Counter(kind(g(r, "run_id")) for r in rows)
    show("traffic kinds (run_id text before its first digit)", by_kind)
    print("\nper traffic kind: rows | probe_id filled | attack_succeeded NULL / 0 / 1 | category filled | system_prompt_version filled")
    for k in by_kind:
        rs = [r for r in rows if kind(g(r, "run_id")) == k]
        n = len(rs)
        pid = sum(1 for r in rs if not blank(g(r, "probe_id")))
        a_null = sum(1 for r in rs if g(r, "attack_succeeded") is None)
        a0 = sum(1 for r in rs if g(r, "attack_succeeded") in (0, "0", False))
        a1 = sum(1 for r in rs if g(r, "attack_succeeded") in (1, "1", True))
        cat = sum(1 for r in rs if not blank(g(r, "category")))
        spv = sum(1 for r in rs if not blank(g(r, "system_prompt_version")))
        print(f"  {k:24s} {n:7d} | probe_id {pid:6d} | succeeded NULL {a_null:6d} / 0 {a0:6d} / 1 {a1:6d} | category {cat:6d} | version {spv:6d}")

    pid_kind = collections.defaultdict(collections.Counter)
    for r in rows:
        p = g(r, "probe_id")
        pid_kind[kind(g(r, "run_id"))][(str(p).split(".")[0] if not blank(p) else "(null)")] += 1
    print("\nprobe_id prefix per traffic kind (the part before the first dot):")
    for k, c in pid_kind.items():
        print(f"  {k:24s} {dict(c.most_common(8))}")

    # 3: how a row is filled in
    show("category values", collections.Counter(str(g(r, "category")) for r in rows))
    show("detector values (the detector's name)", collections.Counter(str(g(r, "detector")) for r in rows), 20)
    if "detector" in cols and "category" in cols:
        cross = collections.Counter((str(g(r, "detector")), str(g(r, "category"))) for r in rows)
        show("detector x category (is 'B' set whenever a detector fired? what happens on judge:unavailable?)", cross, 25)
    unavailable = [r for r in rows if "unavailable" in str(g(r, "detector")).lower() or "unavailable" in str(g(r, "rationale") or "").lower()]
    print(f"\nrows mentioning 'unavailable' in detector or rationale: {len(unavailable)}"
          + (f"; their category values: {dict(collections.Counter(str(g(r, 'category')) for r in unavailable))}" if unavailable else ""))
    show("system_prompt_version values", collections.Counter(str(g(r, "system_prompt_version")) for r in rows))

    # Mapper columns
    for c in ("predicted_category", "classification_confidence", "classified_at"):
        if c in cols:
            print(f"\n{c}: filled in {sum(1 for r in rows if not blank(g(r, c)))} of {len(rows)} rows")
    if "predicted_category" in cols:
        show("predicted_category values", collections.Counter(str(g(r, "predicted_category")) for r in rows))
    if "mapper_results" in tables:
        n = con.execute("SELECT COUNT(*) FROM mapper_results").fetchone()[0]
        print(f"\nmapper_results table: {n} rows")

    # 4: the candidate Mapper filter
    flagged = lambda r: not blank(g(r, "category"))
    succ = lambda r: g(r, "attack_succeeded") in (1, "1", True)
    tool = lambda r: not blank(g(r, "probe_id"))
    print("\nfilter check: rows that match each part of 'flagged OR succeeded OR from an attack tool':")
    print(f"  flagged {sum(1 for r in rows if flagged(r))}, succeeded {sum(1 for r in rows if succ(r))}, with probe_id {sum(1 for r in rows if tool(r))}, "
          f"any of the three {sum(1 for r in rows if flagged(r) or succ(r) or tool(r))}, none of the three {sum(1 for r in rows if not (flagged(r) or succ(r) or tool(r)))}")
    miss = [r for r in rows if tool(r) and not flagged(r) and not succ(r)]
    print(f"  attack-tool rows that failed AND were not flagged (the case the filter might drop): {len(miss)}")

    if a.samples:
        for k in by_kind:
            print(f"\nsample rows, kind '{k}':")
            for r in [r for r in rows if kind(g(r, 'run_id')) == k][: a.samples]:
                print("  ", {c: (str(g(r, c))[:80] if c == 'input' else g(r, c)) for c in ("run_id", "probe_id", "category", "detector", "attack_succeeded", "system_prompt_version", "input") if c in cols})


if __name__ == "__main__":
    main()
