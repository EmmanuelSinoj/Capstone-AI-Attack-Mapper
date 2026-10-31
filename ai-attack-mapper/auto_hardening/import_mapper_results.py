#!/usr/bin/env python3
"""import_mapper_results.py -- copy a Mapper run's rows into the live alerts.db, keyed by alert_id.

  python import_mapper_results.py --src mapper_results_<run>.db --db alerts.db --expect-run garak_20261027_v6-2            # dry run
  python import_mapper_results.py --src ... --db ... --expect-run garak_20261027_v6-2 --apply                              # writes

What it does (and nothing else):
  * reads the Mapper results database READ-ONLY (table mapper_results);
  * checks that every alert_id exists in --db and belongs to --expect-run (so rows cannot land on the wrong alerts),
    that all rows are one run_id, and that every source column exists in the destination;
  * with --apply: first makes a SQLite backup of --db next to it (alerts.db.bak-pre-mapper-import-<run>), then inserts the rows
    WITHOUT the source id column (the destination assigns its own), INSERT OR IGNORE on (alert_id, run_id, repeat_no),
    in one transaction, and prints before/after counts. Nothing in the alerts table is touched.
Stdlib only. Never deletes anything.
"""
import argparse, sqlite3, sys, pathlib


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, help="Mapper results .db (table mapper_results)")
    ap.add_argument("--db", required=True, help="the alerts.db to import into")
    ap.add_argument("--expect-run", required=True, help="run_id of the alerts the Mapper classified, e.g. garak_20261027_v6-2")
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    a = ap.parse_args()

    src = sqlite3.connect(f"file:{pathlib.Path(a.src).resolve().as_posix()}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    rows = src.execute("SELECT * FROM mapper_results").fetchall()
    if not rows:
        sys.exit("source has no rows")
    cols = [c for c in rows[0].keys() if c != "id"]
    runs = {r["run_id"] for r in rows}
    if len(runs) != 1:
        sys.exit(f"expected one run_id in the source, found {sorted(runs)}")
    run = runs.pop()
    ids = [r["alert_id"] for r in rows]
    print(f"source: {len(rows)} rows, run_id {run}, {len(set(ids))} distinct alert_ids, {sum(1 for r in rows if r['valid_json'])} valid")

    dst = sqlite3.connect(f"file:{pathlib.Path(a.db).resolve().as_posix()}?mode={'rw' if a.apply else 'ro'}", uri=True, timeout=60)
    dcols = {r[1] for r in dst.execute("PRAGMA table_info(mapper_results)")}
    if not dcols:
        sys.exit("destination has no mapper_results table")
    missing = [c for c in cols if c not in dcols]
    if missing:
        sys.exit(f"destination mapper_results lacks columns: {missing}")
    have = {r[0]: r[1] for r in dst.execute(
        f"SELECT id, run_id FROM alerts WHERE id IN ({','.join('?' * len(ids))})", ids)}
    absent = [i for i in ids if i not in have]
    wrong = [i for i in ids if i in have and have[i] != a.expect_run]
    if absent or wrong:
        sys.exit(f"REFUSED: {len(absent)} alert_ids not in the destination, {len(wrong)} belong to another run_id "
                 f"(expected {a.expect_run}). Examples: {absent[:5]} {wrong[:5]}")
    before = dst.execute("SELECT COUNT(*) FROM mapper_results WHERE run_id = ?", (run,)).fetchone()[0]
    print(f"destination: all {len(ids)} alert_ids exist and belong to {a.expect_run}; mapper_results rows for this run before: {before}")
    if not a.apply:
        print("dry run: nothing written. Re-run with --apply.")
        return

    bak = pathlib.Path(a.db).with_name(pathlib.Path(a.db).name + f".bak-pre-mapper-import-{run}")
    if bak.exists():
        sys.exit(f"backup already exists: {bak}")
    b = sqlite3.connect(bak)
    dst.backup(b)
    b.close()
    print(f"backup written: {bak}")
    sql = f"INSERT OR IGNORE INTO mapper_results ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
    with dst:
        dst.executemany(sql, [tuple(r[c] for c in cols) for r in rows])
    after = dst.execute("SELECT COUNT(*) FROM mapper_results WHERE run_id = ?", (run,)).fetchone()[0]
    total = dst.execute("SELECT COUNT(*) FROM mapper_results").fetchone()[0]
    print(f"imported: mapper_results rows for {run}: {before} -> {after} (table total {total}); integrity: "
          f"{dst.execute('PRAGMA integrity_check').fetchone()[0]}")
    dst.close()


if __name__ == "__main__":
    main()
