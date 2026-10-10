"""
load_answer_key.py -- fill the answer_key table from ground_truth_final.json.

Each key is matched to its alert by source_reference, so run this AFTER the synthetic alerts
are loaded (load_alerts.py). Safe to repeat: a key that already exists is left alone unless
--overwrite is given.

Usage (from this folder):
    python load_answer_key.py ground_truth_final.json [--db path/to/alerts.db] [--overwrite]
"""
import argparse
import json
import sys

import db


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Load the full answer key into the alert store.")
    ap.add_argument("ground_truth", help="path to ground_truth_final.json")
    ap.add_argument("--db", default=None, help="alerts.db to use (default: the shared one next to db.py)")
    ap.add_argument("--overwrite", action="store_true", help="replace keys that already exist")
    a = ap.parse_args(argv)
    with open(a.ground_truth, encoding="utf-8") as fh:
        keys = json.load(fh)
    conn = db.get_connection(a.db)
    written = skipped = missing = 0
    for key in keys:
        row = conn.execute("SELECT id FROM alerts WHERE source_reference = ?", (key["source_reference"],)).fetchone()
        if row is None:
            missing += 1
            continue
        if db.save_answer_key(conn, row["id"], key, overwrite=a.overwrite):
            written += 1
        else:
            skipped += 1
    conn.close()
    print(f"answer keys: {written} written, {skipped} already present, {missing} with no matching alert"
          + (" (load the alerts first)" if missing else ""))
    return 0 if (written or skipped) else 1


if __name__ == "__main__":
    sys.exit(main())
