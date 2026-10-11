"""Load the finalized synthetic ATLAS alerts into the shared alert store.

Usage:
    python3 load_alerts.py --db path/to/alerts.db --schema path/to/alert_store/schema.sql

Creates the table from schema.sql if needed, then inserts each row of
alerts_final.jsonl. Re-running is safe: rows whose source_reference is
already in the table are skipped.
"""
import argparse, json, sqlite3
from pathlib import Path

HERE = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--alerts", default=str(HERE / "alerts_final.jsonl"))
    a = ap.parse_args()

    conn = sqlite3.connect(a.db)
    conn.executescript(Path(a.schema).read_text(encoding="utf-8"))
    added = skipped = 0
    for line in Path(a.alerts).read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if conn.execute("SELECT 1 FROM alerts WHERE source_reference = ?",
                        (row["source_reference"],)).fetchone():
            skipped += 1
            continue
        cols = ", ".join(row)
        conn.execute(f"INSERT INTO alerts ({cols}) VALUES ({', '.join('?' for _ in row)})",
                     tuple(row.values()))
        added += 1
    conn.commit()
    conn.close()
    print(f"inserted {added}, skipped {skipped} already present")


if __name__ == "__main__":
    main()
