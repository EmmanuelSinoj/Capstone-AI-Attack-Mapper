"""
assign_split.py -- assign every answer-key row to 'dev' or 'heldout', once, after the
synthetic alert set is frozen.

Stratified by category and reproducible from the seed. It refuses to run again once splits
exist (re-drawing after seeing results would defeat the purpose) unless --force is given.

Usage (from this folder):
    python assign_split.py [--seed 42] [--dev-fraction 0.4] [--db path/to/alerts.db] [--force]
"""
import argparse
import sys

import db


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Assign the development / held-out split.")
    ap.add_argument("--db", default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dev-fraction", type=float, default=0.4)
    ap.add_argument("--force", action="store_true", help="redraw even if splits already exist")
    a = ap.parse_args(argv)
    conn = db.get_connection(a.db)
    try:
        summary = db.assign_splits(conn, seed=a.seed, dev_fraction=a.dev_fraction, force=a.force)
    except ValueError as exc:
        print(f"not changed: {exc}")
        return 1
    finally:
        conn.close()
    print(f"split assigned (seed {a.seed}, dev fraction {a.dev_fraction}):")
    for cat, (n_dev, n_held) in summary.items():
        print(f"  category {cat}: {n_dev} dev, {n_held} held-out")
    print(f"  total: {sum(d for d, _ in summary.values())} dev, {sum(h for _, h in summary.values())} held-out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
