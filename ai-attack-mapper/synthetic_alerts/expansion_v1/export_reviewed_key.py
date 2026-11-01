"""Export only independently approved draft keys; never change a database.

python synthetic_alerts/expansion_v1/export_reviewed_key.py --out reviewed_key.json
"""
import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / 'evaluation' / 'synthetic_expansion_v1'
CHECKS = ['source_faithfulness', 'category_correct', 'sub_cluster_correct', 'phase_correct',
          'framework_ids_correct', 'outcome_wording_correct', 'label_leakage_check']


def export(review_log, draft_key, out):
    keys = json.loads(Path(draft_key).read_text(encoding='utf-8'))
    with Path(review_log).open(encoding='utf-8', newline='') as f:
        reviews = list(csv.DictReader(f))
    if len({r['alert_id'] for r in reviews}) != len(reviews):
        raise ValueError('Duplicate review IDs; no key exported')
    by_id = {k['case_id']: k for k in keys}
    selected = []
    for r in reviews:
        if r['review_status'].strip().lower() != 'approved':
            continue
        if not r['reviewer'].strip() or not r['review_date'].strip():
            raise ValueError(f'{r["alert_id"]}: approval needs a reviewer and review date')
        if any(r[c].strip().lower() != 'pass' for c in CHECKS):
            raise ValueError(f'{r["alert_id"]}: every review check must be pass')
        if r['alert_id'] not in by_id or r['source_reference'] != by_id[r['alert_id']]['source_reference']:
            raise ValueError('Review/source-reference mismatch')
        k = dict(by_id[r['alert_id']])
        k['label_note'] = (f'Approved by {r["reviewer"]} on {r["review_date"]}. '
                           'Hypothetical source-grounded scenario, not an executed attack. ' + r['notes'])
        selected.append(k)
    if not selected:
        raise ValueError('No approved keys. Pending labels cannot be promoted to ground truth.')
    target = Path(out)
    if target.resolve() == Path(draft_key).resolve():
        raise ValueError('Keep the draft key unchanged; choose a separate output file')
    if target.exists():
        raise ValueError('Output exists; choose a new output path')
    target.write_text(json.dumps(selected, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    return len(selected)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--review-log', default=str(EVAL/'review_log.csv'))
    ap.add_argument('--draft-key', default=str(EVAL/'ground_truth_draft.json'))
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    try:
        print(f'Exported {export(a.review_log, a.draft_key, a.out)} reviewed keys')
    except ValueError as error:
        ap.exit(1, str(error)+'\n')
