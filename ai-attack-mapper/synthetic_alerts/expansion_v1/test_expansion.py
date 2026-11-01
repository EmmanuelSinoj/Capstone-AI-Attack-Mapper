"""Data-contract and integration tests; no API calls and no live database access."""
import csv
import hashlib
import importlib.util
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EVAL = ROOT/'evaluation'/'synthetic_expansion_v1'
read = lambda p: json.loads(p.read_text(encoding='utf-8'))
lines = lambda p: [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]


class ExpansionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = lines(HERE/'alerts_additional_960.jsonl')
        cls.keys = read(EVAL/'ground_truth_draft.json')
        cls.provenance = read(EVAL/'provenance.json')
        cls.manifest = read(EVAL/'manifest.json')

    def test_counts_balance_and_original_preservation(self):
        original = lines(ROOT/'synthetic_alerts/alerts_final.jsonl')
        combined = lines(HERE/'alerts_expanded_1000.jsonl')
        self.assertEqual(len(self.rows), 960)
        self.assertEqual(len(combined), 1000)
        self.assertEqual(combined[:40], original)
        self.assertEqual(Counter(k['category'] for k in self.keys), dict.fromkeys('ABCD',240))
        self.assertEqual(set(Counter(x['scenario_family'] for x in self.provenance).values()), {20})

    def test_schema_and_no_prediction_or_ground_truth_leak(self):
        original = lines(ROOT/'synthetic_alerts/alerts_final.jsonl')[0]
        for row in self.rows:
            self.assertEqual(set(row), set(original))
            for field in ['category','ground_truth_category','lifecycle_phase','atlas_technique',
                          'attck_technique','owasp_category','rationale','classification_confidence',
                          'detector','confidence','probe_id','playbook']:
                self.assertIsNone(row[field])
            self.assertEqual(row['hardening_applied'],0)
            self.assertTrue(row['input'].startswith('This hypothetical alert'))
            self.assertNotRegex(row['input']+row['output'],r'AML\.(?:T|CS)\d|SYNEXP1-\d|\bLLM\d{2}\b')

    def test_unique_text_and_provenance(self):
        self.assertEqual(len({r['source_reference'] for r in self.rows}),960)
        self.assertEqual(len({(r['input'],r['output']) for r in self.rows}),960)
        for row,key,p in zip(self.rows,self.keys,self.provenance):
            self.assertEqual(row['source_reference'],key['source_reference'])
            self.assertEqual(row['source_reference'],p['source_reference'])
            self.assertEqual(p['human_review_status'],'pending')
            self.assertIsNone(p['split'])
            self.assertFalse(p['executed_on_live_testbed'])
            self.assertEqual(p['input_output_sha256'],hashlib.sha256((row['input']+'\n'+row['output']).encode()).hexdigest())

    def test_framework_ids_and_taxonomy_values(self):
        refs=read(ROOT/'mapper/data/framework_reference_data.json')
        prompt=(ROOT/'mapper/prompt.py').read_text(encoding='utf-8')
        for k in self.keys:
            self.assertIn('"'+k['sub_cluster']+'"',prompt)
            self.assertIn('"'+k['phase']+'"',prompt)
            for group,ids in [('atlas',[k['atlas_technique_primary']]+k['atlas_techniques_supporting']),
                              ('attack',k['attck_techniques']),('owasp_llm',k['owasp_llm_2026'])]:
                for identifier in ids:
                    self.assertIn(identifier,refs[group])
                    self.assertIn(identifier,k['framework_notes'])

    def test_verified_source_registry_and_pending_reviews(self):
        sources=read(EVAL/'sources.json')
        self.assertEqual(len(sources),44)
        self.assertEqual(sum(x.startswith('AML.CS') for x in sources),40)
        for p in self.provenance:
            self.assertIn(p['source_id'],sources)
            if p['source_overlaps_original_40']:
                self.assertEqual(p['evaluation_use'],'robustness_only')
        with (EVAL/'review_log.csv').open(newline='',encoding='utf-8') as f:
            reviews=list(csv.DictReader(f))
        self.assertEqual(len(reviews),960)
        self.assertTrue(all(r['review_status']=='pending' and not r['reviewer'] for r in reviews))

    def test_file_hashes(self):
        for name,digest in self.manifest['sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest,name)

    def test_existing_loader_and_mapper_view(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/'test.db'
            command=[sys.executable,str(ROOT/'synthetic_alerts/load_alerts.py'),'--db',str(db),
                     '--schema',str(ROOT/'alert_store/schema.sql')]
            subprocess.run(command,check=True,capture_output=True)
            conn=sqlite3.connect(db)
            old=conn.execute('SELECT source_reference,ground_truth_category FROM alerts ORDER BY id').fetchall()
            conn.close()
            command+=['--alerts',str(HERE/'alerts_additional_960.jsonl')]
            subprocess.run(command,check=True,capture_output=True)
            second=subprocess.run(command,check=True,capture_output=True,text=True)
            self.assertIn('inserted 0, skipped 960',second.stdout)
            conn=sqlite3.connect(db)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1000)
            self.assertEqual(conn.execute('SELECT source_reference,ground_truth_category FROM alerts ORDER BY id LIMIT 40').fetchall(),old)
            self.assertEqual([r[1] for r in conn.execute('PRAGMA table_info(mapper_input)')],['id','source','input','output'])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts WHERE source_reference LIKE 'SYNEXP1-%' AND ground_truth_category IS NOT NULL").fetchone()[0],0)
            conn.close()

    def test_review_export_refuses_pending_and_allows_approved_subset(self):
        spec=importlib.util.spec_from_file_location('review_export',HERE/'export_reviewed_key.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'approved.json'
            with self.assertRaises(ValueError): module.export(EVAL/'review_log.csv',EVAL/'ground_truth_draft.json',out)
            self.assertFalse(out.exists())
            with (EVAL/'review_log.csv').open(newline='',encoding='utf-8') as f: r=next(csv.DictReader(f))
            r.update(review_status='approved',reviewer='fixture reviewer',review_date='2026-11-01')
            for name in module.CHECKS:r[name]='pass'
            log=Path(td)/'review.csv'
            with log.open('w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=list(r));w.writeheader();w.writerow(r)
            self.assertEqual(module.export(log,EVAL/'ground_truth_draft.json',out),1)
            self.assertEqual(len(read(out)),1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
