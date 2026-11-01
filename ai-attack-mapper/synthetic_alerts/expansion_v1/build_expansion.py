"""Rebuild 960 hypothetical alerts from reviewed-source scenario definitions.

Standard library only. No network access, API calls, model inference, or database writes.
Run from any directory: python synthetic_alerts/expansion_v1/build_expansion.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EVAL = ROOT / 'evaluation' / 'synthetic_expansion_v1'
VERSION = 'synthetic-expansion-v1'
BASE_COMMIT = '9d987ceb5b1ee96472b1765363baa93ec0cffab1'

CONTEXTS = [
    ('finance', 'a financial-services test tenant', 'the account administrator', 'simulated account records'),
    ('health', 'a health-services training environment', 'the application owner', 'fictional service records'),
    ('education', 'a university research sandbox', 'the lab operator', 'synthetic research records'),
    ('engineering', 'an engineering organisation\u2019s isolated test environment', 'the platform operator', 'dummy project records'),
    ('public_service', 'a public-service tabletop environment', 'the security coordinator', 'fabricated administrative records'),
]
PROFILES = ['confirmed_in_scenario', 'blocked_in_scenario', 'outcome_unknown', 'partial_evidence']


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def narrative(s, context, profile):
    _, tenant, operator, records = context
    setup = (f'This hypothetical alert concerns {tenant}. It is a constructed scenario, '
             f'not a claim about a newly observed incident. {records.capitalize()} and '
             'non-production credentials are used where the scenario requires data. ')
    core = s['mechanism']
    if profile == 'confirmed_in_scenario':
        evidence = (f'The scenario packet combines the initiating activity with a corresponding '
                    f'application or endpoint observation. {operator.capitalize()} has both '
                    'sides of the transaction available for review.')
        outcome = f'The constructed outcome is that {s["effect"]}. The packet links the effect to the initiating action; this is stipulated synthetic evidence, not a measured production outcome.'
    elif profile == 'blocked_in_scenario':
        evidence = (f'The scenario packet includes the initiating activity and a prevention record. '
                    f'{operator.capitalize()} is asked to distinguish attacker intent from a '
                    'completed compromise; the presence of the attempt does not establish success.')
        outcome = f'The constructed outcome is that {s["block"]}. The record describes a blocked attempt and must not be interpreted as a completed compromise.'
    elif profile == 'outcome_unknown':
        evidence = (f'{operator.capitalize()} receives the initiating activity but lacks the final '
                    'application response, endpoint result, or destination-side record. The '
                    'available material describes intent and the attempted mechanism only.')
        outcome = (f'The intended effect is that {s["effect"]}. The final result is not supplied. '
                   'Neither success nor prevention can be established from this packet.')
    else:
        evidence = (f'The scenario packet contains an intermediate observation but no complete '
                    f'chain to the intended effect. {operator.capitalize()} has requested '
                    'correlation with the missing final-stage record.')
        outcome = (f'The initiating action and part of its processing are present, but the packet '
                   f'does not establish that {s["effect"]}. The outcome remains partially observed; '
                   'a completed compromise must not be inferred.')
    return setup + core + ' ' + evidence, 'Hypothetical scenario outcome: ' + outcome


def build():
    scenarios = json.loads((HERE / 'scenarios.json').read_text(encoding='utf-8'))
    sources = json.loads((EVAL / 'sources.json').read_text(encoding='utf-8'))
    original_path = ROOT / 'synthetic_alerts' / 'alerts_final.jsonl'
    original = [json.loads(x) for x in original_path.read_text(encoding='utf-8').splitlines() if x.strip()]
    original_keys = json.loads((ROOT / 'evaluation' / 'ground_truth_final.json').read_text(encoding='utf-8'))
    original_sources = {x['case_id'] for x in original_keys}
    # The report IDs in the original key refer to the same publications.
    original_sources |= {'FBI-2025-0515', 'MS-2025-0924', 'OPENAI-SCOPECREEP'}
    catalog = json.loads((ROOT / 'mapper/data/framework_reference_data.json').read_text(encoding='utf-8'))
    rows, keys, provenance, reviews = [], [], [], []
    allowed_fields = set(original[0])
    assert len(original) == 40 and len(scenarios) == 48
    for s in scenarios:
        source = sources[s['source']]
        for context in CONTEXTS:
            for profile in PROFILES:
                ordinal = 41 + len(rows)
                alert_id = f'SYNEXP1-{ordinal:04d}'
                ref = f'{alert_id} | mechanism adapted from {s["source"]} | {VERSION}'
                inp, out = narrative(s, context, profile)
                row = {k: None for k in original[0]}
                row.update(source='synthetic', input=inp, output=out, source_reference=ref,
                           hardening_applied=0, ground_truth_category=None)
                assert set(row) == allowed_fields
                rows.append(row)
                notes = {}
                official = set(source.get('official_atlas_relationships', []))
                for identifier in [s['atlas'], *s['support']]:
                    notes[identifier] = ('Present in the source case\u2019s ATLAS relationships; relevance to this adapted scenario is proposed.'
                                         if identifier in official else 'Analyst-proposed mapping for the adapted mechanism; not an explicit source-case annotation.')
                for identifier in [*s['attack'], *s['owasp']]:
                    notes[identifier] = 'Analyst-proposed mapping using the project\u2019s pinned reference catalogue; requires independent review.'
                keys.append({
                    'case_id': alert_id, 'case_name': source['title'] + ' / synthetic adaptation',
                    'case_type': 'Exercise', 'source_url': source['url'], 'source_reference': ref,
                    'category': s['category'], 'sub_cluster': s['sub'], 'phase': s['phase'],
                    'outcome_status': 'hypothetical', 'atlas_technique_primary': s['atlas'],
                    'atlas_techniques_supporting': s['support'], 'attck_techniques': s['attack'],
                    'owasp_llm_2026': s['owasp'], 'framework_notes': notes,
                    'in_scope': True, 'non_adversarial': s.get('non_adversarial', False),
                    'label_note': ('DRAFT / NOT HUMAN-VERIFIED. Classify the described attack intent, not whether it succeeded. '
                                   'Labels follow the frozen project taxonomy. No actual attack was executed. '
                                   f'Parent source {s["source"]}; scenario family {s["id"]}; observability {profile}.')
                })
                provenance.append({
                    'alert_id': alert_id, 'source_reference': ref, 'source_id': s['source'],
                    'source_url': source['url'], 'scenario_family': s['id'],
                    'source_group': s['source'], 'context': context[0], 'observability': profile,
                    'proposed_category': s['category'], 'proposed_sub_cluster': s['sub'],
                    'intended_effect': s['effect'], 'blocked_effect': s['block'],
                    'generation_method': 'assistant-authored mechanism plus deterministic context/outcome expansion',
                    'generator_version': VERSION, 'human_review_status': 'pending',
                    'source_overlaps_original_40': s['source'] in original_sources,
                    'evaluation_use': 'robustness_only' if s['source'] in original_sources else 'new_source_review_candidate',
                    'split': None, 'executed_on_live_testbed': False,
                    'input_output_sha256': hashlib.sha256((inp + '\n' + out).encode()).hexdigest()
                })
                reviews.append({'alert_id': alert_id, 'source_reference': ref, 'source_group': s['source'],
                                'review_status': 'pending', 'reviewer': '', 'review_date': '',
                                'source_faithfulness': '', 'category_correct': '', 'sub_cluster_correct': '',
                                'phase_correct': '', 'framework_ids_correct': '', 'outcome_wording_correct': '',
                                'label_leakage_check': '', 'notes': ''})
    assert len(rows) == 960 and Counter(x['category'] for x in keys) == dict.fromkeys('ABCD', 240)
    for path, records in [(HERE/'alerts_additional_960.jsonl', rows),
                          (HERE/'alerts_expanded_1000.jsonl', original + rows)]:
        path.write_text(''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in records), encoding='utf-8')
    dump(EVAL/'ground_truth_draft.json', keys)
    dump(EVAL/'provenance.json', provenance)
    with (EVAL/'review_log.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(reviews[0])); writer.writeheader(); writer.writerows(reviews)
    case_groups = Counter(x['source_group'] for x in provenance)
    manifest = {
        'dataset_version': VERSION, 'created_date': '2026-11-01', 'base_repository_commit': BASE_COMMIT,
        'original_alerts': 40, 'additional_alerts': 960, 'combined_alerts': 1000,
        'additional_per_category': dict(Counter(x['category'] for x in keys)),
        'scenario_families': 48, 'source_groups': len(case_groups),
        'official_atlas_case_studies': sum(x.startswith('AML.CS') for x in sources),
        'primary_reports_and_papers': sum(not x.startswith('AML.CS') for x in sources),
        'contexts_per_family': 5, 'outcome_profiles_per_context': 4,
        'source_group_sizes': dict(case_groups),
        'new_source_group_count': len({x['source_group'] for x in provenance if not x['source_overlaps_original_40']}),
        'all_new_labels_human_reviewed': False, 'live_attacks_executed': False,
        'default_use': 'synthetic robustness and workload testing; accuracy evaluation requires independent label review',
        'sampling_warning': '960 related variants are not 960 independent incidents. Source groups and scenario families must be preserved in evaluation.',
        'heldout_policy': 'No automatic split. Keep source families together; original heldout set and lock remain unchanged.',
        'framework_reference_versions': catalog.get('versions'),
        'source_access': 'Official MITRE ATLAS pinned data and directly inspected primary publications; no third-party dataset imports.',
        'sha256': {}
    }
    for path in [HERE/'scenarios.json', HERE/'build_expansion.py', original_path,
                 ROOT/'evaluation/ground_truth_final.json', ROOT/'mapper/prompt.py',
                 ROOT/'mapper/data/framework_reference_data.json', HERE/'alerts_additional_960.jsonl',
                 HERE/'alerts_expanded_1000.jsonl', EVAL/'ground_truth_draft.json', EVAL/'provenance.json',
                 EVAL/'sources.json', EVAL/'review_log.csv']:
        manifest['sha256'][str(path.relative_to(ROOT))] = sha(path)
    dump(EVAL/'manifest.json', manifest)
    print(json.dumps({k: manifest[k] for k in ['additional_alerts','combined_alerts','additional_per_category','source_groups','new_source_group_count']}, indent=2))


if __name__ == '__main__':
    build()
