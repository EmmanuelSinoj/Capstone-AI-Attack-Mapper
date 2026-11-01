# Synthetic alert expansion v1: 960 additional alerts

This review branch adds **960 hypothetical, source-grounded alerts** (240 each for A, B, C, D). Together with the untouched original 40, the optional combined export contains 1,000 records (250 per category).

These are **48 mechanism/scenario families x 5 fictional deployment contexts x 4 evidence/outcome profiles**, grounded in **44 source groups**: 40 official MITRE ATLAS case studies, FBI/IC3 and Microsoft reports, an OpenAI threat report, and an original research paper. Twenty of those source groups are absent from the original 40-alert set; 24 overlap it. The 960 variants are **not 960 independent cases, incidents, human-reviewed examples, or executed attacks**. The expansion is primarily a robustness and workload corpus.

## Files and compatibility

| File | Purpose |
|---|---|
| `alerts_additional_960.jsonl` | New alerts only; same fields as `synthetic_alerts/alerts_final.jsonl` |
| `alerts_expanded_1000.jsonl` | Optional export: original 40, in original order, then the new 960 |
| `scenarios.json` | Assistant-authored mechanism definitions and proposed taxonomy/mapping labels |
| `build_expansion.py` | Deterministic regeneration; Python standard library, no API calls |
| `export_reviewed_key.py` | Exports only approved label rows after review |
| `test_expansion.py` | Contract, provenance, reference-ID and real-loader checks |

The following files are in `evaluation/synthetic_expansion_v1/` and **must not be mounted into the Mapper container**:

- `ground_truth_draft.json`: all proposed labels, phases, bare framework IDs, rationale/qualifier notes and source URLs, using the existing answer-key field names. **This is a draft answer key, not validated ground truth.**
- `provenance.json`: unique alert IDs, source groups, scenario families, observability profiles, review status, original-set overlap and content hashes.
- `sources.json`: pinned official ATLAS source descriptions, references and relationships; primary-publication URLs and qualified summaries.
- `review_log.csv`: 960 pending review rows; no invented reviewers, dates or approvals.
- `manifest.json`: counts, reference versions, grouping policy and SHA-256 hashes.
- `validation_report.json`: automated results, including known limitations.

Prediction fields, detection fields and **`ground_truth_category` are NULL on every new input row**. This deliberately prevents unreviewed proposals becoming scored truth merely because alerts were loaded. The Mapper must read the existing `mapper_input` view (`id, source, input, output`), not full alert rows or this folder: `scenarios.json` also contains proposed labels. Original input/answer-key files, split assignments and the held-out lock are unchanged.

Every new `source_reference` is unique (`SYNEXP1-0041` through `SYNEXP1-1000`), so the repository's existing unique-index and idempotent-loader contract are preserved. The answer key joins by `source_reference`, not by database row ID. IDs 0041-1000 are dataset ordinals, not assumed SQLite IDs.

## Source fidelity and generated evidence

The source registry distinguishes the source incident/exercise from the new hypothetical exercise. Synthetic deployment details, prevention events, canary data, successful outcomes, and incomplete evidence are authored scenario conditions; they are not asserted to have happened in the cited case or on the capstone testbed. All new answer-key outcomes are `hypothetical`, and `attack_succeeded` is not populated. These records must never be used as live defensive-effectiveness evidence for WBS 7.2.

ATLAS is pinned to the same **2026.09** release used by the project, at official repository commit `f56c1468731d6428e5bf875263b4643b46d67437`. Its retrieved content hash is recorded. The complete upstream descriptions used here are attributed under Apache-2.0; see `NOTICE.md` and `APACHE-2.0.txt`.

The FBI, Microsoft, OpenAI and research-paper entries were read directly. No records were imported from random/public incident databases. Microsoft calls model assistance **likely**, not proven, and reports a blocked phishing campaign. The OpenAI source does not establish autonomous execution. Those qualifications are preserved in the source notes and relevant mechanisms.

All ATT&CK/OWASP cross-mappings and some ATLAS assignments are **analyst proposals**. Source-attested ATLAS relationships are distinguished in `framework_notes`. Bare IDs are validated against the repository's pinned catalogue, including its OWASP 2026 labels; membership does not independently verify semantic correctness or the external catalogue version. Current catalogue IDs are used rather than carrying deprecated IDs into the expansion. Review must check relevance, not only ID existence.

## Load for workload testing

Run from `ai-attack-mapper/`, initially on a **new or disposable database**, not the live v7b database:

```bash
python synthetic_alerts/load_alerts.py --db expansion_sandbox.db --schema alert_store/schema.sql --alerts synthetic_alerts/expansion_v1/alerts_expanded_1000.jsonl
```

For an experimental database copy already containing the original 40, use `alerts_additional_960.jsonl` instead. Running the command twice skips existing source references. The main loader's default remains the original 40-alert file.

Classify for schema robustness, latency, error rate, cost and throughput; report that workload as synthetic and templated. Do not call the results independent classification accuracy. No paid API was used to create or validate this package; classification runs are a separate action.

## Review before classification-accuracy evaluation

1. Review source faithfulness, the proposed category/sub-cluster, phase, mapping IDs, outcome qualifications and label leakage. Resolve disagreements against source evidence. Update draft keys when needed and record corrections.
2. For each approved row, enter `approved`, a real reviewer and date, and `pass` for each review check in the CSV. Automated checks do not constitute this review.
3. Export the approved subset:

```bash
python synthetic_alerts/expansion_v1/export_reviewed_key.py --out evaluation/synthetic_expansion_v1/reviewed_key_v1.json
python alert_store/load_answer_key.py evaluation/synthetic_expansion_v1/reviewed_key_v1.json --db expansion_sandbox.db
```

4. Assign development/evaluation partitions explicitly **by source group**, after deduplication and checking source overlaps. Do not run the existing random row-level `assign_split.py` over this combined corpus. Never move variants of an original development case into a supposedly new held-out set. Existing used held-out cases do not become unseen again through rewording.
5. Report new-source cases, seen-source variants, scenario families and context/outcome profiles separately. Preserve source groups when estimating uncertainty (e.g. group bootstrap); do not use an ordinary binomial interval that assumes 960 independent observations.

Keep the original 40-alert pilot results unchanged. A balanced generated corpus is not evidence of the real-world frequency of its categories. No claim of reliable 1,000-case ground truth is made.

## Rebuild and check

```bash
python synthetic_alerts/expansion_v1/build_expansion.py
python synthetic_alerts/expansion_v1/test_expansion.py
```

The build reads only local definition/source files, writes only the expansion outputs, and never opens a database. The automated tests use temporary SQLite databases and the repository's actual loader/schema. Human review files are regenerated as pending by a rebuild: archive completed review logs and approved keys before regenerating.
