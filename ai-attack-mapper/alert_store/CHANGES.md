# Alert store update -- what changed and who needs to do what

## What changed
1. **One table definition.** `schema.sql` is the only one; `alert_schema.py` no longer
   defines its own (older, 11-column) table. `alert_store.init_db()` now uses it too.
2. **Answer key kept away from the Mapper.** New `mapper_input` view (id, source, input,
   output) and `db.get_mapper_input()` and `alert_store.query_mapper_input()`. `query_alerts()` and `get_alert_by_id()` no longer return
   `ground_truth_category` / `source_reference` unless asked (`include_ground_truth=True`).
   `update_alert()` refuses to change them without `allow_protected=True`.
3. **Classification goes to the right columns.** `update_alert_classification()` used to
   overwrite the detector's `confidence` with the Mapper's; it now writes
   `classification_confidence`. New `db.save_classification(conn, id, mapper_json)`.
4. **New columns:** `sub_cluster`, `in_scope`, `adversarial` (Mapper output fields that
   had no home). New view `evaluation_truth` for the evaluation scripts.
5. **Constraints (new databases):** `category` and `ground_truth_category` must be A-E or
   NULL; flags must be 0/1; `source_reference` is unique.
6. **Old databases upgrade themselves** (columns added, or table rebuilt with rows kept).
7. `Alert` gained optional `probe_id` and `source_reference` (added at the end, so
   existing calls keep working). `alert_store.insert_alert` now stores `probe_id`.
8. UTF-8 explicit on every file read. README and test rewritten (15 checks).

## Who needs to do what
- **Everyone:** pull, then run `python3 db.py` once on your local alerts.db (or delete it).
- **Aneeq (live logger):** category must now be a code A-E; live prompt injection is **B**,
  not free text and not C. Pass `probe_id` / `run_id` / `attack_succeeded` where you have them.
- **Mapper / pilot harness:** read with `get_mapper_input()` only; write with `save_classification()`.
- **Shadi (evaluation):** read with `get_ground_truth()`. `load_alerts.py` is unchanged and works.
- **Old behaviour you might have relied on:** `query_alerts()` returning every column;
  `update_alert_classification()` writing `confidence`.

## Not changed
- `load_alerts.py` and the alerts data.
- The Mapper prompt (the CS0072 C-vs-D rule still has to be settled there).
