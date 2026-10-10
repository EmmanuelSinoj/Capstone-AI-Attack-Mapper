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


## Update (Oct 5): the detector's flag and the Mapper's call are kept apart
- **Problem found:** the first version of this update let the Mapper write its category into `category`, the
  same column the live logger fills with `'B'` when it flags an interaction. The Mapper's answer overwrote the
  detector's flag, and an "out of scope" answer set the column to NULL, so a flagged alert looked unflagged.
- **Fix:** new columns `predicted_category` (the Mapper's call) and `classified_at` (the Mapper has run). `save_classification()`
  and `update_alert_classification()` now write there and never touch `category`. The `evaluation_truth` view
  reads `predicted_category`. New helper `db.get_mapper_queue()`.
- **No change to the detection logger:** it keeps writing `category = 'B'` when it flags an interaction.
- **Existing databases:** the two new columns are added automatically on the next connection. Existing rows keep
  their `category` values; `predicted_category` starts empty.
- **Also in this version:** the column upgrade tolerates several simultaneous first requests (it used to fail with
  "duplicate column name" for some of them right after a restart).


## Update v3 (Oct 6): what the Mapper pilot and the evaluation need
- **`mapper_results` table:** every Mapper run is stored on its own row, so the local-versus-Claude pilot and the repeat runs
  can be compared and nothing is overwritten. Unusable replies are kept as invalid rows with the raw reply, so JSON reliability can be measured.
- **`answer_key` table:** the full answer key (sub-cluster, phase, framework IDs, scope and attacker flags, outcome, case type) and the
  `split` column. `alerts.ground_truth_category` is still filled and still protected.
- **Views:** `evaluation_truth` keeps its first nine columns and gains the key columns. New `mapper_scores` gives per-run correctness flags.
- **Helpers:** `save_mapper_result`, `get_mapper_results`, `save_answer_key`, `assign_splits`; scripts `load_answer_key.py` and `assign_split.py`.
- **Safer upgrades:** the database records a schema version; whenever it is older than the code, the views are re-created. (`CREATE VIEW IF NOT EXISTS`
  never replaces an old definition, which is how an out-of-date evaluation view could survive.)
- **Tested:** 22 checks pass, including the real ground truth (19 keys), a 33,000-row database upgraded in about 25 ms with every row and flag kept, and
  20 trials of 8 simultaneous first requests with no errors. Later connections cost under a millisecond.
- **Not changed:** the `alerts` columns, the detection logger, Aneeq's scripts, `mapper_input`.
