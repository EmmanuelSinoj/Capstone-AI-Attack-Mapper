-- AI Attack Mapper -- Shared Alert Store schema.
--
-- THE single definition of the alerts table. alert_schema.py, alert_store.py
-- and db.py all read this file; none of them defines the table separately.
--
-- Both the Live Attack Path and the Synthetic Alert Path write to this
-- single table so the classification engine treats live and synthetic
-- alerts identically. See Design section of the Capstone Group document
-- and docs/architecture.md for the full data-flow diagram.
--
-- Changes in this version (see CHANGES.md):
--   * new columns sub_cluster, in_scope, adversarial, predicted_category, classified_at (Mapper output fields
--     that previously had nowhere to be stored)
--   * CHECK constraints on category / ground_truth_category (A-E or NULL)
--     and on the 0/1 flags -- these apply to NEW databases only; rebuild
--     an old alerts.db to get them (SQLite cannot add CHECKs to a table
--     that already exists)
--   * unique index on source_reference (synthetic alerts load once)
--   * views: mapper_input (what the Mapper may read) and evaluation_truth
--     (what the evaluation scripts may read)

CREATE TABLE IF NOT EXISTS alerts (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    source                  TEXT NOT NULL CHECK (source IN ('live', 'synthetic')),

    -- Raw interaction (live: testbed prompt/response; synthetic: the
    -- drafted alert's scenario text standing in for prompt/response).
    input                   TEXT NOT NULL,
    output                  TEXT,

    -- Detection metadata (live path only; NULL for synthetic alerts).
    detector                TEXT,
    confidence              REAL,

    -- The DETECTOR's flag on live rows: 'B' when the detection layer flagged the
    -- interaction (live prompt injection / jailbreak), NULL when it did not, and NULL
    -- for every synthetic alert. The Mapper never writes here (its call goes to
    -- predicted_category), so the flag survives classification. E is never assigned.
    -- The answer key lives in ground_truth_category, never here.
    category                TEXT CHECK (category IS NULL OR category IN ('A', 'B', 'C', 'D', 'E')),

    -- The MAPPER's own category call (A-D). NULL until the Mapper has run, and it stays
    -- NULL if the Mapper says the alert is out of scope. classified_at says the Mapper
    -- has run on this row (UTC timestamp), whatever its answer was.
    predicted_category      TEXT CHECK (predicted_category IS NULL OR predicted_category IN ('A', 'B', 'C', 'D', 'E')),
    classified_at           TEXT,

    -- Framework mapping, populated by the classification engine.
    lifecycle_phase         TEXT,
    attck_technique         TEXT,        -- JSON list of ATT&CK ids
    atlas_technique         TEXT,        -- JSON list of ATLAS ids
    owasp_category          TEXT,        -- JSON list of OWASP LLM Top 10 ids
    classification_confidence REAL,      -- the Mapper's confidence (NOT the detector's `confidence`)
    rationale               TEXT,
    sub_cluster             TEXT,        -- Mapper's sub_cluster_or_theme
    in_scope                INTEGER CHECK (in_scope IS NULL OR in_scope IN (0, 1)),
    adversarial             INTEGER CHECK (adversarial IS NULL OR adversarial IN (0, 1)),

    -- Provenance.
    system_prompt_version   INTEGER,     -- live path: version at time of interaction
    probe_id                TEXT,        -- live path: Garak/PyRIT probe identifier for ONE interaction
    run_id                  TEXT,        -- groups many rows into one named test/eval execution
                                         -- (e.g. a heuristics v1/v2/v3 comparison pass, one Garak
                                         -- sweep, one PyRIT batch) so runs can be told apart from
                                         -- each other -- distinct from probe_id, which identifies
                                         -- the probe within a run, not the run itself.
    source_reference        TEXT,        -- synthetic path: ATLAS case study / paper citation.
                                         -- ANSWER-KEY LEAK RISK: includes the case title, so the
                                         -- Mapper must never see it (use the mapper_input view).

    -- Response.
    hardening_applied       INTEGER NOT NULL DEFAULT 0 CHECK (hardening_applied IN (0, 1)),  -- boolean
    playbook                TEXT,

    -- Ground truth (filled in for the evaluation set only). ANSWER KEY:
    -- never shown to the Mapper; read it only through evaluation_truth.
    ground_truth_category   TEXT CHECK (ground_truth_category IS NULL OR ground_truth_category IN ('A', 'B', 'C', 'D', 'E')),

    -- Garak/PyRIT's OWN pass/fail grading of whether the attack actually
    -- got the target model to comply -- independent of what our own
    -- detector said about the interaction. 1 = attack succeeded (model
    -- complied), 0 = attack failed (model refused/resisted), NULL = not
    -- graded / not applicable (e.g. a benign or synthetic row with no
    -- attack-generation tool behind it). This is the ground truth Auto-
    -- Hardening's before/after evaluation needs -- it's not the same
    -- thing as `confidence`, which is our detector's belief, not the
    -- attack's actual outcome.
    attack_succeeded        INTEGER CHECK (attack_succeeded IS NULL OR attack_succeeded IN (0, 1)),

    timestamp               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts(run_id);

-- A synthetic alert is loaded once; the loader skips rows already present,
-- and this index enforces it at the database level. Live rows have no
-- source_reference and are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_reference
    ON alerts(source_reference) WHERE source_reference IS NOT NULL;

-- ---------------------------------------------------------------------------------------
-- (v3) The FULL answer key, one row per alert that has one. alerts.ground_truth_category
-- only holds the category; scoring sub-cluster, attack phase, framework IDs and the
-- scope/attacker flags needs the rest. It lives in its own table so the Mapper can never
-- see it (mapper_input exposes only id, source, input, output), and it carries the
-- development / held-out split so the split is stored, not recomputed.
-- Framework ID lists are JSON text, like the Mapper's own columns.
CREATE TABLE IF NOT EXISTS answer_key (
    alert_id          INTEGER PRIMARY KEY,
    category          TEXT CHECK (category IS NULL OR category IN ('A', 'B', 'C', 'D', 'E')),
    sub_cluster       TEXT,
    lifecycle_phase   TEXT,
    atlas_primary     TEXT,
    atlas_supporting  TEXT,
    attck_techniques  TEXT,
    owasp_categories  TEXT,
    in_scope          INTEGER CHECK (in_scope IS NULL OR in_scope IN (0, 1)),
    adversarial       INTEGER CHECK (adversarial IS NULL OR adversarial IN (0, 1)),
    outcome_status    TEXT,
    case_type         TEXT,          -- incident / exercise / paper, when known
    split             TEXT CHECK (split IS NULL OR split IN ('dev', 'heldout')),
    label_note        TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- (v3) One row per Mapper RUN on one alert. The pilot compares a local model with Claude and
-- runs Claude several times, so results cannot live in the alert row (each run would
-- overwrite the last). valid_json = 0 rows keep the raw reply, so JSON reliability is
-- measurable. Re-running the same (alert, run, repeat) replaces that row only.
CREATE TABLE IF NOT EXISTS mapper_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id            INTEGER NOT NULL,
    run_id              TEXT NOT NULL,       -- e.g. pilot_20261008_local, pilot_20261008_sonnet
    model               TEXT NOT NULL,
    prompt_version      TEXT,
    repeat_no           INTEGER NOT NULL DEFAULT 1,
    valid_json          INTEGER NOT NULL DEFAULT 0 CHECK (valid_json IN (0, 1)),
    predicted_category  TEXT CHECK (predicted_category IS NULL OR predicted_category IN ('A', 'B', 'C', 'D', 'E')),
    sub_cluster         TEXT,
    in_scope            INTEGER CHECK (in_scope IS NULL OR in_scope IN (0, 1)),
    adversarial         INTEGER CHECK (adversarial IS NULL OR adversarial IN (0, 1)),
    lifecycle_phase     TEXT,
    attck_technique     TEXT,
    atlas_technique     TEXT,
    owasp_category      TEXT,
    confidence          REAL CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    rationale           TEXT,
    raw_output          TEXT,
    error               TEXT,
    latency_ms          INTEGER,
    input_tokens        INTEGER,
    output_tokens       INTEGER,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (alert_id, run_id, repeat_no)
);
CREATE INDEX IF NOT EXISTS idx_mapper_results_run ON mapper_results(run_id);
CREATE INDEX IF NOT EXISTS idx_mapper_results_alert ON mapper_results(alert_id);

-- What the Mapper (and the Model Selection Pilot harness) may read:
-- the interaction only. No category, no answer key, no case title.
CREATE VIEW IF NOT EXISTS mapper_input AS
    SELECT id, source, input, output FROM alerts;

-- What the evaluation scripts read to score the Mapper: the answer key
-- next to the Mapper's own prediction.
-- (v3: the first nine columns are unchanged; the answer-key columns are appended.)
CREATE VIEW IF NOT EXISTS evaluation_truth AS
    SELECT a.id, a.source,
           COALESCE(k.category, a.ground_truth_category) AS ground_truth_category,
           a.predicted_category,
           a.sub_cluster AS predicted_sub_cluster, a.classification_confidence,
           a.in_scope, a.adversarial, a.source_reference,
           k.sub_cluster AS truth_sub_cluster, k.lifecycle_phase AS truth_lifecycle_phase,
           k.in_scope AS truth_in_scope, k.adversarial AS truth_adversarial,
           k.outcome_status, k.split
    FROM alerts a LEFT JOIN answer_key k ON k.alert_id = a.id
    WHERE a.ground_truth_category IS NOT NULL OR k.alert_id IS NOT NULL;

-- (v3) Per-run scoring: every Mapper run next to the answer key, with 1/0 correctness
-- flags (NULL when the run gave no usable answer or the key has no value to compare).
-- Framework-ID lists are compared in Python, not here.
CREATE VIEW IF NOT EXISTS mapper_scores AS
    SELECT r.id AS result_id, r.alert_id, r.run_id, r.model, r.prompt_version, r.repeat_no,
           r.valid_json, k.split,
           k.category AS truth_category, r.predicted_category,
           CASE WHEN r.valid_json = 1 AND r.predicted_category IS NOT NULL AND k.category IS NOT NULL
                THEN r.predicted_category = k.category END AS category_correct,
           k.sub_cluster AS truth_sub_cluster, r.sub_cluster AS predicted_sub_cluster,
           CASE WHEN r.valid_json = 1 AND r.sub_cluster IS NOT NULL AND k.sub_cluster IS NOT NULL
                THEN r.sub_cluster = k.sub_cluster END AS sub_cluster_correct,
           k.in_scope AS truth_in_scope, r.in_scope AS predicted_in_scope,
           CASE WHEN r.valid_json = 1 AND r.in_scope IS NOT NULL AND k.in_scope IS NOT NULL
                THEN r.in_scope = k.in_scope END AS in_scope_correct,
           k.adversarial AS truth_adversarial, r.adversarial AS predicted_adversarial,
           CASE WHEN r.valid_json = 1 AND r.adversarial IS NOT NULL AND k.adversarial IS NOT NULL
                THEN r.adversarial = k.adversarial END AS adversarial_correct,
           r.confidence, r.latency_ms
    FROM mapper_results r JOIN answer_key k ON k.alert_id = r.alert_id;
