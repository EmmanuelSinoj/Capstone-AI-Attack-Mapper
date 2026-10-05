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
--   * new columns sub_cluster, in_scope, adversarial (Mapper output fields
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

    -- Taxonomy category (A-D; E is never assigned to an alert). For
    -- synthetic alerts this stays NULL until the Mapper classifies the
    -- alert, so classification is blind. The answer key lives in
    -- ground_truth_category, never here.
    category                TEXT CHECK (category IS NULL OR category IN ('A', 'B', 'C', 'D', 'E')),

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

-- What the Mapper (and the Model Selection Pilot harness) may read:
-- the interaction only. No category, no answer key, no case title.
CREATE VIEW IF NOT EXISTS mapper_input AS
    SELECT id, source, input, output FROM alerts;

-- What the evaluation scripts read to score the Mapper: the answer key
-- next to the Mapper's own prediction.
CREATE VIEW IF NOT EXISTS evaluation_truth AS
    SELECT id, source, ground_truth_category, category AS predicted_category,
           sub_cluster AS predicted_sub_cluster, classification_confidence,
           in_scope, adversarial, source_reference
    FROM alerts
    WHERE ground_truth_category IS NOT NULL;
