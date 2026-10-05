-- AI Attack Mapper -- Shared Alert Store schema.
--
-- Both the Live Attack Path and the Synthetic Alert Path write to this
-- single table so the classification engine treats live and synthetic
-- alerts identically. See Design section of the Capstone Group document
-- and docs/architecture.md for the full data-flow diagram.

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

    -- Taxonomy category, set at generation/detection time and refined
    -- once the classification engine runs.
    category                TEXT,

    -- Framework mapping, populated by the classification engine.
    lifecycle_phase         TEXT,
    attck_technique         TEXT,
    atlas_technique         TEXT,
    owasp_category          TEXT,
    classification_confidence REAL,
    rationale               TEXT,

    -- Provenance.
    system_prompt_version   INTEGER,     -- live path: version at time of interaction
    probe_id                TEXT,        -- live path: Garak/PyRIT probe identifier for ONE interaction
    run_id                  TEXT,        -- groups many rows into one named test/eval execution
                                         -- (e.g. a heuristics v1/v2/v3 comparison pass, one Garak
                                         -- sweep, one PyRIT batch) so runs can be told apart from
                                         -- each other -- distinct from probe_id, which identifies
                                         -- the probe within a run, not the run itself.
    source_reference        TEXT,        -- synthetic path: ATLAS case study / paper citation

    -- Response.
    hardening_applied       INTEGER NOT NULL DEFAULT 0,  -- boolean
    playbook                TEXT,

    -- Ground truth (filled in for the evaluation set only).
    ground_truth_category   TEXT,

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
