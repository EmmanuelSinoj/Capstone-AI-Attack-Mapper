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
    probe_id                TEXT,        -- live path: Garak/PyRIT probe identifier
    source_reference        TEXT,        -- synthetic path: ATLAS case study / paper citation

    -- Response.
    hardening_applied       INTEGER NOT NULL DEFAULT 0,  -- boolean
    playbook                TEXT,

    -- Ground truth (filled in for the evaluation set only).
    ground_truth_category   TEXT,

    timestamp               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
