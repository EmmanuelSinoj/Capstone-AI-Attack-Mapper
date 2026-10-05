"""
alert_schema.py

Single shared definition of the alert record format used across the
AI Attack Mapper pipeline. Every component (Testbed logging, Detection,
Synthetic Alert Generator, the Mapper, Playbook Generation, Auto-Hardening)
imports this module rather than redefining the schema independently.

Fields:
    id                      - auto-incrementing primary key (assigned by SQLite)
    source                  - 'live' or 'synthetic'
    input                   - the attack prompt / input text
    output                  - the model's response to that input
    detector                - which detection mechanism flagged it
                              (e.g. 'heuristic', 'judge_model', 'both', or
                              null for synthetic alerts with no live detector)
    confidence              - float 0.0-1.0, confidence the alert is a
                              genuine attack (from detection or classification)
    category                - one of the five taxonomy category codes (A-E)
    timestamp               - ISO-8601 string, when the alert was created
    system_prompt_version   - which version of the testbed's protected
                              system prompt was active at the time
                              (null for synthetic alerts, no live testbed)
    run_id                  - groups alerts from the same named test/eval
                              execution (e.g. a heuristics v1/v2/v3
                              comparison pass, one Garak sweep, one PyRIT
                              batch) so runs can be told apart from each
                              other; null for ordinary one-off live traffic
    probe_id                - live path: Garak/PyRIT probe identifier for ONE
                              interaction (null otherwise)
    source_reference        - synthetic path: ATLAS case study / paper citation.
                              ANSWER-KEY LEAK RISK (contains the case title):
                              the Mapper must never read it -- see mapper_input
                              view in schema.sql
    attack_succeeded        - Garak/PyRIT's own pass/fail grading of
                              whether the attack got the target model to
                              comply: True/False, or null when not graded
                              or not applicable (e.g. benign/synthetic
                              rows). This is ground truth for Auto-
                              Hardening's before/after evaluation and is
                              independent of `confidence`, which is our
                              own detector's belief about the interaction.

The full table (including the columns the Mapper and the evaluation fill in,
such as lifecycle_phase, classification_confidence and ground_truth_category)
is defined ONCE, in schema.sql. This module only describes the subset of
fields the live logger and the synthetic loader write at insert time.

Category source: "AI-Enabled Cyber Attack Mapping Framework" (summer
research co-op paper, Section IV, Table III). Five attack-oriented
taxonomy categories, A-E. A sixth grouping in the paper, Category F
(Cross-Cutting Surveys/Frameworks), is explicitly NOT part of the
attack taxonomy per the paper and is therefore not a valid value here.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

# The five taxonomy categories, exactly as defined in Section IV,
# Table III of the research co-op paper. Values are the category
# codes (A-E) used throughout that paper and the Deliverable 1 draft.
VALID_CATEGORIES = {
    "A",  # AI-Assisted Traditional Attacks
    "B",  # Attacks Against AI Systems
    "C",  # LLM/GenAI Application Attacks
    "D",  # Agentic AI Threats
    "E",  # Defense & Governance Gaps
}

# Human-readable labels for display/reporting, keyed by the same codes.
CATEGORY_LABELS = {
    "A": "AI-Assisted Traditional Attacks",
    "B": "Attacks Against AI Systems",
    "C": "LLM/GenAI Application Attacks",
    "D": "Agentic AI Threats",
    "E": "Defense & Governance Gaps",
}

VALID_SOURCES = {"live", "synthetic"}


@dataclass
class Alert:
    source: str
    input: str
    output: str
    category: Optional[str] = None          # may be unset until the Mapper classifies it
    detector: Optional[str] = None
    confidence: Optional[float] = None
    system_prompt_version: Optional[str] = None
    run_id: Optional[str] = None             # groups rows from one named test/eval run
    attack_succeeded: Optional[bool] = None  # Garak/PyRIT's own ground-truth pass/fail
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: Optional[int] = None                # assigned by SQLite on insert
    probe_id: Optional[str] = None           # live path: Garak/PyRIT probe identifier
    source_reference: Optional[str] = None   # synthetic path: ATLAS case / paper citation (answer-key leak risk)

    def validate(self) -> None:
        if self.source not in VALID_SOURCES:
            raise ValueError(f"source must be one of {VALID_SOURCES}, got {self.source!r}")
        if self.category is not None and self.category not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {VALID_CATEGORIES}, got {self.category!r}")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.attack_succeeded is not None and not isinstance(self.attack_succeeded, bool):
            raise ValueError(f"attack_succeeded must be a bool or None, got {self.attack_succeeded!r}")


# The table definition lives in schema.sql and nowhere else, so the schema
# and the table can never drift apart. CREATE_TABLE_SQL is the whole script
# (table, indexes and views); run it with executescript(), or just call
# alert_store.init_db() / db.get_connection(), which also upgrade old databases.
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
CREATE_TABLE_SQL = SCHEMA_PATH.read_text(encoding="utf-8")
