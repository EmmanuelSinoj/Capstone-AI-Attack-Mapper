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

Category source: "AI-Enabled Cyber Attack Mapping Framework" (summer
research co-op paper, Section IV, Table III). Five attack-oriented
taxonomy categories, A-E. A sixth grouping in the paper, Category F
(Cross-Cutting Surveys/Frameworks), is explicitly NOT part of the
attack taxonomy per the paper and is therefore not a valid value here.
"""

from dataclasses import dataclass, field
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
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: Optional[int] = None                # assigned by SQLite on insert

    def validate(self) -> None:
        if self.source not in VALID_SOURCES:
            raise ValueError(f"source must be one of {VALID_SOURCES}, got {self.source!r}")
        if self.category is not None and self.category not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {VALID_CATEGORIES}, got {self.category!r}")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")


# The exact SQL used to create the table. Kept here so the schema
# definition and the table definition can never drift apart.
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    source                  TEXT NOT NULL CHECK (source IN ('live', 'synthetic')),
    input                   TEXT NOT NULL,
    output                  TEXT NOT NULL,
    detector                TEXT,
    confidence              REAL CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    category                TEXT CHECK (category IS NULL OR category IN ('A', 'B', 'C', 'D', 'E')),
    timestamp               TEXT NOT NULL,
    system_prompt_version   TEXT
);
"""
