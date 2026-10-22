"""
mapper/severity.py

Deterministic severity scoring, computed in code rather than asked of the
model. Rationale: the Model Selection Pilot compares Ollama vs. Claude on
classification accuracy -- if severity were a free-text field the model
invents per-call, differences in "severity accuracy" between backends
would really just be differences in how each model free-associates a
word, not a meaningful signal. Scoring it deterministically from fields
the model DOES produce (category, sub_cluster_or_theme, adversarial,
confidence) keeps severity comparable across backends and auditable --
anyone can recompute it by hand from the rationale this module attaches.

Severity reflects potential impact of the attack MECHANISM at the
category/sub-cluster level, then two adjustments bring it down to the
specific alert:
  - non-adversarial alerts are capped at Medium (no attacker evidenced,
    so this is an operational/reliability concern, not an active attack)
  - low-confidence classifications (<0.50) are downgraded one level,
    since acting urgently on an uncertain classification is itself a risk

Out-of-scope alerts (in_scope=False) get "Informational" -- there's
nothing in the taxonomy to rate.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .schema import MapperResult

LEVELS = ["Informational", "Low", "Medium", "High", "Critical"]

# Baseline severity by category. Where a category covers sub-clusters of
# meaningfully different impact (e.g. Category B spans both "jailbreak
# attempt that got deflected" and "supply-chain compromise"), a keyword
# table overrides the category default by matching against
# sub_cluster_or_theme (case-insensitive substring match, checked in the
# order below -- first match wins, so more specific keywords are listed
# first within each category).
BASE_SEVERITY_TABLE = {
    "A": {
        "default": "Medium",
        "keywords": [],
    },
    "B": {
        "default": "High",  # prompt injection & jailbreaking
        "keywords": [
            ("supply-chain", "Critical"),
            ("supply chain", "Critical"),
            ("poisoning", "Critical"),
            ("backdoor", "Critical"),
            ("extraction", "High"),
            ("inversion", "High"),
            ("adversarial example", "High"),
        ],
    },
    "C": {
        "default": "Medium",
        "keywords": [
            ("rag poisoning", "High"),
            ("false rag", "High"),
            ("membership-inference", "High"),
            ("membership inference", "High"),
            ("data extraction", "High"),
            ("privacy", "High"),
            ("system-prompt", "Medium"),
            ("system prompt", "Medium"),
            ("hidden-context", "Medium"),
            ("hidden context", "Medium"),
            ("inference-cost", "Low"),
            ("inference cost", "Low"),
            ("cost harvesting", "Low"),
            ("misinformation", "Medium"),
            ("ranking manipulation", "Medium"),
        ],
    },
    "D": {
        "default": "High",
        "keywords": [
            ("autonomous pentest", "Critical"),
            ("exploit generation", "Critical"),
            ("tool", "Critical"),
            ("api", "Critical"),
            ("sql", "Critical"),
            ("rce", "Critical"),
            ("code-execution", "Critical"),
            ("code execution", "Critical"),
            ("memory", "High"),
            ("long-context", "High"),
            ("long context", "High"),
            ("context corruption", "High"),
            ("multi-agent trust", "High"),
            ("trust failure", "High"),
            ("multi-step attack chain", "High"),
        ],
    },
}


def _base_severity(category: str, sub_cluster_or_theme: str) -> str:
    table = BASE_SEVERITY_TABLE.get(category)
    if table is None:
        return "Informational"
    text = (sub_cluster_or_theme or "").lower()
    for keyword, level in table["keywords"]:
        if keyword in text:
            return level
    return table["default"]


def compute_severity(result: "MapperResult") -> dict:
    """
    Returns {"severity": <label>, "severity_score": <0-4 ordinal>,
    "severity_rationale": <short audit trail>}.

    Call this once, right after schema.validate() succeeds -- classify.py
    does this automatically, so most callers never need to call it
    directly.
    """
    if not result.in_scope:
        return {
            "severity": "Informational",
            "severity_score": LEVELS.index("Informational"),
            "severity_rationale": "Alert is out of taxonomy scope; no severity applies.",
        }

    base = _base_severity(result.category, result.sub_cluster_or_theme)
    idx = LEVELS.index(base)
    notes = [
        f"base severity for category {result.category} / "
        f"'{result.sub_cluster_or_theme}' is {base}"
    ]

    if result.adversarial is False:
        capped = min(idx, LEVELS.index("Medium"))
        if capped != idx:
            notes.append("capped at Medium: no adversarial actor evidenced")
        idx = capped

    if result.confidence is not None and result.confidence < 0.5:
        downgraded = max(idx - 1, 0)
        if downgraded != idx:
            notes.append(
                f"downgraded one level: classification confidence "
                f"{result.confidence:.2f} < 0.50"
            )
        idx = downgraded

    return {
        "severity": LEVELS[idx],
        "severity_score": idx,
        "severity_rationale": "; ".join(notes),
    }


def severity_from_fields(category, sub_cluster_or_theme, adversarial, confidence, in_scope=True) -> dict:
    """Same rubric as compute_severity(), from plain column values (e.g. an alerts or
    mapper_results row). The shared alert store has no severity column -- severity is
    deterministic, so it is recomputed on read instead of stored. 0/1 ints are accepted
    for the flags; in_scope None (never classified) is treated as not scoreable."""
    from types import SimpleNamespace
    if in_scope is None or category is None and in_scope:
        return {"severity": None, "severity_score": None, "severity_rationale": "not classified"}
    row = SimpleNamespace(
        in_scope=bool(in_scope),
        category=category,
        sub_cluster_or_theme=sub_cluster_or_theme,
        adversarial=None if adversarial is None else bool(adversarial),
        confidence=confidence,
    )
    return compute_severity(row)
