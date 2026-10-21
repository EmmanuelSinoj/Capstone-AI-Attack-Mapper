"""
mapper/schema.py

Validates the Mapper's parsed JSON response and flattens it into the shape
alert_store's DB columns expect (see AI_Attack_Mapper_Prompt_v1.md,
"Structured output schema (formal)").

Status update (Oct 17, 2026): the three columns this module used to fold
into `rationale` as a bracketed-prefix workaround -- in_scope, adversarial,
sub_cluster_or_theme -- now have real columns in alert_store/schema.sql,
added alongside two new ones (severity, severity_score) that this module
also now populates. FLATTEN_PLACEHOLDER_GAPS defaults to False as a result.
Flip it back to True only if you're running against an older alerts.db
that hasn't picked up the schema migration yet.
"""

from dataclasses import dataclass, field
from typing import Optional

from . import severity as severity_mod

VALID_CATEGORIES = {"A", "B", "C", "D", None}
ARRAY_JOIN_DELIMITER = ","  # placeholder pending Emmanuel's confirmation (see Known gaps)
FLATTEN_PLACEHOLDER_GAPS = False


class SchemaValidationError(ValueError):
    pass


@dataclass
class MapperResult:
    alert_id: str
    in_scope: bool
    adversarial: Optional[bool]
    category: Optional[str]
    category_label: Optional[str]
    sub_cluster_or_theme: Optional[str]
    lifecycle_phase: Optional[str]
    framework_attack: list = field(default_factory=list)
    framework_atlas: list = field(default_factory=list)
    framework_owasp_llm: list = field(default_factory=list)
    confidence: Optional[float] = None
    rationale: str = ""
    # Populated by classify.py after validate() succeeds, via severity.py.
    # Left as None here so validate() alone (e.g. in tests) still works
    # without requiring a separate severity-computation step.
    severity: Optional[str] = None
    severity_score: Optional[int] = None
    severity_rationale: str = ""


def validate(raw: dict) -> MapperResult:
    """
    Validates a parsed JSON response against the schema in prompt.py.
    Raises SchemaValidationError with a specific reason on any violation --
    never silently coerces a bad value, since a wrong category or a
    dropped field is worse than a loud failure here.
    """
    missing = [k for k in ("alert_id", "in_scope", "rationale") if k not in raw]
    if missing:
        raise SchemaValidationError(f"missing required field(s): {missing}")

    in_scope = raw["in_scope"]
    if not isinstance(in_scope, bool):
        raise SchemaValidationError(f"in_scope must be bool, got {type(in_scope).__name__}")

    if in_scope is False:
        # Per the spec: only alert_id, in_scope, rationale required when out of scope.
        return MapperResult(
            alert_id=str(raw["alert_id"]),
            in_scope=False,
            adversarial=raw.get("adversarial"),
            category=None,
            category_label=None,
            sub_cluster_or_theme=None,
            lifecycle_phase=None,
            confidence=None,
            rationale=str(raw["rationale"]),
        )

    required_in_scope = (
        "adversarial", "category", "category_label", "sub_cluster_or_theme",
        "lifecycle_phase", "framework_mapping", "confidence", "rationale",
    )
    missing = [k for k in required_in_scope if k not in raw]
    if missing:
        raise SchemaValidationError(f"missing required field(s) for in_scope=true alert: {missing}")

    category = raw["category"]
    # VALID_CATEGORIES includes None so the *out-of-scope* early-return path
    # above can use it too -- but we're past that path here (in_scope is
    # True), so None is NOT acceptable at this point. Without this check, a
    # model that says "in_scope: true" but can't commit to a category (e.g.
    # a confused refusal-flavored response) passes validation with
    # category=None, gets written to the DB, and silently looks like a
    # completed classification instead of the failure it actually is --
    # this is exactly what happened with llama3.2:latest on the Oct 17/18
    # prompt-injection test alert (see Known gaps / README).
    if category is None or category not in VALID_CATEGORIES:
        raise SchemaValidationError(
            f"category must be one of A/B/C/D for an in-scope alert, got {category!r}"
        )

    adversarial = raw["adversarial"]
    if not isinstance(adversarial, bool):
        raise SchemaValidationError(f"adversarial must be bool, got {type(adversarial).__name__}")

    confidence = raw["confidence"]
    if not isinstance(confidence, (int, float)) or not (0.0 <= float(confidence) <= 1.0):
        raise SchemaValidationError(f"confidence must be a float in [0.0, 1.0], got {confidence!r}")

    fm = raw["framework_mapping"]
    if not isinstance(fm, dict) or not all(k in fm for k in ("attack", "atlas", "owasp_llm")):
        raise SchemaValidationError(
            "framework_mapping must be an object with attack/atlas/owasp_llm array keys"
        )
    for key in ("attack", "atlas", "owasp_llm"):
        if not isinstance(fm[key], list):
            raise SchemaValidationError(f"framework_mapping.{key} must be a list, got {type(fm[key]).__name__}")

    return MapperResult(
        alert_id=str(raw["alert_id"]),
        in_scope=True,
        adversarial=adversarial,
        category=category,
        category_label=str(raw["category_label"]),
        sub_cluster_or_theme=str(raw["sub_cluster_or_theme"]),
        lifecycle_phase=str(raw["lifecycle_phase"]),
        framework_attack=list(fm["attack"]),
        framework_atlas=list(fm["atlas"]),
        framework_owasp_llm=list(fm["owasp_llm"]),
        confidence=float(confidence),
        rationale=str(raw["rationale"]),
    )


def attach_severity(result: MapperResult) -> MapperResult:
    """
    Computes severity.compute_severity(result) and attaches it to the
    result in place, returning the same object for convenient chaining
    (classify.py does: return attach_severity(validate(raw_json))).
    """
    sev = severity_mod.compute_severity(result)
    result.severity = sev["severity"]
    result.severity_score = sev["severity_score"]
    result.severity_rationale = sev["severity_rationale"]
    return result


def to_db_columns(result: MapperResult) -> dict:
    """
    Flattens a validated (and severity-scored) MapperResult into the
    column names in alert_store/schema.sql. As of the Oct 17, 2026
    migration, in_scope/adversarial/sub_cluster_or_theme/severity/
    severity_score are real columns -- no more bracket-prefix workaround
    by default. Booleans are written as 0/1 ints since SQLite has no
    native boolean type.
    """
    rationale_text = result.rationale
    if FLATTEN_PLACEHOLDER_GAPS:
        # Legacy path -- only for an alerts.db that predates the schema
        # migration. See module docstring.
        gap_prefix_parts = [f"in_scope={result.in_scope}"]
        if result.adversarial is not None:
            gap_prefix_parts.append(f"adversarial={result.adversarial}")
        if result.sub_cluster_or_theme:
            gap_prefix_parts.append(f"sub_cluster={result.sub_cluster_or_theme}")
        rationale_text = f"[{', '.join(gap_prefix_parts)}] {rationale_text}"

    columns = {
        "id": result.alert_id,
        "category": result.category,  # None stays None for out-of-scope alerts
        "lifecycle_phase": result.lifecycle_phase,
        "attck_technique": ARRAY_JOIN_DELIMITER.join(result.framework_attack),  # [sic] matches real column name
        "atlas_technique": ARRAY_JOIN_DELIMITER.join(result.framework_atlas),
        "owasp_category": ARRAY_JOIN_DELIMITER.join(result.framework_owasp_llm),
        "classification_confidence": result.confidence,
        "rationale": rationale_text,
    }

    if not FLATTEN_PLACEHOLDER_GAPS:
        columns.update({
            "in_scope": int(result.in_scope),
            "adversarial": None if result.adversarial is None else int(result.adversarial),
            "sub_cluster_or_theme": result.sub_cluster_or_theme,
            "severity": result.severity,
            "severity_score": result.severity_score,
        })

    return columns
