"""
mapper/framework_reference.py

Resolves the Mapper's framework_mapping IDs against the REAL framework data
-- not just the condensed ID table baked into prompt.py (which exists to
steer the model's choices, not to double as a data source).

Source data (data/framework_reference_data.json, built once, checked into
the repo so classification never depends on network access at runtime):
  - attack: MITRE ATT&CK Enterprise v19.2+ techniques and tactics, trimmed
    from the official STIX bundle (github.com/mitre-attack/attack-stix-data).
  - atlas: MITRE ATLAS techniques (including sub-techniques), trimmed from
    the official ATLAS.yaml (github.com/mitre-atlas/atlas-data).
  - owasp_llm: the OWASP Top 10 for LLM Applications (2026 edition -- same
    identifiers/names already used in prompt.py and in the project's
    Taxonomy & Framework Reference Tables doc: LLM03 is Excessive Agency,
    LLM04 is Supply Chain, etc. -- this is the 2026 renumbering, not the
    2023/2025 one, so don't "fix" these against an older OWASP list).

What this module does with that data, given a MapperResult (post
schema.validate()):
  - looks up every ID the model returned in each of the three frameworks
  - attaches the framework's own name/description/url alongside each ID
  - flags any ID the model returned that ISN'T in the real data as
    "unresolved" -- this is a free, meaningful side effect of having a real
    lookup table: it catches hallucinated/malformed IDs (including the
    "comma-joined into one element" and "ID + technique name crammed
    together" failure modes seen in live Ollama runs) instead of silently
    scoring them as just-wrong.

This does NOT change what IDs the model is asked to produce (prompt.py is
unchanged) -- it only resolves what the model gave us against the ground
truth of the actual frameworks, for storage and for the dashboard.
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .schema import MapperResult

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "framework_reference_data.json")
_DATA = None  # lazy-loaded, module-level cache


def _load():
    global _DATA
    if _DATA is None:
        with open(_DATA_PATH, encoding="utf-8") as f:
            _DATA = json.load(f)
    return _DATA


@dataclass
class ResolvedId:
    id: str
    resolved: bool
    name: str = ""
    description: str = ""
    url: str = ""


@dataclass
class FrameworkEnrichment:
    attack: list = field(default_factory=list)      # list[ResolvedId]
    atlas: list = field(default_factory=list)        # list[ResolvedId]
    owasp_llm: list = field(default_factory=list)    # list[ResolvedId]

    @property
    def unresolved_count(self) -> int:
        return sum(
            1 for lst in (self.attack, self.atlas, self.owasp_llm)
            for r in lst if not r.resolved
        )

    @property
    def total_count(self) -> int:
        return len(self.attack) + len(self.atlas) + len(self.owasp_llm)


# A raw ID string from the model sometimes isn't just the ID -- e.g.
# "AML.T0110.00x AI Agent Tool Poisoning" or two IDs comma-joined into one
# array element. This tries to recover a bare ID to look up before giving
# up and reporting the whole string as unresolved. It does NOT silently
# "fix" the model's output in place -- the evaluator still sees and can
# flag the original malformed string (see evaluate.py's malformed_ids) --
# this is only used for the enrichment lookup.
_ID_PATTERNS = (
    re.compile(r"^(T\d{4}(?:\.\d{3})?)"),            # ATT&CK technique
    re.compile(r"^(TA\d{4})"),                        # ATT&CK tactic
    re.compile(r"^(AML\.T\d{4}(?:\.\d{3})?)"),         # ATLAS
    re.compile(r"^(LLM\d{2})"),                        # OWASP LLM Top 10
)


def _extract_bare_id(raw_id: str) -> str:
    text = raw_id.strip()
    for pattern in _ID_PATTERNS:
        m = pattern.match(text)
        if m:
            return m.group(1)
    return text


def _resolve_one(raw_id: str, table: dict) -> ResolvedId:
    bare = _extract_bare_id(raw_id)
    entry = table.get(bare)
    if entry is None:
        return ResolvedId(id=raw_id, resolved=False)
    return ResolvedId(
        id=bare, resolved=True,
        name=entry["name"], description=entry["description"], url=entry["url"],
    )


def enrich(result: "MapperResult") -> FrameworkEnrichment:
    """
    Resolves result.framework_attack / framework_atlas / framework_owasp_llm
    against the real framework data. Safe to call on an out-of-scope result
    (all three lists are empty, so this just returns an empty enrichment).
    """
    data = _load()
    return FrameworkEnrichment(
        attack=[lookup("attack", i) for i in result.framework_attack],
        atlas=[lookup("atlas", i) for i in result.framework_atlas],
        owasp_llm=[lookup("owasp_llm", i) for i in result.framework_owasp_llm],
    )


def canonical(framework: str, raw_id: str) -> str:
    """Bare ID with revoked/retired IDs mapped to their current replacement
    (e.g. ATT&CK T1656 -> T1684.001, ATLAS AML.T0058 -> AML.T0115.001). Used on BOTH sides
    when scoring, so a label written against an older release still matches."""
    bare = _extract_bare_id(raw_id)
    revoked = _load().get(f"{framework}_revoked", {})
    seen = set()
    while bare in revoked and bare not in seen:
        seen.add(bare)
        bare = revoked[bare]
    return bare


def lookup(framework: str, raw_id: str) -> ResolvedId:
    """Resolve a single ID against one framework ('attack' | 'atlas' | 'owasp_llm').
    A revoked ID resolves to its replacement."""
    data = _load()
    if framework not in ("attack", "atlas", "owasp_llm"):
        raise ValueError(f"unknown framework {framework!r}; expected attack/atlas/owasp_llm")
    resolved = _resolve_one(raw_id, data[framework])
    if not resolved.resolved:
        current = canonical(framework, raw_id)
        if current in data[framework]:
            resolved = _resolve_one(current, data[framework])
    return resolved


def coverage_stats() -> dict:
    """How many real IDs each framework's local reference table covers -- for the
    dashboard's "about this data" panel, not used in scoring. Deliberately only
    the three ID tables, not the tactic-matrix structures added alongside them
    (see matrix_data.py) -- those aren't "coverage" in the same sense."""
    data = _load()
    return {k: len(data[k]) for k in ("attack", "atlas", "owasp_llm")}


def parse_id_list(value) -> list:
    """An ID-list column as a Python list. The shared alert store stores these as JSON
    text ('["AML.T0051", "AML.T0054"]'); rows written by older Mapper code used
    comma-joined text. Accepts both, plus None/''/an actual list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        text = str(value).strip()
        if not text:
            return []
        try:
            items = json.loads(text)
            if not isinstance(items, list):
                items = [items]
        except json.JSONDecodeError:
            items = text.split(",")
    return [str(i).strip() for i in items if i is not None and str(i).strip()]
