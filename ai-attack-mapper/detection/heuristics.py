"""
Heuristic pattern-based prompt-injection / jailbreak detector.

Fast, cheap, synchronous first-pass filter -- runs on every testbed
interaction before the judge model gets a look. See
live_attack_path/detection/README.md for how this fits into the
overall detection layer, and docs/architecture.md for the full
Live Attack Path diagram this is one box of.

Two signals as of 2026-09-25: the original hand-written regex patterns
below (exact-match only), plus a fuzzy-matching third signal via
rebuff_heuristics.py (reused from the archived Rebuff project -- see
that file's own docstring for provenance/license). The fuzzy matcher
was added after comparing this module against a separately-built
heuristic scanner a teammate (Emmanuel) put together independently
(see PROGRESS_LOG.md, 2026-09-25, for the full comparison): regex-only
matching has a real, acknowledged gap -- a paraphrased injection that
doesn't hit any of the patterns below sails through untouched. The
fuzzy matcher catches many of those paraphrases at the cost of being a
similarity score rather than an exact rule, so it's kept as a distinct,
separately-reported signal (see REBUFF_SCORE_THRESHOLD below) rather
than folded silently into the same bucket as an exact regex hit.
"""

import re
from typing import List, Tuple

from .rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input

# Each pattern targets a known family of jailbreak/injection phrasing
# drawn from the literature review's "Attacks Against AI Systems" and
# "LLM and GenAI Application Attacks" categories (Capstone Group doc,
# Section III). This is a starting set, not a finished one -- expected
# to grow as Attack Generation (Garak/PyRIT) surfaces payloads that
# slip past it. Add new patterns here, not inline in callers.
_PATTERNS = [
    (re.compile(r"ignore (all|any|previous|prior|the above) instructions", re.I), "instruction_override"),
    (re.compile(r"disregard (all|any|previous|prior|your) (instructions|rules|guidelines)", re.I), "instruction_override"),
    (re.compile(r"you are (now|no longer) (DAN|in developer mode|unrestricted)", re.I), "persona_jailbreak"),
    (re.compile(r"reveal (your|the) (system prompt|instructions|configuration)", re.I), "prompt_exfiltration"),
    (re.compile(r"print (your|the) (system prompt|instructions)", re.I), "prompt_exfiltration"),
    (re.compile(r"pretend (you are|to be).*(without|no) (restrictions|rules|filters)", re.I), "persona_jailbreak"),
    (re.compile(r"act as (if|though) you (have no|do not have) (restrictions|guidelines)", re.I), "persona_jailbreak"),
    (re.compile(r"\bDAN\b.*(mode|prompt)", re.I), "persona_jailbreak"),
    (re.compile(r"bypass (your|the|all) (safety|content) (filters|guidelines|restrictions)", re.I), "filter_bypass"),
    (re.compile(r"(sudo|admin|root) mode", re.I), "privilege_escalation_roleplay"),
    (re.compile(r"repeat (the words?|everything) (above|before this)", re.I), "prompt_exfiltration"),
    (re.compile(r"what (is|was) your (system prompt|initial instructions)", re.I), "prompt_exfiltration"),
]


# Threshold for the fuzzy-matching score from rebuff_heuristics.py
# (0.0-1.0). PROVISIONAL -- carried over from Emmanuel's own manual
# testing (see his heuristic_scanner.py commit), not yet re-derived
# against this project's own live data: benign strings scored as high
# as 0.581 in his testing (any accidental one-word overlap gives a
# ~0.5 baseline), while actual injection samples scored 0.733-0.919.
# 0.65 sits in that gap. Worth re-tuning against alerts.db's own
# ~8,700 real live interactions (e.g. checking how many `heuristic:
# clean` rows would flip to flagged at this threshold) before treating
# this as final -- not done yet, flagged here rather than silently
# trusted.
REBUFF_SCORE_THRESHOLD = 0.65

# Only applied to the *prompt*, matching Emmanuel's own scan_input()
# design: this phrase list ("ignore previous instructions", its many
# paraphrases) describes attacker-side injection language, not
# something a compliant or non-compliant model response would itself
# contain, so running it against the response side wouldn't be
# checking for anything meaningful.
def _check_rebuff(prompt: str) -> Tuple[bool, float]:
    if not prompt:
        return False, 0.0
    score = detect_prompt_injection_using_heuristic_on_input(prompt)
    return score >= REBUFF_SCORE_THRESHOLD, score


def check(text: str) -> Tuple[bool, List[str]]:
    """Return (flagged, matched_pattern_names) for a single piece of text."""
    if not text:
        return False, []
    matched = [name for pattern, name in _PATTERNS if pattern.search(text)]
    return (len(matched) > 0), matched


def check_interaction(prompt: str, response: str) -> Tuple[bool, List[str], float]:
    """Check both sides of an interaction.

    Confidence is a coarse heuristic, not a calibrated probability: a
    match in the *response* (the model appears to have complied) counts
    for more than a match in the prompt alone (someone merely tried).
    The fuzzy matcher firing alone (no exact regex hit on either side)
    is scored by its own similarity score instead of the fixed 0.5 --
    a borderline 0.65 match is genuinely less certain than an exact
    regex hit, and a 0.95 match is genuinely more certain, so collapsing
    both into the same flat number would throw away real signal.
    """
    prompt_flagged, prompt_matches = check(prompt)
    response_flagged, response_matches = check(response)
    rebuff_flagged, rebuff_score = _check_rebuff(prompt)

    rebuff_matches = [f"rebuff_fuzzy({rebuff_score:.2f})"] if rebuff_flagged else []
    all_matches = sorted(set(prompt_matches + response_matches + rebuff_matches))
    flagged = prompt_flagged or response_flagged or rebuff_flagged

    if not flagged:
        confidence = 0.0
    elif response_flagged:
        confidence = 0.9
    elif prompt_flagged:
        confidence = 0.5
    else:
        confidence = rebuff_score

    return flagged, all_matches, confidence
