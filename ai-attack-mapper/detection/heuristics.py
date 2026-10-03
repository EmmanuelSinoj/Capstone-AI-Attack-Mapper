"""
Exact-pattern prompt-injection / jailbreak detector (fuzzy matcher REMOVED 2026-10-02).

Live design (detection v6, see VERSION.md): a prompt is flagged if it matches one of the 43
exact patterns below (after Unicode/zero-width normalisation and after decoding base64, hex and
ROT13 -- see preprocessing.py), OR if the judge model (judge.py) scores it at/above its cutoff.
The Rebuff-derived fuzzy matcher was switched off because on real JailbreakHub prompts it raised
the false-positive rate from about 20% to about 63% for a modest recall gain
(see eval_judge/compare_fuzzy_off_output.txt). rebuff_heuristics.py is no longer imported.

This file also keeps _check_system_prompt_leak: it checks whether the *response* contains the
real, current system prompt verbatim -- the strongest signal available, and unrelated to phrasing.

Pattern set (43) = Emmanuel's v5 set (38: the original 12 -- two corrected so "ignore all previous
instructions" actually matches -- plus 6 structural-markup and 20 expanded patterns) plus 5
`encoding_smuggling` patterns added 2026-10-02 ("decode the following ...", "Encoded: ... Decoded:",
decode + follow-up verb). The 5 encoding patterns were written after looking at Garak's encoding
probes, so Garak numbers for that family are in-sample; the independent check is
eval_judge/encoding_holdout_80.json (results in eval_judge/encoding_rule_eval_output.txt).
"""

import re
from typing import List, Optional, Tuple

from .preprocessing import normalize_for_detection, decode_candidates

# Original 12 patterns. Two are corrected here (marked below) -- both had
# a real bug found while testing today's additions: they only allowed ONE
# qualifier word between the verb and the noun, so the single most classic
# phrasing, "ignore all previous instructions", never actually matched
# either pattern. It was only ever caught because the fuzzy matcher (or a
# second clause in the same sentence) happened to catch it instead. Fixed
# to allow the natural two-qualifier-word form; verified against every
# phrasing variant before and after the fix.
_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+|any\s+|the above\s+)?(?:previous\s+|prior\s+)?instructions", re.I), "instruction_override"),  # FIXED
    (re.compile(r"disregard\s+(?:all\s+|any\s+|your\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|guidelines)", re.I), "instruction_override"),  # FIXED
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

# New: structural markup / chat-template injection -- exact matches for
# fake special tokens an attacker inserts to trick the model into
# thinking a new instruction block has started. Zero overlap with
# ordinary prose, so this carries the same low false-positive profile
# as the original patterns.
_STRUCTURAL_PATTERNS = [
    (re.compile(r"\[/?INST\]", re.I), "structural_markup"),
    (re.compile(r"<\|im_(start|end)\|>", re.I), "structural_markup"),
    (re.compile(r"###\s*(Instruction|System)\s*:", re.I), "structural_markup"),
    (re.compile(r"</?system>", re.I), "structural_markup"),
    (re.compile(r"<\|system\|>", re.I), "structural_markup"),
    (re.compile(r"\[/?SYS\]", re.I), "structural_markup"),
]

# New: broader exact-match coverage, independently written (not derived
# from looking at our own benchmark's misses -- see PROGRESS_LOG for why
# that specific approach was rejected after the v3/narrow-phrase tests).
_EXPANDED_PATTERNS = [
    (re.compile(r"forget (your|all|any) (instructions|training|guidelines)", re.I), "instruction_override"),
    (re.compile(r"start (over|fresh) (completely|entirely) (with|and) (no|without) (rules|restrictions)", re.I), "instruction_override"),
    (re.compile(r"new instructions (supersede|override|replace) (all|any) prior", re.I), "instruction_override"),
    (re.compile(r"(debug|maintenance|test) mode (is )?(enabled|activated|on)", re.I), "persona_jailbreak"),
    (re.compile(r"no ethical (guidelines|constraints|restrictions)", re.I), "persona_jailbreak"),
    (re.compile(r"without (any )?(limitations|restrictions|rules)", re.I), "persona_jailbreak"),
    (re.compile(r"\b(unshackled|uncensored) (version|mode|ai)\b", re.I), "persona_jailbreak"),
    (re.compile(r"(evil|opposite) (twin|day) mode", re.I), "persona_jailbreak"),
    (re.compile(r"print your (configuration|guidelines)", re.I), "prompt_exfiltration"),  # narrowed to "your" only -- "print the configuration" false-positived on ordinary IT text ("print the configuration of my network adapter")
    (re.compile(r"what is your (system )?prompt", re.I), "prompt_exfiltration"),
    (re.compile(r"show (me )?your (rules|guidelines|instructions)", re.I), "prompt_exfiltration"),
    (re.compile(r"output your (guidelines|instructions|configuration)", re.I), "prompt_exfiltration"),
    (re.compile(r"as your (creator|developer|maker)", re.I), "authority_claim"),
    (re.compile(r"(admin|developer) override (code)?", re.I), "authority_claim"),
    (re.compile(r"content policy (is )?(off|disabled)", re.I), "filter_bypass"),
    (re.compile(r"safety (is )?(off|disabled)", re.I), "filter_bypass"),
    (re.compile(r"(restrictions|guardrails) (are )?(disabled|removed|lifted)", re.I), "filter_bypass"),
    (re.compile(r"respond (only )?in base ?64", re.I), "encoding_request"),
    (re.compile(r"encode your (reply|response) in", re.I), "encoding_request"),
    (re.compile(r"use rot ?13", re.I), "encoding_request"),
]

# Encoding / cipher smuggling (added 2026-10-02). A prompt that supplies encoded text and asks the bot to DECODE AND ACT
# on it is hiding its real instruction from the prompt-side detectors; Garak's encoding probes and the "decode and obey"
# style both look like this. Deliberately narrow: ordinary talk about encodings ("how do I decode base64 in Python",
# "what is ROT13", "my receipt shows =E2=80=99") must NOT match, so each pattern needs either the literal
# "decode the following/this message" request shape, an "Encoded: ... Decoded:" template, or decode + a follow-up
# verb (follow / obey / execute / comply / do what it says). Caveat: written after seeing Garak's wording, so Garak
# numbers for this family are in-sample; the independent check is eval_judge/encoding_holdout_80.json.
_CIPHER = (r"(?:base ?(?:64|32|16|85|2048)|rot ?(?:13|47)|hex(?:adecimal)?|binary|morse(?: code)?|atbash|caesar|vigen[e\u00e8]re|"
           r"nato|phonetic|pig latin|leetspeak|braille|url[- ]encoded|ascii ?85|uu(?:encode)?)")
_ACT = r"(?:follow|obey|execute|run|comply|act on|carry out|do what|answer|respond to)"
_ENCODING_REQUEST_PATTERNS = [
    (re.compile(r"\bdecode (?:the |this |these )?(?:following|below|text|message|string|code)\b", re.I), "encoding_smuggling"),
    (re.compile(r"\bencoded\s*:.{0,4000}?\bdecoded\b", re.I | re.S), "encoding_smuggling"),
    (re.compile(r"\b(?:decode|decrypt|decipher|convert|translate)\b[^.\n]{0,60}\b" + _CIPHER + r"\b[^.\n]{0,60}\b(?:and|then)\b[^.\n]{0,25}\b" + _ACT + r"\b", re.I), "encoding_smuggling"),
    (re.compile(r"\b(?:decode|decrypt|decipher)\b[^.\n]{0,40}\b(?:and|then)\b[^.\n]{0,20}\b" + _ACT + r"\b", re.I), "encoding_smuggling"),
    (re.compile(r"\b(?:follow|obey|execute|carry out|act on|comply with)\b[^.\n]{0,30}\b(?:decoded|decrypted|deciphered|plaintext)\b", re.I), "encoding_smuggling"),
]

_ALL_PATTERNS = _PATTERNS + _STRUCTURAL_PATTERNS + _EXPANDED_PATTERNS + _ENCODING_REQUEST_PATTERNS


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


# Minimum normalized length before a substring match counts as a real
# leak rather than a coincidence -- a short/generic system prompt could
# otherwise trivially "leak" via unrelated short phrases in a response.
_MIN_LEAK_LENGTH = 20


def _check_system_prompt_leak(response: str, system_prompt: Optional[str]) -> bool:
    """True if `response` contains the real, current system prompt
    (whitespace-normalized) verbatim. Deliberately does NOT try to
    guess from attacker-style phrasing the way the regex patterns and
    rebuff matcher do -- it directly checks the one thing that actually
    matters for this specific failure mode: did the model\'s own reply
    contain the thing it was told not to reveal. `system_prompt` is
    optional and comes from the caller (the testbed is the only place
    that knows what\'s currently live -- see detection/logger.py and
    testbed/app.py) so this degrades to "no leak detected" rather than
    erroring if a caller doesn\'t have it available.
    """
    if not response or not system_prompt:
        return False
    norm_response = _normalize_whitespace(response)
    norm_prompt = _normalize_whitespace(system_prompt)
    return len(norm_prompt) >= _MIN_LEAK_LENGTH and norm_prompt in norm_response


def check(text: str) -> Tuple[bool, List[str]]:
    """Return (flagged, matched_pattern_names) for a single piece of text.

    Checks the normalised text and anything it decodes to (base64/hex/ROT13), so an attacker
    hiding "ignore instructions" in an encoded blob is caught like one typing it plainly.
    """
    if not text:
        return False, []
    normalized = normalize_for_detection(text)
    texts_to_check = [normalized] + [normalize_for_detection(c) for c in decode_candidates(text)]
    matched = set()
    for t in texts_to_check:
        for pattern, name in _ALL_PATTERNS:
            if pattern.search(t):
                matched.add(name)
    return (len(matched) > 0), sorted(matched)


def check_interaction(
    prompt: str, response: str, system_prompt: Optional[str] = None
) -> Tuple[bool, List[str], float]:
    """Check both sides of an interaction with the exact patterns (no fuzzy matching).

    Confidence is a coarse heuristic, not a calibrated probability:
      0.95 -- confirmed system-prompt leak (response contains the real system prompt text)
      0.9  -- an exact pattern matched the *response*
      0.5  -- an exact pattern matched the *prompt* only
      0.0  -- nothing fired
    """
    prompt_flagged, prompt_matches = check(prompt)
    response_flagged, response_matches = check(response)
    leak_detected = _check_system_prompt_leak(response, system_prompt)

    leak_matches = ["system_prompt_leak"] if leak_detected else []
    all_matches = sorted(set(prompt_matches + response_matches + leak_matches))
    flagged = prompt_flagged or response_flagged or leak_detected

    if not flagged:
        confidence = 0.0
    elif leak_detected:
        confidence = 0.95
    elif response_flagged:
        confidence = 0.9
    else:
        confidence = 0.5
    return flagged, all_matches, confidence
