from llm_guard.input_scanners import Regex, BanSubstrings
from llm_guard.output_scanners import NoRefusalLight
from rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (all |any )?(previous|prior|above) (instructions|rules)",
    r"you are now (DAN|in developer mode|unrestricted)",
    r"pretend (you have|to have) no (restrictions|rules|filters)",
    r"reveal your (system prompt|instructions|rules)",
    r"repeat (the words|everything) above",
    r"act as if you have no (guidelines|restrictions)",
]

INJECTION_SUBSTRINGS = [
    "jailbreak",
    "developer mode",
    "no restrictions",
    "do anything now",
]

REBUFF_SCORE_THRESHOLD = 0.65

_input_regex_scanner = Regex(patterns=INJECTION_PATTERNS, is_blocked=True, redact=False)
_input_substring_scanner = BanSubstrings(substrings=INJECTION_SUBSTRINGS, case_sensitive=False)
_output_scanner = NoRefusalLight()


def scan_input(text: str) -> dict:
    matched_by = []
    scores = []

    _, is_valid_regex, score_regex = _input_regex_scanner.scan(text)
    if not is_valid_regex:
        matched_by.append("regex")
    scores.append(score_regex)

    _, is_valid_substr, score_substr = _input_substring_scanner.scan(text)
    if not is_valid_substr:
        matched_by.append("substring")
    scores.append(score_substr)

    rebuff_score = detect_prompt_injection_using_heuristic_on_input(text)
    if rebuff_score >= REBUFF_SCORE_THRESHOLD:
        matched_by.append("rebuff_fuzzy")
    scores.append(rebuff_score)

    return {
        "flagged": len(matched_by) > 0,
        "risk_score": max(scores),
        "matched_by": matched_by,
    }


def scan_output(prompt: str, output: str) -> dict:
    _, is_valid, score = _output_scanner.scan(prompt, output)
    return {
        "flagged": is_valid,
        "risk_score": score,
    }
