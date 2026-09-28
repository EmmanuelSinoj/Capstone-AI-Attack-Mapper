"""
preprocessing.py

Normalizes text before it reaches ANY detection signal (regex or
Rebuff fuzzy matching). Both signals compare literal characters --
neither can see through an attacker inserting invisible characters
between letters, or substituting look-alike Unicode characters for
ASCII ones. This step closes that gap without touching the matching
logic itself.

Two things it does:
1. Unicode NFKC normalization -- collapses many compatibility/
   look-alike characters (e.g. full-width Latin letters, certain
   stylized Unicode variants) to their standard ASCII form.
2. Strips zero-width and invisible formatting characters (zero-width
   space, zero-width joiner/non-joiner, word joiner, BOM, soft
   hyphen) that would otherwise silently break every pattern match
   by splitting a word apart at the character level.

Known limitation: NFKC does not catch every possible homoglyph attack
(e.g. Cyrillic 'а' vs Latin 'a' are visually identical but NOT
NFKC-equivalent, since they're semantically different letters in
Unicode). A full homoglyph-confusables map would close that gap
further but adds a real maintenance burden -- flagged as a possible
future addition, not built here.

Source: detection_v4 in Emmanuel's heuristics v1-v4 comparison
(PR #2, "Heuristic detection comparison (v1-v4): recommend v4"),
brought into the live pipeline unmodified.
"""

import re
import unicodedata

_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad]"
    # zero-width space, zero-width non-joiner, zero-width joiner,
    # word joiner, byte-order-mark, soft hyphen
)

def normalize_for_detection(text: str) -> str:
    if not text:
        return text
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_CHARS.sub("", text)
    return text
