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
"""

import base64
import codecs
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
    text = _canonicalize_homoglyphs(text)
    return text


_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def decode_candidates(text: str) -> list:
    """
    Returns extra strings to ALSO run detection against, decoded from any
    obfuscation found in the original text. The original text is still
    checked as-is elsewhere -- this only adds candidates, never replaces
    the input.

    ROT13 is always tried, since it's a pure reversible substitution
    (ROT13(ROT13(x)) == x) -- there's no way to "detect" it's present the
    way base64/hex have a distinctive charset, so the cheap, safe option
    is to just always compute it and scan it too. This can never
    introduce a false positive that scanning the original text wouldn't
    already risk, since ROT13 just relabels letters, it doesn't change
    text structure.

    Base64 and hex are detected by finding runs that look like them and
    attempting to decode; a candidate is kept only if it decodes to
    printable text, so decoding garbage doesn't add noise.
    """
    if not text:
        return []
    candidates = [codecs.encode(text, "rot_13")]

    for match in _BASE64_RUN.finditer(text):
        try:
            decoded = base64.b64decode(match.group(), validate=True).decode("utf-8")
            if decoded.isprintable():
                candidates.append(decoded)
        except Exception:
            pass

    for match in _HEX_RUN.finditer(text):
        try:
            decoded = bytes.fromhex(match.group()).decode("utf-8")
            if decoded.isprintable():
                candidates.append(decoded)
        except Exception:
            pass

    return candidates


# Common Latin-lookalike characters from Cyrillic and Greek, used to evade
# exact-match patterns by substituting visually identical letters. NFKC
# does NOT catch these -- Cyrillic 'а' and Latin 'a' are visually
# identical but are different, non-equivalent Unicode code points, so
# NFKC normalization (a compatibility-form fix) leaves them untouched.
# This map is deliberately small and conservative: only characters that
# are near-perfect visual matches for a single Latin letter in most
# fonts, to avoid mangling genuine Cyrillic/Greek text.
_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T", "Н": "H",
    "і": "i", "І": "I", "Ѕ": "S", "ѕ": "s", "Ј": "J", "ј": "j",
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)


def _canonicalize_homoglyphs(text: str) -> str:
    return text.translate(_HOMOGLYPH_TABLE)
