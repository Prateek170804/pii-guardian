"""Name-based and value-based sensitive-data detectors.

Returns structured signals; never returns or stores raw sample values.
All value regexes are simple/RE2-friendly so behavior is consistent with Snowflake.
"""
import re


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------
def normalize_name(name: str) -> str:
    return (name or "").strip().lower()


def _name_forms(name: str) -> tuple[str, str]:
    """Return (raw, separator-spaced) forms.

    Underscore is a regex word character, so `\\bssn\\b` would miss `claimant_ssn`.
    Matching against a space-separated form as well makes word boundaries fire
    across separators, while the raw form still satisfies patterns like `social_?security`.
    """
    raw = normalize_name(name)
    spaced = re.sub(r"[_\-.]+", " ", raw)
    return raw, spaced


# ---------------------------------------------------------------------------
# Name-based detection
# ---------------------------------------------------------------------------
# The generic person-name patterns match ANY "name". They are demoted when the
# column is clearly a NON-person "X name" (a street/building/file/form/... name),
# so STREET_NAME / LOC_BLDG_NAME / GDW_SRC_FILE_NAME aren't tagged as a person's
# direct identifier. (The specific person patterns like insured_name are unaffected.)
_GENERIC_NAME_PATTERNS = (r"\bname\b", r"\bnm\b")
_NON_PERSON_NAME = re.compile(
    r"\b(file|form|field|table|column|object|report|template|src|source|system|server|"
    r"host|db|database|schema|batch|job|log|folder|dir|program|scheme|product|brand|"
    r"company|building|bldg|room|rooms|apt|ste|suite|floor|unit|street|site|zone)\b",
    re.IGNORECASE,
)


class NameDetector:
    """Matches a column name against the CDE dictionary."""

    def __init__(self, cde_dictionary: dict, strengths: dict):
        self.strong = strengths.get("strong", 0.9)
        self.weak = strengths.get("weak", 0.5)
        # Pre-compile patterns: category -> [(compiled, strength_value, strength_label)]
        self.patterns: dict[str, list] = {}
        for category, groups in cde_dictionary.get("categories", {}).items():
            entries = []
            for label, value in (("strong", self.strong), ("weak", self.weak)):
                for pat in groups.get(label, []) or []:
                    entries.append((re.compile(pat, re.IGNORECASE), value, label))
            self.patterns[category] = entries

    def detect(self, column_name: str) -> dict | None:
        """Return the best name signal for a column, or None."""
        raw, spaced = _name_forms(column_name)
        best = None  # (category, signal, label, pattern)
        for category, entries in self.patterns.items():
            for compiled, value, label in entries:
                if compiled.search(raw) or compiled.search(spaced):
                    if (category == "DIRECT_IDENTIFIER"
                            and compiled.pattern in _GENERIC_NAME_PATTERNS
                            and _NON_PERSON_NAME.search(spaced)):
                        continue  # e.g. 'street/building/file name' is not a person
                    if best is None or value > best[1]:
                        best = (category, value, label, compiled.pattern)
        if best is None:
            return None
        return {"category": best[0], "signal": best[1], "strength": best[2], "pattern": best[3]}


# A small, explicit name->hint map for choosing a precise masking behavior.
_NAME_HINTS = [
    ("ssn", re.compile(r"\bssn\b|social_?security|tax_?id|\btin\b", re.I)),
    ("email", re.compile(r"e_?mail", re.I)),
    ("phone", re.compile(r"\bphone\b|\bmobile\b|\bmsisdn\b", re.I)),
    ("card", re.compile(r"card_?(no|num|number)|\bpan\b|cc_?(no|num|number)|credit_?card", re.I)),
]


def name_hint(column_name: str) -> str | None:
    raw, spaced = _name_forms(column_name)
    for hint, pat in _NAME_HINTS:
        if pat.search(raw) or pat.search(spaced):
            return hint
    return None


# ---------------------------------------------------------------------------
# Value-based detection
# ---------------------------------------------------------------------------
def _luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# SSN: the dashed form is specific. A bare 9-digit run is ambiguous with account /
# member / record IDs, so it is still detected but down-weighted (see specificity
# below) — surfaced for review rather than auto-classified.
_RE_SSN_DASHED = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_RE_SSN_BARE = re.compile(r"^\d{9}$")
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Phone: require at least one separator (space/dot/dash) between the digit groups,
# parentheses around the area code allowed. A bare run of 10 digits is far more
# often a policy/account/record number than a phone, so digits alone must NOT match.
_RE_PHONE = re.compile(r"^\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]?\d{4}$")
_RE_ZIP = re.compile(r"^\d{5}(-\d{4})?$")
_RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _is_card(v: str) -> bool:
    return _luhn_ok(re.sub(r"[ \-]", "", v))


# value detector -> (predicate, implied category, specificity)
#
# `specificity` ∈ (0,1] gates a VALUE-ONLY match (a column whose *name* gave no
# signal). Distinctive formats (email, dashed SSN) are trusted on their own;
# ambiguous numeric formats (bare ZIP-length, bare date, bare 9-digit) are weak
# evidence alone and need a corroborating column name to reach the auto threshold.
# When a name signal IS present, fusion uses the raw ratio (Classifier._score), so
# named columns like ZIP_CODE — bare 5-digit values, but clearly named — are
# unaffected. This is what stops plain numeric ID/count columns from being labelled
# CONTACT just because they happen to be 5 or 10 digits long.
_VALUE_DETECTORS = [
    ("ssn",   lambda v: bool(_RE_SSN_DASHED.match(v)), "GOV_ID",           1.0),
    ("ssn",   lambda v: bool(_RE_SSN_BARE.match(v)),   "GOV_ID",           0.5),
    ("email", lambda v: bool(_RE_EMAIL.match(v)),      "CONTACT",          1.0),
    ("card",  _is_card,                                 "FINANCIAL",       0.9),
    ("phone", lambda v: bool(_RE_PHONE.match(v)),      "CONTACT",          0.9),
    ("zip",   lambda v: bool(_RE_ZIP.match(v)),        "CONTACT",          0.4),
    ("dob",   lambda v: bool(_RE_DATE.match(v)),       "QUASI_IDENTIFIER", 0.4),
]


def detect_values(samples: list[str]) -> dict | None:
    """Run value detectors over non-null samples.

    Returns the best-matching detector with its match ratio, implied category and
    specificity (plus the sample count). Never returns the sample values themselves.
    """
    values = [str(v).strip() for v in (samples or []) if str(v).strip()]
    n = len(values)
    if n == 0:
        return None
    best = None  # (label, ratio, category, specificity)
    for label, predicate, category, specificity in _VALUE_DETECTORS:
        matches = sum(1 for v in values if predicate(v))
        ratio = matches / n
        if ratio > 0 and (best is None or ratio > best[1]):
            best = (label, ratio, category, specificity)
    if best is None:
        return None
    return {"detector": best[0], "ratio": round(best[1], 3), "category": best[2],
            "specificity": best[3], "sample_count": n}
