"""Rule-based PII detection using regular expressions and column-name hints."""

import re

PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?:\+1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "DATE_OF_BIRTH": re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
}

# Column names that strongly suggest PII even when values are hard to match.
COLUMN_HINTS = {
    "NAME": ("name", "first_name", "last_name", "full_name"),
    "ADDRESS": ("address", "street", "addr"),
    "EMAIL": ("email", "e_mail"),
    "PHONE": ("phone", "mobile", "cell"),
    "SSN": ("ssn", "social"),
    "DATE_OF_BIRTH": ("dob", "birth", "birthday"),
}


def luhn_valid(number: str) -> bool:
    """Check a card number with the Luhn checksum to cut false positives."""
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_pii(text: str) -> list[dict]:
    """Return every PII match in a piece of text as {type, value, start, end}."""
    if not isinstance(text, str):
        return []
    found = []
    for pii_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group()
            if pii_type == "CREDIT_CARD" and not luhn_valid(value):
                continue
            found.append({"type": pii_type, "value": value, "start": match.start(), "end": match.end()})
    return found


def column_hint(column_name: str) -> str | None:
    """Guess a PII type from a column name, or None."""
    name = column_name.lower()
    for pii_type, keywords in COLUMN_HINTS.items():
        if any(k in name for k in keywords):
            return pii_type
    return None
