from __future__ import annotations

import re
from dataclasses import dataclass

from .entities import EntityType


@dataclass
class Match:
    entity_type: EntityType
    value: str
    start: int
    end: int


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    digits.reverse()
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _make_ip_validator() -> re.Pattern[str]:
    octet = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    return re.compile(
        rf"\b{octet}\.{octet}\.{octet}\.{octet}\b"
    )


# Patterns in priority order.  Each entry: (EntityType, compiled_pattern, extra_validator_or_None)
# The priority list determines which pattern wins on position tie / overlap.
_PATTERN_DEFS: list[tuple[EntityType, re.Pattern[str], object]] = []


def _build_patterns() -> list[tuple[EntityType, re.Pattern[str], object]]:
    defs: list[tuple[EntityType, re.Pattern[str], object]] = []

    # 1. JWT
    defs.append((
        EntityType.JWT,
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        None,
    ))

    # 2. API_KEY
    defs.append((
        EntityType.API_KEY,
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{20,}"
            r"|AIza[A-Za-z0-9_-]{35}"
            r"|AKIA[A-Z0-9]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{36}"
            r"|xoxb-[0-9]+-[A-Za-z0-9]+"
            r"|sk_live_[A-Za-z0-9]+"
            r"|rk_live_[A-Za-z0-9]+)\b"
        ),
        None,
    ))

    # 3. CREDIT_CARD — Visa/MC/Amex/Discover with Luhn validation
    def _cc_validator(m: re.Match[str]) -> bool:
        digits = re.sub(r"[\s\-]", "", m.group())
        return _luhn_valid(digits)

    defs.append((
        EntityType.CREDIT_CARD,
        re.compile(
            r"\b(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"          # Visa 13 or 16
            r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"  # MC
            r"|3[47][0-9]{13}"                   # Amex 15
            r"|6(?:011|5[0-9]{2})[0-9]{12}"      # Discover 16
            r")\b"
        ),
        _cc_validator,
    ))

    # 4. ROUTING_NUMBER — keyword prefix REQUIRED (non-optional) to avoid SSN collision
    defs.append((
        EntityType.ROUTING_NUMBER,
        re.compile(r"\b(?:routing(?:\s+number)?[:\s]+)[0-9]{9}\b", re.IGNORECASE),
        None,
    ))

    # 5. BANK_ACCOUNT
    defs.append((
        EntityType.BANK_ACCOUNT,
        re.compile(r"\b(?:account(?:\s+number)?[:\s]+)[0-9]{8,17}\b", re.IGNORECASE),
        None,
    ))

    # 6. SSN
    defs.append((
        EntityType.SSN,
        re.compile(
            r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
        ),
        None,
    ))

    # 7. PASSPORT
    defs.append((
        EntityType.PASSPORT,
        re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"),
        None,
    ))

    # 8. DRIVERS_LICENSE
    defs.append((
        EntityType.DRIVERS_LICENSE,
        re.compile(r"\b(?:DL|D\.?L\.?|license)[:\s#]*[A-Z0-9]{5,15}\b", re.IGNORECASE),
        None,
    ))

    # 9. MRN
    defs.append((
        EntityType.MRN,
        re.compile(
            r"\b(?:MRN|medical\s+record(?:\s+number)?)[:\s#]*[A-Z0-9]{5,12}\b",
            re.IGNORECASE,
        ),
        None,
    ))

    # 10. NPI
    defs.append((
        EntityType.NPI,
        re.compile(r"\b(?:NPI)[:\s]*[0-9]{10}\b", re.IGNORECASE),
        None,
    ))

    # 11. DEA
    defs.append((
        EntityType.DEA,
        re.compile(r"\b[A-Z]{2}[0-9]{7}\b"),
        None,
    ))

    # 12. EMAIL
    defs.append((
        EntityType.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        None,
    ))

    # 13. PHONE — use lookbehind/lookahead instead of \b so (800) format is caught
    defs.append((
        EntityType.PHONE,
        re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}(?!\d)"
        ),
        None,
    ))

    # 14. DATE_OF_BIRTH — context-aware, keyword prefix required
    defs.append((
        EntityType.DATE_OF_BIRTH,
        re.compile(
            r"(?:dob|date\s+of\s+birth|born|birthday)[:\s]*"
            r"(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}"
            r"|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}"
            r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}"
            r"|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4})",
            re.IGNORECASE,
        ),
        None,
    ))

    # 15. IP_ADDRESS — validated 0-255 per octet
    defs.append((
        EntityType.IP_ADDRESS,
        _make_ip_validator(),
        None,
    ))

    # 16. MAC_ADDRESS
    defs.append((
        EntityType.MAC_ADDRESS,
        re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
        None,
    ))

    # 17. ZIP_CODE
    defs.append((
        EntityType.ZIP_CODE,
        re.compile(r"\b[0-9]{5}(?:-[0-9]{4})?\b"),
        None,
    ))

    # 18. COORDINATES — lat,lon format
    defs.append((
        EntityType.COORDINATES,
        re.compile(
            r"\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)"
            r"\s*,\s*"
            r"[-+]?(?:180(?:\.0+)?|(?:(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?))\b"
        ),
        None,
    ))

    return defs


_COMPILED_PATTERNS = _build_patterns()


def find_matches(text: str, enabled_types: set[EntityType]) -> list[Match]:
    """Return non-overlapping matches sorted by start position.

    Priority is determined by pattern order in _COMPILED_PATTERNS.
    Greedy left-to-right: once a span is consumed it cannot be claimed by a
    lower-priority pattern even if that pattern would produce a longer match.
    """
    # Collect all raw candidates, annotated with their priority index
    candidates: list[tuple[int, int, int, EntityType, str]] = []  # (start, end, priority, type, value)

    for priority, (entity_type, pattern, validator) in enumerate(_COMPILED_PATTERNS):
        if entity_type not in enabled_types:
            continue
        for m in pattern.finditer(text):
            if validator is not None:
                if not validator(m):
                    continue
            candidates.append((m.start(), m.end(), priority, entity_type, m.group()))

    # Sort: primary by start, secondary by priority (lower index = higher priority),
    # tertiary by span length descending (longer match preferred on tie)
    candidates.sort(key=lambda c: (c[0], c[2], -(c[1] - c[0])))

    matches: list[Match] = []
    last_end = 0
    for start, end, _priority, entity_type, value in candidates:
        if start < last_end:
            continue
        matches.append(Match(entity_type=entity_type, value=value, start=start, end=end))
        last_end = end

    return matches
