from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class ScanResult:
    input: str
    risk: float
    reasons: list[str]
    flagged_segments: list[str]

    @property
    def is_safe(self) -> bool:
        return self.risk < 0.5

    @property
    def is_high_risk(self) -> bool:
        return self.risk >= 0.7


class InjectionRiskError(Exception):
    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__(f"Injection risk detected: {', '.join(reasons)}")


# ---------------------------------------------------------------------------
# Compiled pattern groups
# ---------------------------------------------------------------------------

ROLE_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\b", re.IGNORECASE),
    re.compile(r"\bforget\s+(everything|all|your)\b", re.IGNORECASE),
    re.compile(r"\bnew\s+(role|persona|instructions?|system\s+prompt)\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(you\s+are|to\s+be)\b", re.IGNORECASE),
    re.compile(r"\byou\s+must\s+now\b", re.IGNORECASE),
    re.compile(r"\boverride\s+(your|all)\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(your|all|previous)\b", re.IGNORECASE),
]

DELIMITER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"#{3,}"),
    re.compile(r"-{3,}"),
    re.compile(r"={3,}"),
    re.compile(r"<\|(?:system|user|assistant|im_start|im_end)\|>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[\/INST\]"),
    re.compile(r"<<SYS>>|<</SYS>>"),
    re.compile(r"<s>|</s>"),
]

JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bDAN\b"),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bunfiltered\b", re.IGNORECASE),
    re.compile(r"\bno\s+restrictions?\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+(any\s+)?limitations?\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:your\s+|all\s+)?(safety|filters?|restrictions?|guidelines?)\b", re.IGNORECASE),
    re.compile(r"\bsafety\s+(off|disabled|removed)\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
    re.compile(r"\bgrandma\s+trick\b", re.IGNORECASE),
]

_HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "о": "o",  # Cyrillic о
    "р": "p",  # Cyrillic р
    "с": "c",  # Cyrillic с
    "х": "x",  # Cyrillic х
}

_ENCODING_KEYWORDS = {"ignore", "system", "instruction", "override"}

_IMPERATIVE_WORDS = {
    "do", "dont", "don't", "must", "should", "shall",
    "never", "always", "ignore", "forget", "stop", "start",
    "begin", "respond", "reply", "output", "write", "say",
    "tell", "give", "provide", "list",
}


def _normalize_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _check_encoding_tricks(text: str) -> list[tuple[float, str, str]]:
    """Return list of (score_contribution, reason, flagged_segment)."""
    results: list[tuple[float, str, str]] = []

    # Base64 chunk check
    words = text.split()
    for word in words:
        cleaned = word.strip(".,;:!?\"'()")
        if len(cleaned) < 8:
            continue
        # Try to pad and decode
        padding = (4 - len(cleaned) % 4) % 4
        try:
            decoded = base64.b64decode(cleaned + "=" * padding, validate=True).decode("utf-8", errors="ignore")
            decoded_lower = decoded.lower()
            if any(kw in decoded_lower for kw in _ENCODING_KEYWORDS):
                results.append((0.3, "base64 encoding trick", cleaned))
        except Exception:
            pass

    # Homoglyph check
    normalized = _normalize_homoglyphs(text)
    if normalized != text:
        # Re-scan normalized text for role overrides
        for pattern in ROLE_OVERRIDE_PATTERNS:
            if pattern.search(normalized):
                results.append((0.35, "unicode homoglyph obfuscation", text[:40]))
                break

    return results


def _check_instruction_density(text: str) -> list[tuple[float, str, str]]:
    """Return list of (score_contribution, reason, flagged_segment)."""
    words = text.lower().split()
    if len(words) < 10:
        return []
    imperative_count = sum(1 for w in words if w.rstrip(".,;:!?") in _IMPERATIVE_WORDS)
    ratio = imperative_count / len(words)
    if ratio > 0.25:
        contrib = min(ratio, 0.4)
        return [(contrib, "high instruction density", text[:60])]
    return []


def scan(text: str) -> ScanResult:
    score = 0.0
    reasons: list[str] = []
    flagged: list[str] = []

    # 1. Role override — first hit only
    for pattern in ROLE_OVERRIDE_PATTERNS:
        m = pattern.search(text)
        if m:
            score += 0.35
            reasons.append("role override")
            flagged.append(m.group())
            break

    # 2. Delimiters
    delimiter_hits = 0
    for pattern in DELIMITER_PATTERNS:
        m = pattern.search(text)
        if m:
            delimiter_hits += 1
            flagged.append(m.group())
    if delimiter_hits:
        contrib = min(delimiter_hits * 0.15, 0.35)
        score += contrib
        reasons.append("delimiter injection")

    # 3. Jailbreak keywords
    jailbreak_hits = 0
    for pattern in JAILBREAK_PATTERNS:
        m = pattern.search(text)
        if m:
            jailbreak_hits += 1
            flagged.append(m.group())
    if jailbreak_hits:
        contrib = min(jailbreak_hits * 0.25, 0.40)
        score += contrib
        reasons.append("jailbreak keyword")

    # 4. Encoding tricks
    for contrib, reason, segment in _check_encoding_tricks(text):
        score += contrib
        if reason not in reasons:
            reasons.append(reason)
        flagged.append(segment)

    # 5. Instruction density
    for contrib, reason, segment in _check_instruction_density(text):
        score += contrib
        if reason not in reasons:
            reasons.append(reason)
        flagged.append(segment)

    return ScanResult(
        input=text,
        risk=min(round(score, 3), 1.0),
        reasons=reasons,
        flagged_segments=list(set(flagged)),
    )


class BulwarkWall:
    def __init__(
        self,
        threshold: float = 0.6,
        mode: str = "block",
        log_fn: Optional[Callable[[ScanResult], None]] = None,
    ) -> None:
        self.threshold = threshold
        self.mode = mode
        self._log_fn = log_fn or self._default_log

    @staticmethod
    def _default_log(r: ScanResult) -> None:
        print(f"[bulwark] risk={r.risk:.2f} reasons={r.reasons}")

    def check(self, text: str) -> ScanResult:
        result = scan(text)
        if result.risk >= self.threshold:
            self._log_fn(result)
            if self.mode == "block":
                raise InjectionRiskError(result.reasons)
        return result
