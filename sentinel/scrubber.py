from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .entities import EntityType, PRESETS
from .patterns import find_matches, Match
from .vault import Vault


@dataclass
class ScrubResult:
    original: str
    scrubbed: str
    vault: Vault
    matches: list[Match]

    @property
    def entity_count(self) -> int:
        return len(self.matches)

    @property
    def entity_types_found(self) -> set[EntityType]:
        return {m.entity_type for m in self.matches}

    @property
    def has_pii(self) -> bool:
        return bool(self.matches)

    def summary(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for m in self.matches:
            counts[m.entity_type.value] = counts.get(m.entity_type.value, 0) + 1
        return {"total_entities": self.entity_count, "entity_types": counts, "has_pii": self.has_pii}


class Sentinel:
    def __init__(
        self,
        mode: str = "default",
        enabled_types: Optional[set[EntityType]] = None,
    ) -> None:
        if enabled_types is not None:
            self.enabled_types = enabled_types
        elif mode in PRESETS:
            self.enabled_types = PRESETS[mode]
        else:
            raise ValueError(f"Unknown mode '{mode}'. Choose from: {list(PRESETS.keys())}")

    def scrub(self, text: str, vault: Optional[Vault] = None) -> ScrubResult:
        if vault is None:
            vault = Vault()
        matches = find_matches(text, self.enabled_types)
        scrubbed = text
        for match in reversed(matches):
            token = vault.tokenize(match.entity_type.value, match.value)
            scrubbed = scrubbed[:match.start] + token + scrubbed[match.end:]
        return ScrubResult(original=text, scrubbed=scrubbed, vault=vault, matches=matches)

    def rehydrate(self, text: str, vault: Vault) -> str:
        return vault.rehydrate(text)


_default_sentinel = Sentinel(mode="default")


def scrub(
    text: str,
    mode: str = "default",
    vault: Optional[Vault] = None,
) -> tuple[str, Vault]:
    shield = Sentinel(mode=mode) if mode != "default" else _default_sentinel
    result = shield.scrub(text, vault=vault)
    return result.scrubbed, result.vault


def rehydrate(text: str, vault: Vault) -> str:
    return vault.rehydrate(text)
