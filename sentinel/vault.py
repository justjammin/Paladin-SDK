import hashlib
import threading
from typing import Optional


class Vault:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._lock = threading.Lock()

    def tokenize(self, entity_type: str, value: str) -> str:
        hash_suffix = hashlib.sha256(value.encode()).hexdigest()[:6].upper()
        token = f"[{entity_type}_{hash_suffix}]"
        with self._lock:
            self._store[token] = value
        return token

    def get(self, token: str) -> Optional[str]:
        with self._lock:
            return self._store.get(token)

    def rehydrate(self, text: str) -> str:
        with self._lock:
            result = text
            for token, value in self._store.items():
                result = result.replace(token, value)
            return result

    def all_tokens(self) -> dict[str, str]:
        with self._lock:
            return dict(self._store)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
