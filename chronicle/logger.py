import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceEntry:
    entry_id: str
    user_id: str
    action: str
    timestamp: str
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "entry_id": self.entry_id,
                "user_id": self.user_id,
                "action": self.action,
                "timestamp": self.timestamp,
                "input_hash": self.input_hash,
                "output_hash": self.output_hash,
                "metadata": self.metadata,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        )
        return _sha256(payload)

    def finalize(self) -> "TraceEntry":
        self.entry_hash = self.compute_hash()
        return self


class TraceContext:
    def __init__(self, logger: "Logger", user_id: str, action: str):
        self._logger = logger
        self._entry = TraceEntry(
            entry_id=str(uuid.uuid4()),
            user_id=user_id,
            action=action,
            timestamp=_now_iso(),
            prev_hash=logger._last_hash,
        )

    def record_input(self, text: str) -> None:
        self._entry.input_hash = _sha256(text)

    def record_output(self, text: str) -> None:
        self._entry.output_hash = _sha256(text)

    def record_metadata(self, **kwargs: Any) -> None:
        self._entry.metadata.update(kwargs)

    def __enter__(self) -> "TraceContext":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self._entry.metadata["error"] = str(exc_val)
            self._entry.metadata["error_type"] = exc_type.__name__
        self._entry.finalize()
        self._logger._write(self._entry)
        return None  # do not suppress exceptions


class LocalStorage:
    def __init__(self, path: str = "./paladin-audit.log"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: TraceEntry) -> None:
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        entries: list[dict] = []
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def verify_chain(self) -> tuple[bool, list[str]]:
        entries = self.read_all()
        errors: list[str] = []
        prev_hash: Optional[str] = None

        for i, entry_dict in enumerate(entries):
            # Recompute hash from payload fields (excluding entry_hash itself)
            payload = json.dumps(
                {
                    "entry_id": entry_dict["entry_id"],
                    "user_id": entry_dict["user_id"],
                    "action": entry_dict["action"],
                    "timestamp": entry_dict["timestamp"],
                    "input_hash": entry_dict["input_hash"],
                    "output_hash": entry_dict["output_hash"],
                    "metadata": entry_dict["metadata"],
                    "prev_hash": entry_dict["prev_hash"],
                },
                sort_keys=True,
            )
            expected_hash = _sha256(payload)

            if entry_dict.get("entry_hash") != expected_hash:
                errors.append(
                    f"Entry {i} ({entry_dict.get('entry_id')}): entry_hash mismatch"
                )

            if entry_dict.get("prev_hash") != prev_hash:
                errors.append(
                    f"Entry {i} ({entry_dict.get('entry_id')}): prev_hash mismatch"
                )

            prev_hash = entry_dict.get("entry_hash")

        return (len(errors) == 0, errors)


class Logger:
    def __init__(self, storage: str | Any = "local", log_path: str = "./paladin-audit.log"):
        if storage == "local":
            self._storage = LocalStorage(log_path)
        else:
            self._storage = storage
        self._last_hash: Optional[str] = self._get_last_hash()

    def _get_last_hash(self) -> Optional[str]:
        try:
            entries = self._storage.read_all()
            if entries:
                return entries[-1].get("entry_hash")
        except Exception:
            pass
        return None

    def _write(self, entry: TraceEntry) -> None:
        self._storage.append(entry)
        self._last_hash = entry.entry_hash

    def trace(self, user_id: str, action: str) -> TraceContext:
        return TraceContext(self, user_id, action)

    def verify(self) -> tuple[bool, list[str]]:
        return self._storage.verify_chain()

    def export(self, format: str = "json") -> str:
        entries = self._storage.read_all()
        if format == "json":
            return json.dumps(entries, indent=2)
        # CSV
        if not entries:
            return ""
        headers = list(entries[0].keys())
        lines = [",".join(headers)]
        for entry in entries:
            row = [str(entry.get(h, "")) for h in headers]
            lines.append(",".join(row))
        return "\n".join(lines)
