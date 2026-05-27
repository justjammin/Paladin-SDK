import json
import pytest
from chronicle.logger import Logger, TraceEntry, LocalStorage


def test_hash_deterministic():
    entry = TraceEntry(
        entry_id="abc-123",
        user_id="user-1",
        action="llm_call",
        timestamp="2024-01-01T00:00:00+00:00",
    )
    h1 = entry.compute_hash()
    h2 = entry.compute_hash()
    assert h1 == h2


def test_finalize_sets_entry_hash():
    entry = TraceEntry(
        entry_id="abc-123",
        user_id="user-1",
        action="llm_call",
        timestamp="2024-01-01T00:00:00+00:00",
    )
    entry.finalize()
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64
    # all hex chars
    int(entry.entry_hash, 16)


def test_basic_trace(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with log.trace("user-1", "llm_call") as t:
        t.record_input("Hello")
    storage = LocalStorage(log_path)
    entries = storage.read_all()
    assert len(entries) == 1
    assert entries[0]["action"] == "llm_call"
    assert entries[0]["user_id"] == "user-1"


def test_input_hashed_not_stored(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with log.trace("user-1", "llm_call") as t:
        t.record_input("sensitive text here")
    storage = LocalStorage(log_path)
    entries = storage.read_all()
    raw = json.dumps(entries[0])
    assert "sensitive text here" not in raw
    assert entries[0]["input_hash"] is not None


def test_chain_integrity_five_entries(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    for i in range(5):
        with log.trace("user-1", f"action_{i}") as t:
            t.record_input(f"input {i}")
    valid, errors = log.verify()
    assert valid
    assert errors == []


def test_tamper_detection(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with log.trace("user-1", "llm_call") as t:
        t.record_input("Hello")

    storage = LocalStorage(log_path)
    entries = storage.read_all()
    entries[0]["user_id"] = "TAMPERED"

    # Overwrite the log with the tampered entry
    with open(log_path, "w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")

    new_log = Logger(log_path=log_path)
    valid, errors = new_log.verify()
    assert not valid
    assert len(errors) > 0


def test_error_captured(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with pytest.raises(ValueError):
        with log.trace("user-1", "llm_call") as t:
            t.record_input("Hello")
            raise ValueError("LLM timeout")

    storage = LocalStorage(log_path)
    entries = storage.read_all()
    assert entries[0]["metadata"]["error"] == "LLM timeout"
    assert entries[0]["metadata"]["error_type"] == "ValueError"


def test_export_json(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with log.trace("user-1", "llm_call") as t:
        t.record_input("Hello")
    exported = log.export(format="json")
    parsed = json.loads(exported)
    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_multiple_users_interleaved(tmp_path):
    log_path = str(tmp_path / "audit.log")
    log = Logger(log_path=log_path)
    with log.trace("alice", "action_a") as t:
        t.record_input("alice input")
    with log.trace("bob", "action_b") as t:
        t.record_input("bob input")
    with log.trace("alice", "action_c") as t:
        t.record_input("alice input 2")

    storage = LocalStorage(log_path)
    entries = storage.read_all()
    assert len(entries) == 3

    valid, errors = log.verify()
    assert valid
    assert errors == []
