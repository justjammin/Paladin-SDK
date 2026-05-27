"""Tests for covenant — agent action gates."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

from covenant import Gate, Policy, PolicyViolationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _silent_audit(action: str, approved: bool, reason: str) -> None:
    pass  # suppress printed output during tests


def _make_gate(policy: Policy, **gate_kwargs) -> Gate:
    return Gate(policies=[policy], audit_log_fn=_silent_audit, **gate_kwargs)


# ---------------------------------------------------------------------------
# Rate limit tests
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_rate_limit_enforced_on_third_call(self):
        policy = Policy(action="send_email", max_calls_per_minute=2)
        gate = _make_gate(policy)

        gate.execute("send_email", lambda: None)
        gate.execute("send_email", lambda: None)

        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("send_email", lambda: None)
        assert "rate limit" in exc_info.value.reason

    def test_rate_limit_50_calls_succeed_under_100_per_min(self):
        policy = Policy(action="ping", max_calls_per_minute=100)
        gate = _make_gate(policy)

        for _ in range(50):
            gate.execute("ping", lambda: "ok")  # must not raise

    def test_rate_limit_error_contains_limit_info(self):
        policy = Policy(action="send_email", max_calls_per_minute=1)
        gate = _make_gate(policy)

        gate.execute("send_email", lambda: None)
        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("send_email", lambda: None)
        assert "1/min" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Cooldown tests
# ---------------------------------------------------------------------------

class TestCooldown:
    def test_cooldown_blocks_immediate_retry(self):
        policy = Policy(action="send_sms", cooldown_seconds=60)
        gate = _make_gate(policy)

        gate.execute("send_sms", lambda: None)

        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("send_sms", lambda: None)
        assert "cooldown" in exc_info.value.reason

    def test_cooldown_shows_remaining_time(self):
        policy = Policy(action="send_sms", cooldown_seconds=30)
        gate = _make_gate(policy)

        gate.execute("send_sms", lambda: None)

        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("send_sms", lambda: None)
        # remaining time should be mentioned
        assert "remaining" in exc_info.value.reason or "s remaining" in exc_info.value.reason

    def test_cooldown_action_recorded_correctly(self):
        policy = Policy(action="charge_card", cooldown_seconds=10)
        gate = _make_gate(policy)

        gate.execute("charge_card", lambda: None)
        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("charge_card", lambda: None)
        assert exc_info.value.action == "charge_card"


# ---------------------------------------------------------------------------
# Domain allowlist / blocklist tests
# ---------------------------------------------------------------------------

class TestDomainPolicy:
    def test_allowlisted_domain_passes(self):
        policy = Policy(action="http_call", allowlist=["stripe.com"])
        gate = _make_gate(policy)
        result = gate.execute("http_call", lambda url: "ok", url="https://api.stripe.com/v1/charges")
        assert result == "ok"

    def test_non_allowlisted_domain_blocked(self):
        policy = Policy(action="http_call", allowlist=["stripe.com"])
        gate = _make_gate(policy)
        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("http_call", lambda url: "ok", url="https://evil.com/steal")
        assert "allowlist" in exc_info.value.reason

    def test_blocklisted_domain_blocked(self):
        policy = Policy(action="http_call", blocklist=["evil.com"])
        gate = _make_gate(policy)
        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("http_call", lambda url: "ok", url="https://evil.com/steal")
        assert "blocklisted" in exc_info.value.reason

    def test_non_blocklisted_domain_passes(self):
        policy = Policy(action="http_call", blocklist=["evil.com"])
        gate = _make_gate(policy)
        result = gate.execute("http_call", lambda url: "safe", url="https://api.stripe.com/charge")
        assert result == "safe"


# ---------------------------------------------------------------------------
# Human approval tests
# ---------------------------------------------------------------------------

class TestHumanApproval:
    def test_approval_granted_fn_executes(self):
        policy = Policy(action="delete_user", requires_human=True)
        gate = Gate(
            policies=[policy],
            approval_fn=lambda action, kwargs: True,
            audit_log_fn=_silent_audit,
        )
        result = gate.execute("delete_user", lambda: "deleted")
        assert result == "deleted"

    def test_approval_denied_raises(self):
        policy = Policy(action="delete_user", requires_human=True)
        gate = Gate(
            policies=[policy],
            approval_fn=lambda action, kwargs: False,
            audit_log_fn=_silent_audit,
        )
        with pytest.raises(PolicyViolationError) as exc_info:
            gate.execute("delete_user", lambda: "deleted")
        assert "denied" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Unregistered action tests
# ---------------------------------------------------------------------------

class TestUnregisteredAction:
    def test_unregistered_action_passes_via_execute(self):
        gate = Gate(policies=[], audit_log_fn=_silent_audit)
        result = gate.execute("anything", lambda: "fine")
        assert result == "fine"

    def test_unregistered_action_passes_via_guard(self):
        gate = Gate(policies=[], audit_log_fn=_silent_audit)

        @gate.guard("unregistered_action")
        def my_fn() -> str:
            return "ok"

        assert my_fn() == "ok"

    def test_guard_decorator_wraps_function(self):
        gate = Gate(policies=[], audit_log_fn=_silent_audit)

        @gate.guard("my_action")
        def compute(x: int, y: int) -> int:
            return x + y

        assert compute(2, 3) == 5


# ---------------------------------------------------------------------------
# PolicyViolationError structure
# ---------------------------------------------------------------------------

class TestPolicyViolationError:
    def test_error_has_action_and_reason(self):
        err = PolicyViolationError("test_action", "some reason")
        assert err.action == "test_action"
        assert err.reason == "some reason"
        assert "test_action" in str(err)
        assert "some reason" in str(err)

    def test_error_is_exception(self):
        err = PolicyViolationError("a", "b")
        assert isinstance(err, Exception)
