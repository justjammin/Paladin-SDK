from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import wraps
from typing import Callable, Optional
from urllib.parse import urlparse


@dataclass
class Policy:
    action: str
    requires_human: bool = False
    cooldown_seconds: Optional[int] = None
    max_calls_per_minute: Optional[int] = None
    allowlist: Optional[list[str]] = None
    blocklist: Optional[list[str]] = None


class PolicyViolationError(Exception):
    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"[covenant] Policy violation for '{action}': {reason}")


class Gate:
    def __init__(
        self,
        policies: list[Policy],
        approval_fn: Optional[Callable[[str, dict], bool]] = None,
        audit_log_fn: Optional[Callable[[str, bool, str], None]] = None,
    ) -> None:
        self._policies: dict[str, Policy] = {p.action: p for p in policies}
        self._approval_fn = approval_fn or self._default_approval
        self._audit_log_fn = audit_log_fn or self._default_audit
        self._call_times: dict[str, deque[float]] = defaultdict(deque)
        self._last_call: dict[str, float] = {}
        self._lock = threading.Lock()

    def _default_approval(self, action: str, kwargs: dict) -> bool:
        response = input(
            f"\n[covenant] HUMAN APPROVAL REQUIRED\n"
            f"Action: {action}\n"
            f"Args: {kwargs}\n"
            f"Approve? (yes/no): "
        )
        return response.strip().lower() in ("yes", "y")

    def _default_audit(self, action: str, approved: bool, reason: str) -> None:
        status = "APPROVED" if approved else "BLOCKED"
        print(f"[covenant] {status} | action={action} | reason={reason}")

    def _check_policy(self, action: str, kwargs: dict) -> None:
        policy = self._policies.get(action)
        if policy is None:
            return

        now = time.monotonic()

        with self._lock:
            if policy.cooldown_seconds is not None:
                last = self._last_call.get(action)
                if last is not None:
                    elapsed = now - last
                    if elapsed < policy.cooldown_seconds:
                        remaining = round(policy.cooldown_seconds - elapsed, 1)
                        raise PolicyViolationError(
                            action, f"cooldown active — {remaining}s remaining"
                        )

            if policy.max_calls_per_minute is not None:
                window = self._call_times[action]
                cutoff = now - 60
                while window and window[0] < cutoff:
                    window.popleft()
                if len(window) >= policy.max_calls_per_minute:
                    raise PolicyViolationError(
                        action,
                        f"rate limit exceeded ({policy.max_calls_per_minute}/min)",
                    )
                window.append(now)

            self._last_call[action] = now

        url = kwargs.get("url") or kwargs.get("endpoint") or kwargs.get("to")
        if url and isinstance(url, str) and url.startswith("http"):
            domain = urlparse(url).netloc
            if policy.blocklist and any(b in domain for b in policy.blocklist):
                raise PolicyViolationError(action, f"domain '{domain}' is blocklisted")
            if policy.allowlist and not any(a in domain for a in policy.allowlist):
                raise PolicyViolationError(action, f"domain '{domain}' not in allowlist")

        if policy.requires_human:
            approved = self._approval_fn(action, kwargs)
            self._audit_log_fn(action, approved, "human approval requested")
            if not approved:
                raise PolicyViolationError(action, "human approval denied")
        else:
            self._audit_log_fn(action, True, "policy passed")

    def guard(self, action: str) -> Callable:
        def decorator(fn: Callable) -> Callable:
            @wraps(fn)
            def wrapper(*args: object, **kwargs: object) -> object:
                self._check_policy(action, kwargs)  # type: ignore[arg-type]
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def execute(self, action: str, fn: Callable, **kwargs: object) -> object:
        self._check_policy(action, kwargs)  # type: ignore[arg-type]
        return fn(**kwargs)
