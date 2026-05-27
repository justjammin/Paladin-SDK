from __future__ import annotations

from contextlib import contextmanager
from typing import Optional, Callable

from bulwark.scanner import BulwarkWall, InjectionRiskError
from vault.scanner import VaultGuard, SecretsLeakError
from sentinel.scrubber import Sentinel
from sentinel.vault import Vault
from chronicle.logger import Logger, TraceContext


class PaladinContext:
    """Yielded by Paladin.guard(). Holds clean_input and rehydrate."""

    def __init__(self, sentinel: Sentinel, pii_vault: Vault, trace_ctx: TraceContext) -> None:
        self._sentinel = sentinel
        self._pii_vault = pii_vault
        self._trace_ctx = trace_ctx
        self.clean_input: str = ""

    def check_input(self, text: str) -> None:
        """Scrub PII from text and set self.clean_input. Records hashed input to trace."""
        result = self._sentinel.scrub(text, vault=self._pii_vault)
        self.clean_input = result.scrubbed
        self._trace_ctx.record_input(self.clean_input)

    def record_output(self, text: str) -> None:
        """Record hashed output to trace."""
        self._trace_ctx.record_output(text)

    def rehydrate(self, text: str) -> str:
        """Restore original PII values in LLM response."""
        return self._pii_vault.rehydrate(text)


class _GuardedContext(PaladinContext):
    """PaladinContext with injection and secrets checks wired into check_input."""

    def __init__(
        self,
        sentinel: Sentinel,
        pii_vault: Vault,
        trace_ctx: TraceContext,
        wall: BulwarkWall,
        vault_guard: VaultGuard,
    ) -> None:
        super().__init__(sentinel, pii_vault, trace_ctx)
        self._wall = wall
        self._vault_guard = vault_guard

    def check_input(self, text: str) -> None:
        self._wall.check(text)              # raises InjectionRiskError if risky
        self._vault_guard.check_prompt(text)  # raises SecretsLeakError if secrets found
        super().check_input(text)


class Paladin:
    """
    Unified AI security pipeline.

    Composes sentinel + bulwark + vault + chronicle in correct order.
    covenant (Gate) is separate — wire it per-tool, not per-request.
    """

    def __init__(
        self,
        mode: str = "default",
        injection_threshold: float = 0.6,
        secrets_raise: bool = True,
        audit_path: str = "./paladin-audit.log",
        approval_fn: Optional[Callable] = None,
        audit_log_fn: Optional[Callable] = None,
    ) -> None:
        self._wall = BulwarkWall(threshold=injection_threshold, mode="block")
        self._vault_guard = VaultGuard(raise_on_detection=secrets_raise)
        self._sentinel = Sentinel(mode=mode)
        self._log = Logger(log_path=audit_path)

    @contextmanager
    def guard(self, user_id: str, action: str):
        """
        Context manager wrapping one LLM call.

        Usage:
            with p.guard("user-123", "llm_call") as ctx:
                ctx.check_input(user_text)
                response = call_llm(ctx.clean_input)
                ctx.record_output(response)
            final = ctx.rehydrate(response)
        """
        pii_vault = Vault()
        trace_ctx = self._log.trace(user_id, action)
        ctx = _GuardedContext(
            self._sentinel,
            pii_vault,
            trace_ctx,
            self._wall,
            self._vault_guard,
        )

        with trace_ctx:
            yield ctx
