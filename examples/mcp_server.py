"""
MCP server — Paladin pipeline inside every tool handler.
"""
from paladin import Paladin
from covenant import Gate, Policy
from bulwark.scanner import InjectionRiskError

p = Paladin(mode="default", audit_path="./logs/mcp-audit.log")
gate = Gate(
    policies=[
        Policy("file_write",   requires_human=True),
        Policy("shell_exec",   requires_human=True, cooldown_seconds=60),
        Policy("web_fetch",    max_calls_per_minute=30),
    ],
    approval_fn=lambda action, kwargs: True,
    audit_log_fn=lambda *a: None,
)


async def handle_tool_call(session_id: str, tool_name: str, params: dict) -> dict:
    try:
        with p.guard(session_id, tool_name) as ctx:
            ctx.check_input(str(params))
            gate.execute(tool_name, lambda **k: None, **params)
            result = {"status": "executed", "tool": tool_name}
            ctx.record_output(str(result))
        return result
    except InjectionRiskError as e:
        return {"error": "blocked", "reasons": e.reasons}
