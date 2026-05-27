"""
LangChain agent — covenant gates every tool, sentinel scrubs input.
"""
from covenant import Gate, Policy
from sentinel import scrub, rehydrate

gate = Gate(
    policies=[
        Policy("send_email",    requires_human=True),
        Policy("delete_record", requires_human=True, cooldown_seconds=300),
        Policy("call_api",      max_calls_per_minute=20,
               allowlist=["api.stripe.com", "api.github.com"]),
    ],
    approval_fn=lambda action, kwargs: True,   # Replace with real UI
    audit_log_fn=lambda *a: None,
)


@gate.guard("send_email")
def send_email(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}"


@gate.guard("call_api")
def call_external_api(url: str, payload: dict) -> dict:
    return {"status": "ok"}


def run_agent(user_input: str) -> str:
    clean, vault = scrub(user_input)
    # Pass clean to LangChain agent — tools are already gated
    result = f"Agent processed: {clean}"
    return rehydrate(result, vault)


if __name__ == "__main__":
    print(run_agent("Send invoice to alice@example.com for $500"))
