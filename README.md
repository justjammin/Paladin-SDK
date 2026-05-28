# Paladin SDK

> **Zero-AI. Zero network calls. Zero dependencies.**
> Five composable SDKs that form a complete AI security pipeline.
> Drop any one in independently, or compose all five for end-to-end protection.

---

## Overview

```
paladin_sdk/
├── sentinel/     — Detect, tokenize, and rehydrate PII
├── bulwark/      — Prompt injection firewall
├── covenant/     — Human approval gates for agent actions
├── vault/        — Secrets scanner for prompts and logs
└── chronicle/    — Immutable, tamper-evident AI audit log
```

### The full pipeline in 8 lines

```python
from paladin import Paladin

p = Paladin(mode="default", audit_path="./paladin-audit.log")

with p.guard(user_id, action="llm_call") as ctx:
    ctx.check_input(user_input)      # injection check → secrets check → PII scrub
    response = call_llm(ctx.clean_input)
    ctx.record_output(response)

final = ctx.rehydrate(response)      # restore PII in response
```

---

## Install

```bash
# Full pipeline
pip install paladin

# Individual packages
pip install paladin-sentinel
pip install paladin-bulwark
pip install paladin-covenant
pip install paladin-vault
pip install paladin-chronicle
```

---

## SDK 1 — `sentinel`

> Detect and tokenize PII before it reaches the LLM. Rehydrate after.

```python
from sentinel import scrub, rehydrate

clean, vault = scrub("My SSN is 123-45-6789 and email is john@example.com")
# clean → "My SSN is [SSN_A1B2C3] and email is [EMAIL_D4E5F6]"

response = call_llm(clean)
final = rehydrate(response, vault)
```

### Compliance modes

```python
from sentinel import Sentinel

shield = Sentinel(mode="hipaa")   # or "gdpr", "pci", "default"
result = shield.scrub(text)

print(result.has_pii)              # True/False
print(result.summary())            # { total_entities: 3, entity_types: {...} }
print(result.entity_types_found)   # { EntityType.SSN, EntityType.EMAIL }
```

### Detects (no AI, no network)

| Category  | Entities                                                   |
|-----------|------------------------------------------------------------|
| Identity  | Email, Phone, SSN, Passport, Driver's License, DOB         |
| Financial | Credit Card (Luhn-validated), Bank Account, Routing Number |
| Medical   | MRN, NPI, DEA Number                                       |
| Network   | IPv4, MAC Address                                          |
| Auth      | API Keys (AWS/OpenAI/GitHub/Stripe/Slack), JWT, Passwords  |
| Location  | Address, ZIP Code, GPS Coordinates                         |

---

## SDK 2 — `bulwark`

> Heuristic-based prompt injection firewall. Scores and blocks malicious inputs before they reach the LLM.

```python
from bulwark import scan, InjectionRiskError

result = scan(user_input)

if result.risk > 0.7:
    raise InjectionRiskError(result.reasons)

# result.risk    → float 0.0–1.0
# result.reasons → ["role override attempt", "delimiter injection detected"]
```

### Block or log mode

```python
from bulwark import BulwarkWall

wall = BulwarkWall(threshold=0.6, mode="block")   # or mode="log"
wall.check(user_input)                             # raises on block, logs on log
```

---

## SDK 3 — `covenant`

> Policy-enforced approval gates for AI agent actions. Block, rate-limit, or require human confirmation before destructive operations.

```python
from covenant import Gate, Policy

gate = Gate(policies=[
    Policy("send_email",    requires_human=True),
    Policy("delete_record", requires_human=True, cooldown_seconds=300),
    Policy("read_database", max_calls_per_minute=10),
    Policy("call_api",      allowlist=["api.stripe.com", "api.github.com"]),
])

@gate.guard("send_email")
def send_email(to, subject, body):
    # only executes if policy passes
    ...
```

---

## SDK 4 — `vault`

> Secrets scanner for LLM prompts and trace logs. Catches API keys, tokens, and credentials before they persist anywhere.

```python
from vault import scan_prompt, scan_log, SecretsLeakError

# Before sending to LLM
result = scan_prompt(system_prompt + user_message)
if result.has_secrets:
    raise SecretsLeakError(result.findings)

# Scan saved trace logs
findings = scan_log("/var/log/llm-traces/")
```

---

## SDK 5 — `chronicle`

> Immutable, tamper-evident audit log for every LLM call. SHA-256 hash chaining — no blockchain required.

```python
from chronicle import Logger

log = Logger(storage="local", log_path="./paladin-audit.log")

with log.trace(user_id="user-123", action="llm_call") as trace:
    trace.record_input(prompt)
    response = call_llm(prompt)
    trace.record_output(response)
    trace.record_metadata(model="claude-sonnet-4-6", tokens=412, cost_usd=0.003)

valid, errors = log.verify()   # tamper check
```

---

## Composing the Full Pipeline

```python
from sentinel import scrub, rehydrate
from bulwark import BulwarkWall
from vault import VaultGuard
from covenant import Gate, Policy
from chronicle import Logger

wall       = BulwarkWall(threshold=0.6, mode="block")
vault_guard = VaultGuard(raise_on_detection=True)
gate       = Gate(
    policies=[
        Policy("send_email",  requires_human=True),
        Policy("delete",      requires_human=True, cooldown_seconds=300),
        Policy("call_api",    max_calls_per_minute=20),
    ],
    approval_fn=lambda action, kwargs: your_approval_ui(action, kwargs),
    audit_log_fn=lambda *a: None,
)
log = Logger(log_path="./paladin-audit.log")


def safe_llm_call(user_id: str, user_input: str) -> str:
    wall.check(user_input)                          # 1. block injection
    vault_guard.check_prompt(user_input)            # 2. catch secrets
    clean_input, pii_vault = scrub(user_input)      # 3. strip PII

    with log.trace(user_id, action="llm_call") as trace:
        trace.record_input(clean_input)
        response = call_llm(clean_input)
        trace.record_output(response)
        trace.record_metadata(model="claude-sonnet-4-6")

    return rehydrate(response, pii_vault)           # 4. restore PII
```

---

## Package Structure

```
paladin_sdk/
├── sentinel/
│   ├── entities.py              EntityType enum + compliance presets
│   ├── vault.py                 Ephemeral token store
│   ├── patterns.py              Regex + Luhn detection engine
│   ├── scrubber.py              Public API
│   └── tests/test_sentinel.py  63 tests
├── bulwark/
│   ├── scanner.py               Heuristic injection detection
│   └── tests/test_bulwark.py   22 tests
├── covenant/
│   ├── gate.py                  Policy engine + decorator
│   └── tests/test_covenant.py  21 tests
├── vault/
│   ├── scanner.py               Secrets pattern matching
│   └── tests/test_vault.py     10 tests
├── chronicle/
│   ├── logger.py                Hash chain + trace context
│   └── tests/test_chronicle.py 10 tests
├── paladin/
│   ├── pipeline.py              Unified orchestrator
│   └── tests/test_pipeline.py  6 tests
├── examples/
│   ├── fastapi_app.py
│   ├── langchain_agent.py
│   ├── mcp_server.py
│   └── voice_pipeline.py
├── research/
│   └── ARD.md                   Architecture Review Document
├── pyproject.toml
└── Makefile
```

---

## Design Principles

All five SDKs follow the same rules:

- **Zero AI dependency** — detection is regex, heuristics, Luhn, and hash algorithms only
- **Zero network calls** — nothing leaves the process
- **Zero required dependencies** — pure Python stdlib (3.11+)
- **Deterministic** — same input always produces same output
- **Composable** — use one or all five; each is independently installable
- **Auditable** — every decision has a reason string or hash you can inspect
- **Open source** — SDKs are MIT licensed; dashboard is the paid layer

---

## Deployment Scenarios

| Scenario        | sentinel | bulwark | covenant | vault | chronicle |
|-----------------|----------|---------|----------|-------|-----------|
| Raw API backend | ✅        | ✅       | —        | ✅     | ✅         |
| LangChain agent | ✅        | ✅       | ✅        | ✅     | ✅         |
| MCP server      | ✅        | ✅       | ✅        | ✅     | ✅         |
| Multi-agent     | ✅        | ✅       | ✅        | ✅     | ✅         |
| Voice pipeline  | ✅        | —       | —        | —     | ✅         |

---

## Development

```bash
make install    # pip install all packages in editable mode
make test       # pytest (133 tests)
make lint       # ruff check
```

---

*Paladin SDK — built for AI teams who ship to production.*
