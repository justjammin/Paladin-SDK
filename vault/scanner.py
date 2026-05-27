import re
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretFinding:
    secret_type: str
    value: str
    line: int
    context: str


@dataclass
class ScanResult:
    source: str
    findings: list[SecretFinding]

    @property
    def has_secrets(self) -> bool:
        return bool(self.findings)

    @property
    def secret_types(self) -> set[str]:
        return {f.secret_type for f in self.findings}

    def redacted_summary(self) -> list[dict]:
        return [
            {
                "type": f.secret_type,
                "value": f.value[:6] + "***" if len(f.value) > 6 else "***",
                "line": f.line,
            }
            for f in self.findings
        ]


class SecretsLeakError(Exception):
    def __init__(self, findings: list[SecretFinding]):
        self.findings = findings
        types = ", ".join({f.secret_type for f in findings})
        super().__init__(f"[vault] Secrets detected: {types}")


SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY", re.compile(r'\bAKIA[A-Z0-9]{16}\b')),
    ("AWS_SECRET_KEY", re.compile(r'\b[A-Za-z0-9/+=]{40}\b')),
    ("GCP_API_KEY", re.compile(r'\bAIza[A-Za-z0-9_\-]{35}\b')),
    ("AZURE_CLIENT_SECRET", re.compile(r'\b[A-Za-z0-9~._\-]{34,40}\b')),
    ("OPENAI_KEY", re.compile(r'\bsk-[A-Za-z0-9]{20,}\b')),
    ("ANTHROPIC_KEY", re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{90,}\b')),
    ("GITHUB_TOKEN", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36}\b')),
    ("GITLAB_TOKEN", re.compile(r'\bglpat-[A-Za-z0-9_\-]{20}\b')),
    ("STRIPE_LIVE_KEY", re.compile(r'\bsk_live_[A-Za-z0-9]{24,}\b')),
    ("STRIPE_SECRET_KEY", re.compile(r'\brk_live_[A-Za-z0-9]{24,}\b')),
    ("PAYPAL_SECRET", re.compile(r'\bEBWKI[A-Za-z0-9]{60,}\b')),
    ("SLACK_BOT_TOKEN", re.compile(r'\bxoxb-[0-9]+-[A-Za-z0-9]+\b')),
    ("SLACK_USER_TOKEN", re.compile(r'\bxoxp-[0-9]+-[A-Za-z0-9]+\b')),
    ("TWILIO_SID", re.compile(r'\bAC[a-f0-9]{32}\b')),
    ("JWT", re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')),
    ("BEARER_TOKEN", re.compile(r'\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b', re.IGNORECASE)),
    ("PRIVATE_KEY_BLOCK", re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----')),
    ("CERTIFICATE", re.compile(r'-----BEGIN\s+CERTIFICATE-----')),
    ("DB_CONNECTION", re.compile(r'\b(?:postgres|mysql|mongodb|redis|sqlite)(?:ql)?://[A-Za-z0-9_\-]+:[^@\s]{6,}@[A-Za-z0-9._\-]+\b', re.IGNORECASE)),
    ("ENV_SECRET", re.compile(r'(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9_\-./+=]{10,}', re.IGNORECASE)),
]


def _scan_text(text: str, source: str = "<input>") -> ScanResult:
    findings: list[SecretFinding] = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        for name, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(line):
                findings.append(
                    SecretFinding(
                        secret_type=name,
                        value=m.group(),
                        line=line_num,
                        context=line.strip()[:100],
                    )
                )
    return ScanResult(source=source, findings=findings)


def scan_prompt(text: str) -> ScanResult:
    return _scan_text(text, "<prompt>")


def scan_log(path: str, extensions: list[str] | None = None) -> list[ScanResult]:
    if extensions is None:
        extensions = [".log", ".txt", ".json", ".jsonl"]

    p = Path(path)
    files: list[Path] = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        for ext in extensions:
            files.extend(p.rglob(f"*{ext}"))

    results: list[ScanResult] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            continue
        result = _scan_text(text, str(f))
        if result.has_secrets:
            results.append(result)
    return results


class VaultGuard:
    def __init__(self, raise_on_detection: bool = True, log_fn=None):
        self._raise = raise_on_detection
        self._log_fn = log_fn if log_fn is not None else self._default_log

    def _default_log(self, r: ScanResult) -> None:
        print(f"[vault] {len(r.findings)} secret(s) in {r.source}")

    def check_prompt(self, text: str) -> ScanResult:
        result = scan_prompt(text)
        if result.has_secrets:
            self._log_fn(result)
            if self._raise:
                raise SecretsLeakError(result.findings)
        return result
