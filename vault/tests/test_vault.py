import pytest
from vault.scanner import scan_prompt, VaultGuard, SecretsLeakError


def test_aws_access_key_detected():
    result = scan_prompt("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert result.has_secrets
    assert "AWS_ACCESS_KEY" in result.secret_types


def test_openai_key_detected():
    result = scan_prompt("key = sk-abcdefghijklmnopqrstuvwxyz123456")
    assert result.has_secrets
    assert "OPENAI_KEY" in result.secret_types


def test_github_token_detected():
    # exactly 36 alphanumeric chars after "ghp_" to match the pattern
    result = scan_prompt("token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")
    assert result.has_secrets
    assert "GITHUB_TOKEN" in result.secret_types


def test_jwt_detected():
    result = scan_prompt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.abc123def456")
    assert result.has_secrets
    assert "JWT" in result.secret_types


def test_pem_block_detected():
    result = scan_prompt("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...")
    assert result.has_secrets
    assert "PRIVATE_KEY_BLOCK" in result.secret_types


def test_postgres_url_detected():
    result = scan_prompt("db = postgres://admin:secretpassword@db.example.com/mydb")
    assert result.has_secrets
    assert "DB_CONNECTION" in result.secret_types


def test_clean_input_no_secrets():
    result = scan_prompt("Hello, what is the weather like today?")
    assert not result.has_secrets


def test_vault_guard_raises_on_detection():
    guard = VaultGuard(raise_on_detection=True)
    with pytest.raises(SecretsLeakError):
        guard.check_prompt("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")


def test_vault_guard_log_mode_no_raise():
    log: list = []
    guard = VaultGuard(raise_on_detection=False, log_fn=lambda r: log.append(r))
    result = guard.check_prompt("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert result.has_secrets
    assert len(log) == 1
    # does not raise — confirmed by reaching here


def test_redacted_summary():
    result = scan_prompt("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    summary = result.redacted_summary()
    assert len(summary) > 0
    for item in summary:
        assert "***" in item["value"]
        assert len(item["value"]) < 20
