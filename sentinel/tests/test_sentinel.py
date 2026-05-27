"""Tests for sentinel — PII detection and tokenization."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

from sentinel import scrub, rehydrate, Sentinel, ScrubResult, EntityType, Vault
from sentinel.patterns import find_matches, _luhn_valid


# ---------------------------------------------------------------------------
# Vault tests
# ---------------------------------------------------------------------------

class TestVault:
    def test_tokenize_deterministic(self):
        vault = Vault()
        t1 = vault.tokenize("EMAIL", "alice@example.com")
        t2 = vault.tokenize("EMAIL", "alice@example.com")
        assert t1 == t2

    def test_tokenize_different_values_different_tokens(self):
        vault = Vault()
        t1 = vault.tokenize("EMAIL", "alice@example.com")
        t2 = vault.tokenize("EMAIL", "bob@example.com")
        assert t1 != t2

    def test_tokenize_format(self):
        vault = Vault()
        token = vault.tokenize("SSN", "123-45-6789")
        assert token.startswith("[SSN_")
        assert token.endswith("]")
        assert len(token) == len("[SSN_") + 6 + 1  # [SSN_XXXXXX]

    def test_get_returns_original_value(self):
        vault = Vault()
        token = vault.tokenize("PHONE", "555-867-5309")
        assert vault.get(token) == "555-867-5309"

    def test_get_missing_returns_none(self):
        vault = Vault()
        assert vault.get("[FAKE_000000]") is None

    def test_rehydrate_single(self):
        vault = Vault()
        original = "Call me at 555-867-5309"
        scrubbed, v = scrub(original, mode="default")
        restored = rehydrate(scrubbed, v)
        assert restored == original

    def test_rehydrate_multiple_tokens(self):
        vault = Vault()
        email_token = vault.tokenize("EMAIL", "a@b.com")
        ssn_token = vault.tokenize("SSN", "123-45-6789")
        # rehydrate replaces tokens it knows; test with actual returned tokens
        assert vault.rehydrate(email_token) == "a@b.com"
        assert vault.rehydrate(ssn_token) == "123-45-6789"

    def test_clear(self):
        vault = Vault()
        vault.tokenize("EMAIL", "x@y.com")
        assert len(vault) == 1
        vault.clear()
        assert len(vault) == 0

    def test_len(self):
        vault = Vault()
        assert len(vault) == 0
        vault.tokenize("A", "one")
        vault.tokenize("B", "two")
        assert len(vault) == 2

    def test_all_tokens(self):
        vault = Vault()
        t = vault.tokenize("EMAIL", "z@z.com")
        tokens = vault.all_tokens()
        assert t in tokens
        assert tokens[t] == "z@z.com"

    def test_tokenize_stores_in_store(self):
        vault = Vault()
        token = vault.tokenize("IP_ADDRESS", "192.168.1.1")
        assert vault.get(token) == "192.168.1.1"


# ---------------------------------------------------------------------------
# Luhn tests
# ---------------------------------------------------------------------------

class TestLuhn:
    def test_visa_valid(self):
        assert _luhn_valid("4532015112830366") is True

    def test_mc_valid(self):
        assert _luhn_valid("5425233430109903") is True

    def test_amex_valid(self):
        assert _luhn_valid("378282246310005") is True

    def test_invalid_luhn(self):
        assert _luhn_valid("1234567890123456") is False

    def test_all_zeros_invalid(self):
        # 0000000000000001 — sum forced off by 10; genuinely Luhn-invalid
        assert _luhn_valid("0000000000000001") is False


# ---------------------------------------------------------------------------
# Email tests
# ---------------------------------------------------------------------------

class TestEmail:
    def test_simple_email_detected(self):
        result = Sentinel(mode="default").scrub("Contact alice@example.com for info.")
        assert result.has_pii
        assert any(m.entity_type == EntityType.EMAIL for m in result.matches)

    def test_email_round_trip(self):
        original = "Send to bob@company.org now"
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original
        assert "bob@company.org" not in scrubbed

    def test_email_token_in_scrubbed(self):
        scrubbed, vault = scrub("hi user@test.io")
        assert "[EMAIL_" in scrubbed

    def test_email_with_plus(self):
        result = Sentinel(mode="default").scrub("user+tag@domain.com")
        assert any(m.entity_type == EntityType.EMAIL for m in result.matches)

    def test_email_subdomain(self):
        result = Sentinel(mode="default").scrub("admin@mail.corp.example.org")
        assert any(m.entity_type == EntityType.EMAIL for m in result.matches)


# ---------------------------------------------------------------------------
# SSN tests
# ---------------------------------------------------------------------------

class TestSSN:
    def test_ssn_with_dashes(self):
        result = Sentinel(mode="default").scrub("SSN: 123-45-6789")
        assert any(m.entity_type == EntityType.SSN for m in result.matches)

    def test_ssn_without_dashes(self):
        result = Sentinel(mode="default").scrub("SSN: 123456789")
        assert any(m.entity_type == EntityType.SSN for m in result.matches)

    def test_ssn_invalid_000_prefix_not_detected(self):
        result = Sentinel(mode="default").scrub("000-12-3456")
        assert not any(m.entity_type == EntityType.SSN for m in result.matches)

    def test_ssn_invalid_666_prefix_not_detected(self):
        result = Sentinel(mode="default").scrub("666-12-3456")
        assert not any(m.entity_type == EntityType.SSN for m in result.matches)

    def test_ssn_invalid_900_prefix_not_detected(self):
        result = Sentinel(mode="default").scrub("900-12-3456")
        assert not any(m.entity_type == EntityType.SSN for m in result.matches)

    def test_ssn_round_trip(self):
        original = "My SSN is 123-45-6789."
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original


# ---------------------------------------------------------------------------
# Credit card tests
# ---------------------------------------------------------------------------

class TestCreditCard:
    def test_visa_detected(self):
        result = Sentinel(mode="default").scrub("Card: 4532015112830366")
        assert any(m.entity_type == EntityType.CREDIT_CARD for m in result.matches)

    def test_mc_detected(self):
        result = Sentinel(mode="default").scrub("Pay with 5425233430109903")
        assert any(m.entity_type == EntityType.CREDIT_CARD for m in result.matches)

    def test_amex_detected(self):
        result = Sentinel(mode="default").scrub("Amex: 378282246310005")
        assert any(m.entity_type == EntityType.CREDIT_CARD for m in result.matches)

    def test_invalid_luhn_not_detected(self):
        # 4532015112830367 — last digit changed, Luhn invalid
        result = Sentinel(mode="default").scrub("4532015112830367")
        assert not any(m.entity_type == EntityType.CREDIT_CARD for m in result.matches)

    def test_cc_round_trip(self):
        original = "Charge 4532015112830366 for order"
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original


# ---------------------------------------------------------------------------
# Phone tests
# ---------------------------------------------------------------------------

class TestPhone:
    def test_us_dashes(self):
        result = Sentinel(mode="default").scrub("Call 555-867-5309")
        assert any(m.entity_type == EntityType.PHONE for m in result.matches)

    def test_with_country_code(self):
        result = Sentinel(mode="default").scrub("+1 312 555-0100")
        assert any(m.entity_type == EntityType.PHONE for m in result.matches)

    def test_parentheses_format(self):
        result = Sentinel(mode="default").scrub("(800) 555-1234")
        assert any(m.entity_type == EntityType.PHONE for m in result.matches)

    def test_phone_round_trip(self):
        original = "Reach me at 555-867-5309 anytime"
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original


# ---------------------------------------------------------------------------
# API key tests
# ---------------------------------------------------------------------------

class TestAPIKey:
    def test_openai_key(self):
        key = "sk-" + "A" * 20
        result = Sentinel(mode="default").scrub(f"Key: {key}")
        assert any(m.entity_type == EntityType.API_KEY for m in result.matches)

    def test_aws_key(self):
        result = Sentinel(mode="default").scrub("AWS: AKIAIOSFODNN7EXAMPLE")
        assert any(m.entity_type == EntityType.API_KEY for m in result.matches)

    def test_github_key(self):
        key = "ghp_" + "A" * 36
        result = Sentinel(mode="default").scrub(f"Token: {key}")
        assert any(m.entity_type == EntityType.API_KEY for m in result.matches)

    def test_api_key_round_trip(self):
        key = "sk-" + "B" * 20
        original = f"My key is {key} keep it safe"
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original


# ---------------------------------------------------------------------------
# Compliance mode tests
# ---------------------------------------------------------------------------

class TestComplianceModes:
    def test_hipaa_detects_mrn(self):
        result = Sentinel(mode="hipaa").scrub("MRN: AB12345 patient record")
        assert any(m.entity_type == EntityType.MRN for m in result.matches)

    def test_pci_detects_credit_card(self):
        result = Sentinel(mode="pci").scrub("Card: 4532015112830366")
        assert any(m.entity_type == EntityType.CREDIT_CARD for m in result.matches)

    def test_gdpr_detects_passport(self):
        result = Sentinel(mode="gdpr").scrub("Passport: AB1234567")
        assert any(m.entity_type == EntityType.PASSPORT for m in result.matches)

    def test_custom_enabled_types_filters(self):
        # Only EMAIL enabled — SSN in text should NOT match
        s = Sentinel(enabled_types={EntityType.EMAIL})
        result = s.scrub("SSN: 123-45-6789 email: user@test.com")
        types_found = {m.entity_type for m in result.matches}
        assert EntityType.SSN not in types_found
        assert EntityType.EMAIL in types_found

    def test_custom_enabled_types_only_ssn(self):
        s = Sentinel(enabled_types={EntityType.SSN})
        result = s.scrub("email user@test.com SSN 123-45-6789")
        types_found = {m.entity_type for m in result.matches}
        assert EntityType.EMAIL not in types_found
        assert EntityType.SSN in types_found

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            Sentinel(mode="unknown_mode")


# ---------------------------------------------------------------------------
# IP Address tests
# ---------------------------------------------------------------------------

class TestIPAddress:
    def test_valid_ip(self):
        result = Sentinel(mode="default").scrub("Server at 192.168.1.1")
        assert any(m.entity_type == EntityType.IP_ADDRESS for m in result.matches)

    def test_invalid_ip_octet_too_large(self):
        result = Sentinel(mode="default").scrub("Bad: 256.1.1.1")
        assert not any(m.entity_type == EntityType.IP_ADDRESS for m in result.matches)

    def test_ip_round_trip(self):
        original = "Connect to 10.0.0.1 for access"
        scrubbed, vault = scrub(original)
        restored = rehydrate(scrubbed, vault)
        assert restored == original


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self):
        scrubbed, vault = scrub("")
        assert scrubbed == ""
        assert len(vault) == 0

    def test_no_pii_passthrough(self):
        text = "Hello, how are you doing today?"
        scrubbed, vault = scrub(text)
        assert scrubbed == text
        assert len(vault) == 0

    def test_multiple_same_type(self):
        text = "Emails: alice@test.com and bob@test.com"
        result = Sentinel(mode="default").scrub(text)
        email_matches = [m for m in result.matches if m.entity_type == EntityType.EMAIL]
        assert len(email_matches) == 2

    def test_multiple_types_in_one_string(self):
        text = "Email: user@test.com SSN: 123-45-6789"
        result = Sentinel(mode="default").scrub(text)
        types_found = {m.entity_type for m in result.matches}
        assert EntityType.EMAIL in types_found
        assert EntityType.SSN in types_found

    def test_summary_dict_structure(self):
        result = Sentinel(mode="default").scrub("user@test.com")
        summary = result.summary()
        assert "total_entities" in summary
        assert "entity_types" in summary
        assert "has_pii" in summary
        assert summary["has_pii"] is True

    def test_entity_count(self):
        result = Sentinel(mode="default").scrub("alice@test.com bob@test.com")
        assert result.entity_count == 2

    def test_entity_types_found_property(self):
        result = Sentinel(mode="default").scrub("user@example.com 192.168.0.1")
        types = result.entity_types_found
        assert EntityType.EMAIL in types
        assert EntityType.IP_ADDRESS in types

    def test_has_pii_false(self):
        result = Sentinel(mode="default").scrub("No PII here")
        assert result.has_pii is False

    def test_round_trip_complex(self):
        original = "Email user@test.com, SSN 123-45-6789, IP 10.0.0.1"
        scrubbed, vault = scrub(original, mode="default")
        restored = rehydrate(scrubbed, vault)
        assert restored == original

    def test_shared_vault_across_calls(self):
        vault = Vault()
        scrub("alice@test.com", vault=vault)
        scrub("bob@test.com", vault=vault)
        assert len(vault) == 2

    def test_scrub_function_returns_tuple(self):
        result = scrub("test@example.com")
        assert isinstance(result, tuple)
        assert len(result) == 2
        scrubbed_text, vault = result
        assert isinstance(scrubbed_text, str)
        assert isinstance(vault, Vault)

    def test_routing_number_with_keyword_detected(self):
        result = Sentinel(mode="pci").scrub("routing number: 021000021")
        assert any(m.entity_type == EntityType.ROUTING_NUMBER for m in result.matches)

    def test_bare_9_digits_not_routing(self):
        # Without keyword prefix, 9 digits should not match ROUTING_NUMBER
        result = Sentinel(mode="pci").scrub("Code: 123456789")
        assert not any(m.entity_type == EntityType.ROUTING_NUMBER for m in result.matches)

    def test_npi_detected_in_hipaa(self):
        result = Sentinel(mode="hipaa").scrub("NPI: 1234567890")
        assert any(m.entity_type == EntityType.NPI for m in result.matches)
