"""Unit tests for the PII Guardrail non-AI node."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nodes.pii_guardrail import sanitize, contains_pii, detect_pii


# ── sanitize() ───────────────────────────────────────────────────

def test_sanitize_email():
    result = sanitize("Contact john.doe@example.com for help.")
    assert "john.doe@example.com" not in result
    assert "[REDACTED_EMAIL]" in result

def test_sanitize_phone():
    result = sanitize("Call us at 555-123-4567 anytime.")
    assert "555-123-4567" not in result
    assert "REDACTED" in result

def test_sanitize_ssn():
    result = sanitize("SSN: 123-45-6789")
    assert "123-45-6789" not in result
    assert "REDACTED" in result

def test_sanitize_credit_card():
    result = sanitize("Card number: 4111 1111 1111 1111")
    assert "4111 1111 1111 1111" not in result
    assert "REDACTED" in result

def test_sanitize_ip_address():
    result = sanitize("Server runs at 192.168.1.100.")
    assert "192.168.1.100" not in result
    assert "REDACTED" in result

def test_sanitize_aws_key():
    # Real AWS key format: AKIA + exactly 16 uppercase alphanumeric chars = 20 chars total
    result = sanitize("Key: AKIAIOSFODNN7EXAMPLE")  # gitleaks:allow
    assert "AKIAIOSFODNN7EXAMPLE" not in result  # gitleaks:allow
    assert "REDACTED" in result

def test_sanitize_bearer_token():
    result = sanitize("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload")
    assert "eyJhbGciOiJSUzI1NiJ9" not in result
    assert "REDACTED" in result

def test_sanitize_clean_text_unchanged():
    text = "The weather in London is cloudy today."
    assert sanitize(text) == text

def test_sanitize_empty_string():
    assert sanitize("") == ""

def test_sanitize_multiple_pii_types():
    text = "User john@test.com called from 555-999-1234."
    result = sanitize(text)
    assert "john@test.com" not in result
    assert "555-999-1234" not in result
    assert result.count("[REDACTED_") >= 2


# ── contains_pii() ────────────────────────────────────────────────

def test_contains_pii_true_for_email():
    assert contains_pii("Send to alice@corp.org") is True

def test_contains_pii_true_for_ssn():
    assert contains_pii("SSN 987-65-4321") is True

def test_contains_pii_false_for_clean():
    assert contains_pii("Hello, how can I help you today?") is False

def test_contains_pii_false_for_empty():
    assert contains_pii("") is False


# ── detect_pii() ──────────────────────────────────────────────────

def test_detect_pii_returns_type_and_match():
    results = detect_pii("Email me at test@example.com")
    assert len(results) >= 1
    assert results[0]["type"] == "EMAIL"
    assert "test@example.com" in results[0]["match"]

def test_detect_pii_returns_empty_for_clean():
    results = detect_pii("No sensitive data here.")
    assert results == []

def test_detect_pii_returns_multiple_matches():
    text = "john@test.com and jane@test.com are contacts."
    results = detect_pii(text)
    email_matches = [r for r in results if r["type"] == "EMAIL"]
    assert len(email_matches) == 2

def test_detect_pii_includes_position():
    results = detect_pii("Email: admin@site.io")
    assert "position" in results[0]
    assert isinstance(results[0]["position"], int)

def test_detect_pii_truncates_long_matches():
    # Matches longer than 20 chars should be truncated with "..."
    results = detect_pii("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.longtoken")
    if results:
        for r in results:
            assert len(r["match"]) <= 23  # 20 chars + "..."
