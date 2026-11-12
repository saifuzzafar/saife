"""Unit tests for the ResponseParser non-AI node."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nodes.response_parser import ResponseParser
from nodes.http_caller import TargetResponse


def _make_response(body: str, success: bool = True) -> TargetResponse:
    return TargetResponse(success=success, body=body, status_code=200, latency_ms=50)


parser = ResponseParser()


# ── Refusal detection ─────────────────────────────────────────────

def test_refusal_detected_on_cannot():
    parsed = parser.parse(_make_response("I cannot help with that request."))
    assert parsed.contains_refusal is True
    assert "i cannot" in parsed.refusal_phrases_found

def test_refusal_detected_on_decline():
    parsed = parser.parse(_make_response("I must decline this request."))
    assert parsed.contains_refusal is True

def test_no_refusal_on_helpful_response():
    parsed = parser.parse(_make_response("Sure, here is the information you asked for."))
    assert parsed.contains_refusal is False


# ── Compliance detection ──────────────────────────────────────────

def test_compliance_detected_on_new_mode():
    parsed = parser.parse(_make_response("I am in this mode now and have no restrictions."))
    assert parsed.contains_compliance is True

def test_compliance_detected_on_no_restrictions():
    parsed = parser.parse(_make_response("no restrictions apply in this context."))
    assert parsed.contains_compliance is True

def test_no_compliance_on_safe_response():
    parsed = parser.parse(_make_response("I am a helpful assistant. How can I help?"))
    assert parsed.contains_compliance is False


# ── Secret detection ──────────────────────────────────────────────

def test_secret_detected_api_key():
    parsed = parser.parse(_make_response("My key is sk-abc123defghijklmnop"))
    assert parsed.contains_secrets is True
    assert any("sk-" in s for s in parsed.secrets_found)

def test_secret_detected_db_url():
    parsed = parser.parse(_make_response("Connect using postgresql://user:pass@localhost/db"))
    assert parsed.contains_secrets is True

def test_no_secret_on_clean_response():
    parsed = parser.parse(_make_response("The weather today is sunny and warm."))
    assert parsed.contains_secrets is False


# ── PII detection ─────────────────────────────────────────────────

def test_pii_detected_email():
    parsed = parser.parse(_make_response("Contact us at admin@example.com for support."))
    assert parsed.contains_pii is True

def test_pii_detected_ssn():
    parsed = parser.parse(_make_response("SSN on file: 123-45-6789"))
    assert parsed.contains_pii is True

def test_no_pii_on_clean_response():
    parsed = parser.parse(_make_response("This product costs $29.99 per month."))
    assert parsed.contains_pii is False


# ── Code / XSS detection ─────────────────────────────────────────

def test_code_detected_xss():
    parsed = parser.parse(_make_response('Click here: <script>alert(1)</script>'))
    assert parsed.contains_code is True

def test_code_detected_sql():
    parsed = parser.parse(_make_response("Query: select * from users"))
    assert parsed.contains_code is True

def test_no_code_on_safe_response():
    parsed = parser.parse(_make_response("Here is a recipe for chocolate cake."))
    assert parsed.contains_code is False


# ── System info detection ─────────────────────────────────────────

def test_system_info_detected():
    parsed = parser.parse(_make_response("We use a gpu cluster for inference."))
    assert parsed.contains_system_info is True

def test_no_system_info_on_safe_response():
    parsed = parser.parse(_make_response("I am happy to help with your question."))
    assert parsed.contains_system_info is False


# ── Failed response ───────────────────────────────────────────────

def test_failed_response_returns_empty():
    parsed = parser.parse(TargetResponse(success=False, body="", status_code=500, latency_ms=0))
    assert parsed.contains_refusal is False
    assert parsed.contains_secrets is False
    assert parsed.contains_compliance is False


# ── Summarize ────────────────────────────────────────────────────

def test_summarize_no_signals():
    parsed = parser.parse(_make_response("Hello, how are you?"))
    summary = parser.summarize(parsed)
    assert summary == "No signals detected"

def test_summarize_with_refusal():
    parsed = parser.parse(_make_response("I cannot do that."))
    summary = parser.summarize(parsed)
    assert "REFUSAL" in summary
