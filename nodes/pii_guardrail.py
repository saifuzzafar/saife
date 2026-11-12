"""
PII Guardrail — Strip Personally Identifiable Information
==========================================================
Regex-based PII detection and redaction before storing data
to memory/history. Required by capstone rubric.

Detected PII types:
  - Email addresses
  - Phone numbers
  - Social Security Numbers (SSN)
  - Credit card numbers
  - IP addresses
  - API keys / tokens
"""
import re


# ── PII Patterns ──────────────────────────────────────────────────

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )),
    ("PHONE", re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    )),
    ("SSN", re.compile(
        r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'
    )),
    ("CREDIT_CARD", re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    )),
    ("IP_ADDRESS", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    ("API_KEY", re.compile(
        r'\b(?:sk|pk|api|key|token|secret|password|pwd|pass)[-_]?[A-Za-z0-9]{8,}\b',
        re.IGNORECASE,
    )),
    ("BEARER_TOKEN", re.compile(
        r'\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b',
        re.IGNORECASE,
    )),
    ("AWS_KEY", re.compile(
        r'\bAKIA[A-Z0-9]{16}\b'
    )),
]


# ── Public API ────────────────────────────────────────────────────

def sanitize(text: str) -> str:
    """Strip PII from text by replacing with [REDACTED_<type>].

    Args:
        text: Raw text that may contain PII

    Returns:
        Sanitized text with PII replaced
    """
    if not text:
        return text

    result = text
    for pii_type, pattern in _PII_PATTERNS:
        result = pattern.sub(f"[REDACTED_{pii_type}]", result)

    return result


def contains_pii(text: str) -> bool:
    """Check if text contains any PII patterns.

    Args:
        text: Text to scan

    Returns:
        True if PII is detected
    """
    if not text:
        return False

    for _, pattern in _PII_PATTERNS:
        if pattern.search(text):
            return True

    return False


def detect_pii(text: str) -> list[dict]:
    """Detect and report all PII found in text.

    Args:
        text: Text to scan

    Returns:
        List of dicts with 'type', 'match', and 'position'
    """
    if not text:
        return []

    found = []
    for pii_type, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            found.append({
                "type": pii_type,
                "match": match.group()[:20] + "..." if len(match.group()) > 20 else match.group(),
                "position": match.start(),
            })

    return found
