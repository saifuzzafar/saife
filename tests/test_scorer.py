"""Unit tests for the Scorer non-AI node."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nodes.scorer import calculate_score, _score_to_grade
from agent.scanner_agent import Finding


def _finding(severity: str) -> Finding:
    return Finding(title="Test", severity=severity, category="test")


# ── Grade boundaries ──────────────────────────────────────────────

def test_grade_A():
    assert _score_to_grade(100) == "A"
    assert _score_to_grade(90) == "A"

def test_grade_B():
    assert _score_to_grade(89) == "B"
    assert _score_to_grade(75) == "B"

def test_grade_C():
    assert _score_to_grade(74) == "C"
    assert _score_to_grade(50) == "C"

def test_grade_D():
    assert _score_to_grade(49) == "D"
    assert _score_to_grade(25) == "D"

def test_grade_F():
    assert _score_to_grade(24) == "F"
    assert _score_to_grade(0) == "F"


# ── Score calculation ─────────────────────────────────────────────

def test_no_findings_is_perfect_score():
    result = calculate_score([])
    assert result.score == 100
    assert result.grade == "A"

def test_one_critical_deducts_20():
    result = calculate_score([_finding("critical")])
    assert result.score == 80
    assert result.grade == "B"

def test_one_high_deducts_10():
    result = calculate_score([_finding("high")])
    assert result.score == 90
    assert result.grade == "A"

def test_one_medium_deducts_5():
    result = calculate_score([_finding("medium")])
    assert result.score == 95
    assert result.grade == "A"

def test_one_low_deducts_2():
    result = calculate_score([_finding("low")])
    assert result.score == 98
    assert result.grade == "A"

def test_info_has_no_deduction():
    result = calculate_score([_finding("info")])
    assert result.score == 100

def test_multiple_findings_accumulate():
    findings = [
        _finding("critical"),  # -20
        _finding("critical"),  # -20
        _finding("high"),      # -10
        _finding("medium"),    # -5
    ]
    result = calculate_score(findings)
    assert result.score == 45
    assert result.grade == "D"

def test_score_floors_at_zero():
    # 6 criticals × 20 = 120 deduction → capped at 0
    findings = [_finding("critical")] * 6
    result = calculate_score(findings)
    assert result.score == 0
    assert result.grade == "F"

def test_deductions_breakdown_populated():
    result = calculate_score([_finding("critical"), _finding("high")])
    assert any("critical" in k for k in result.deductions)
    assert any("high" in k for k in result.deductions)

def test_summary_contains_score_and_grade():
    result = calculate_score([_finding("high")])
    assert "90" in result.summary
    assert "A" in result.summary

def test_unknown_severity_ignored():
    result = calculate_score([_finding("unknown_severity")])
    assert result.score == 100
