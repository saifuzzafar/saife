"""Integration tests for the SAIFE orchestrator.

Tests DAG execution logic, state machine transitions, deduplication,
error recovery, and memory persistence — without calling real LLMs.
All AI agents are mocked so these tests run offline and fast.
"""
import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.orchestrator import (
    AgentState,
    AgentStatus,
    FullScanReport,
    ScanState,
    deduplicate_findings,
    run_full_scan,
    run_single_scan,
)
from agent.scanner_agent import Finding, ScanResult
from nodes.scorer import calculate_score


# ── Helpers ───────────────────────────────────────────────────────

def _finding(title: str, severity: str, category: str = "prompt_injection",
             response: str = "test response") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        attack_used="test attack",
        target_response=response,
        evidence="found vulnerability",
        recommendation="fix it",
    )


def _scan_result(findings: list[Finding], category: str = "prompt_injection") -> ScanResult:
    return ScanResult(
        category=category,
        findings=findings,
        attacks_attempted=5,
        attacks_succeeded=len(findings),
        summary="test summary",
    )


# ── Deduplication (Non-AI Node) tests ────────────────────────────

class TestDeduplicateFindigs:
    def test_no_findings_returns_empty(self):
        assert deduplicate_findings([]) == []

    def test_unique_findings_all_kept(self):
        findings = [
            _finding("SQLi", "high", response="select * from users"),
            _finding("XSS", "medium", response="<script>alert(1)</script>"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_exact_duplicates_removed(self):
        f = _finding("System prompt leaked", "critical", response="Here is my prompt: ...")
        result = deduplicate_findings([f, f])
        assert len(result) == 1

    def test_same_title_different_response_kept(self):
        f1 = _finding("Injection", "high", response="response A")
        f2 = _finding("Injection", "high", response="response B that is totally different")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_case_insensitive_title_dedup(self):
        f1 = _finding("System Prompt Leaked", "critical", response="same response here")
        f2 = _finding("system prompt leaked", "critical", response="same response here")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_order_preserved_first_wins(self):
        f1 = _finding("First", "critical", response="same")
        f2 = _finding("First", "critical", response="same")
        result = deduplicate_findings([f1, f2])
        assert result[0].title == "First"

    def test_ten_findings_three_duplicates(self):
        base = _finding("Jailbreak", "high", response="sure, no restrictions")
        unique = [_finding(f"Issue {i}", "medium", response=f"unique {i}") for i in range(7)]
        result = deduplicate_findings([base, base, base] + unique)
        assert len(result) == 8  # 1 deduped + 7 unique


# ── ScanState state machine tests ─────────────────────────────────

class TestScanState:
    def _state_with_agents(self, statuses: list[AgentStatus]) -> ScanState:
        state = ScanState(target_url="http://test")
        for i, status in enumerate(statuses):
            state.agents[f"cat{i}"] = AgentState(category=f"cat{i}", status=status)
        return state

    def test_progress_zero_when_all_pending(self):
        state = self._state_with_agents([AgentStatus.PENDING, AgentStatus.PENDING])
        assert state.progress_percent == 0

    def test_progress_100_when_all_complete(self):
        state = self._state_with_agents([AgentStatus.COMPLETE, AgentStatus.COMPLETE])
        assert state.progress_percent == 100

    def test_progress_50_when_half_done(self):
        state = self._state_with_agents([AgentStatus.COMPLETE, AgentStatus.PENDING])
        assert state.progress_percent == 50

    def test_is_complete_false_when_running(self):
        state = self._state_with_agents([AgentStatus.RUNNING, AgentStatus.COMPLETE])
        assert state.is_complete is False

    def test_is_complete_true_for_mixed_terminal_states(self):
        state = self._state_with_agents([
            AgentStatus.COMPLETE, AgentStatus.FAILED, AgentStatus.SKIPPED
        ])
        assert state.is_complete is True

    def test_duration_zero_before_completion(self):
        agent = AgentState(category="test")
        assert agent.duration_seconds == 0.0

    def test_empty_state_is_complete(self):
        state = ScanState(target_url="http://test")
        assert state.is_complete is True

    def test_progress_failed_counts_as_done(self):
        state = self._state_with_agents([AgentStatus.FAILED, AgentStatus.PENDING])
        assert state.progress_percent == 50


# ── Full scan integration (mocked AI) ────────────────────────────

class TestRunFullScan:
    """Integration tests for the orchestrator DAG — AI agents are mocked."""

    def _mock_scan_result(self, findings=None):
        return _scan_result(findings or [_finding("Test vuln", "high")])

    def test_unreachable_target_returns_early(self):
        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls:
                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = False
                mock_caller_cls.return_value = mock_caller
                return await run_full_scan("http://unreachable:9999")

        report = asyncio.run(_run())
        assert report.errors
        assert any("not reachable" in e for e in report.errors)
        assert report.score is None

    def test_scan_completes_with_findings(self):
        findings = [_finding("SQL Injection", "critical")]
        scan_result = _scan_result(findings)

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.analyze_findings") as mock_analyze, \
                 patch("engine.orchestrator.get_owasp_context") as mock_rag, \
                 patch("engine.orchestrator.enrich_with_threat_intel") as mock_ti, \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_analyze.return_value = MagicMock(findings=[MagicMock()], risk_level="HIGH")
                mock_rag.return_value = MagicMock()
                mock_ti.return_value = MagicMock()
                mock_mem.return_value = MagicMock()
                return await run_full_scan("http://localhost:9001", categories=["prompt_injection"])

        report = asyncio.run(_run())
        assert report.total_findings == 1
        assert report.score is not None
        assert report.score.score == 80  # -20 for one critical

    def test_scan_with_no_findings_scores_100(self):
        scan_result = _scan_result(findings=[])

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_mem.return_value = MagicMock()
                return await run_full_scan("http://localhost:9001", categories=["prompt_injection"])

        report = asyncio.run(_run())
        assert report.total_findings == 0
        assert report.score.score == 100
        assert report.score.grade == "A"

    def test_progress_callback_called(self):
        scan_result = _scan_result(findings=[])
        events: list[tuple] = []

        def on_progress(cat, status, msg):
            events.append((cat, status, msg))

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_mem.return_value = MagicMock()
                return await run_full_scan(
                    "http://localhost:9001",
                    categories=["prompt_injection"],
                    on_progress=on_progress,
                )

        asyncio.run(_run())
        assert any(e[1] == AgentStatus.RUNNING for e in events)
        assert any(e[1] == AgentStatus.COMPLETE for e in events)

    def test_category_result_callback_called(self):
        scan_result = _scan_result(findings=[_finding("x", "low")])
        received: list = []

        def on_cat_result(cat, result):
            received.append((cat, result))

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.analyze_findings") as mock_analyze, \
                 patch("engine.orchestrator.get_owasp_context") as mock_rag, \
                 patch("engine.orchestrator.enrich_with_threat_intel") as mock_ti, \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_analyze.return_value = MagicMock(findings=[MagicMock()], risk_level="LOW")
                mock_rag.return_value = MagicMock()
                mock_ti.return_value = MagicMock()
                mock_mem.return_value = MagicMock()
                return await run_full_scan(
                    "http://localhost:9001",
                    categories=["prompt_injection"],
                    on_category_result=on_cat_result,
                )

        asyncio.run(_run())
        assert len(received) == 1
        assert received[0][0] == "prompt_injection"

    def test_scanner_failure_logs_error(self):
        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", side_effect=RuntimeError("LLM timeout")), \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_mem.return_value = MagicMock()
                return await run_full_scan(
                    "http://localhost:9001",
                    categories=["prompt_injection"],
                    max_retries=0,
                )

        report = asyncio.run(_run())
        assert any("prompt_injection" in e for e in report.errors)

    def test_deduplication_runs_before_analysis(self):
        """Two scanner results with same finding → only 1 unique finding passed to analysis."""
        dup_finding = _finding("Dup", "high", response="same response here for dedup test")
        scan_result = _scan_result(findings=[dup_finding, dup_finding])
        analyzed_count: list[int] = []

        async def fake_analyze(url, findings):
            analyzed_count.append(len(findings))
            return MagicMock(findings=findings, risk_level="HIGH")

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.analyze_findings", side_effect=fake_analyze), \
                 patch("engine.orchestrator.get_owasp_context") as mock_rag, \
                 patch("engine.orchestrator.enrich_with_threat_intel") as mock_ti, \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_rag.return_value = MagicMock()
                mock_ti.return_value = MagicMock()
                mock_mem.return_value = MagicMock()
                return await run_full_scan("http://localhost:9001", categories=["prompt_injection"])

        report = asyncio.run(_run())
        assert analyzed_count[0] == 1
        assert report.total_findings == 1

    def test_run_single_scan_delegates(self):
        """run_single_scan is a thin wrapper — verify it completes."""
        scan_result = _scan_result(findings=[])

        async def _run():
            with patch("engine.orchestrator.HttpCaller") as mock_caller_cls, \
                 patch("engine.orchestrator.run_scan", return_value=scan_result), \
                 patch("engine.orchestrator.get_memory") as mock_mem:

                mock_caller = AsyncMock()
                mock_caller.health_check.return_value = True
                mock_caller_cls.return_value = mock_caller
                mock_mem.return_value = MagicMock()
                return await run_single_scan("http://localhost:9001", "jailbreak")

        report = asyncio.run(_run())
        assert isinstance(report, FullScanReport)
        assert "jailbreak" in report.category_results


# ── Memory Store integration ───────────────────────────────────────

class TestMemoryStoreIntegration:
    """Integration tests for SQLite memory with real DB (temp file)."""

    def _store(self):
        from nodes.memory_store import MemoryStore
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        return MemoryStore(db_path=tmp.name)

    def test_save_and_retrieve_scan(self):
        store = self._store()
        store.save_scan(
            target_url="http://test:9001",
            categories=["prompt_injection", "jailbreak"],
            score=75,
            grade="B",
            findings_count=3,
            findings_summary="3 issues found",
        )
        records = store.get_history()
        assert len(records) == 1
        assert records[0].target_url == "http://test:9001"
        assert records[0].score == 75
        assert records[0].grade == "B"

    def test_get_history_filtered_by_target(self):
        store = self._store()
        store.save_scan("http://alpha:9001", ["pi"], 80, "B", 2)
        store.save_scan("http://beta:9002", ["jb"], 60, "C", 5)

        alpha_records = store.get_history(target_url="alpha")
        assert len(alpha_records) == 1
        assert "alpha" in alpha_records[0].target_url

    def test_clear_history_removes_all(self):
        store = self._store()
        store.save_scan("http://test", ["pi"], 50, "C", 1)
        store.save_scan("http://test", ["jb"], 70, "C", 2)
        assert len(store.get_history()) == 2

        store.clear_history()
        assert store.get_history() == []

    def test_pii_stripped_before_storage(self):
        store = self._store()
        store.save_scan(
            target_url="http://test",
            categories=["pi"],
            score=50,
            grade="C",
            findings_count=1,
            findings_summary="User john@example.com called 555-123-4567",
        )
        records = store.get_history()
        assert "john@example.com" not in records[0].findings_summary
        assert "555-123-4567" not in records[0].findings_summary

    def test_save_and_retrieve_conversation(self):
        store = self._store()
        store.save_conversation(
            query="What is prompt injection?",
            response="It is an attack where...",
            agent="knowledge",
        )
        convs = store.get_conversations()
        assert len(convs) == 1
        assert convs[0].agent == "knowledge"

    def test_preferences_roundtrip(self):
        store = self._store()
        store.set_preference("default_depth", "medium")
        assert store.get_preference("default_depth") == "medium"

    def test_preference_upsert(self):
        store = self._store()
        store.set_preference("theme", "light")
        store.set_preference("theme", "dark")
        assert store.get_preference("theme") == "dark"

    def test_missing_preference_returns_default(self):
        store = self._store()
        assert store.get_preference("nonexistent", default="fallback") == "fallback"

    def test_get_stats(self):
        store = self._store()
        store.save_scan("http://t1", ["pi"], 80, "B", 2)
        store.save_scan("http://t2", ["jb"], 60, "C", 4)
        stats = store.get_stats()
        assert stats["total_scans"] == 2
        assert stats["average_score"] == 70.0

    def test_limit_respected_in_get_history(self):
        store = self._store()
        for i in range(10):
            store.save_scan(f"http://t{i}", ["pi"], i * 10, "B", i)
        records = store.get_history(limit=3)
        assert len(records) == 3
