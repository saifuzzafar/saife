"""
SAIFE Orchestrator — Enhanced DAG Executor
============================================
Coordinates security scans with state tracking, progress events,
retry logic, and result deduplication.

DAG Flow:
    [Validate] → [Run Scanners ║ Parallel] → [Deduplicate] → [RAG Enrich] → [Analyze] → [Score]

Node Map:
    AI Nodes:    Scanner Agent (per category), Knowledge Agent (RAG), Analysis Agent
    Non-AI Nodes: HttpCaller, ResponseParser, Scorer, StateTracker, Deduplicator
"""
import asyncio
import sys
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.scanner_agent import run_scan, ScanResult, Finding
from agent.analysis_agent import analyze_findings, AnalysisResult
from agent.threat_intel_agent import enrich_with_threat_intel, ThreatIntelReport
from agent.knowledge_agent import get_owasp_context, KnowledgeResponse
from nodes.scorer import calculate_score, ScanScore
from nodes.http_caller import HttpCaller
from nodes.memory_store import get_memory
from data.attack_prompts import CATEGORIES

# Maps scan depth name → max attacks per category (None = all)
DEPTH_MAP: dict[str, int | None] = {
    "small":  2,   # ~12 attacks total, ~1-2 min
    "medium": 4,   # ~24 attacks total, ~2-4 min
    "full":   None # all 32 attacks,    ~4-6 min
}


# ── State Management ──────────────────────────────────────────────

class AgentStatus(str, Enum):
    """Status of each scanner agent during orchestration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    RETRYING = "retrying"
    SKIPPED = "skipped"


@dataclass
class AgentState:
    """Tracks the state of one scanner agent."""
    category: str
    status: AgentStatus = AgentStatus.PENDING
    findings_count: int = 0
    error: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0


@dataclass
class ScanState:
    """Overall scan state — tracks all agents."""
    target_url: str
    agents: dict[str, AgentState] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def is_complete(self) -> bool:
        return all(
            a.status in (AgentStatus.COMPLETE, AgentStatus.FAILED, AgentStatus.SKIPPED)
            for a in self.agents.values()
        )

    @property
    def progress_percent(self) -> int:
        if not self.agents:
            return 0
        done = sum(
            1 for a in self.agents.values()
            if a.status in (AgentStatus.COMPLETE, AgentStatus.FAILED, AgentStatus.SKIPPED)
        )
        return int((done / len(self.agents)) * 100)


# ── Full Scan Report ──────────────────────────────────────────────

@dataclass
class FullScanReport:
    """Complete scan report with all results."""
    target_url: str
    scan_depth: str = "full"
    score: Optional[ScanScore] = None
    analysis: Optional[AnalysisResult] = None
    category_results: dict[str, ScanResult] = field(default_factory=dict)
    owasp_context: list[KnowledgeResponse] = field(default_factory=list)
    threat_intel: Optional[ThreatIntelReport] = None
    state: Optional[ScanState] = None
    errors: list[str] = field(default_factory=list)
    total_findings: int = 0
    scan_duration_seconds: float = 0.0


# ── Progress Callback Type ────────────────────────────────────────
# CLI will pass a callback to get live updates
ProgressCallback = Optional[Callable[[str, AgentStatus, str], None]]


# ── Deduplication (Non-AI Node) ───────────────────────────────────

def deduplicate_findings(all_findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings found by multiple categories.

    Two findings are duplicates if they have the same title AND
    similar evidence (same target response).

    Args:
        all_findings: List of finding dicts from all scanners

    Returns:
        Deduplicated list
    """
    seen: set[str] = set()
    unique: list[Finding] = []

    for finding in all_findings:
        # Create a dedup key from title + first 100 chars of response
        key = (
            finding.title.lower().strip()
            + "|"
            + finding.target_response[:100].lower().strip()
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


# ── Main Orchestrator ─────────────────────────────────────────────

async def run_full_scan(
    target_url: str,
    categories: list[str] | None = None,
    max_concurrent: int = 3,
    max_retries: int = 1,
    scan_depth: str = "full",
    on_progress: ProgressCallback = None,
    on_category_result=None,
) -> FullScanReport:
    """Run a complete security scan with full orchestration.

    DAG execution order:
    1. [Non-AI] Validate target is reachable
    2. [Non-AI] Initialize state tracker
    3. [AI]     Run scanner agents in parallel (with semaphore)
    4. [Non-AI] Deduplicate findings across categories
    5. [AI]     Analysis agent classifies and enriches findings
    6. [Non-AI] Scorer calculates final score

    Args:
        target_url: Target chatbot URL
        categories: Categories to scan (None = all 6)
        max_concurrent: Max parallel agents
        max_retries: Retries per failed agent
        on_progress: Callback for live updates: (category, status, message)

    Returns:
        FullScanReport with everything
    """
    report = FullScanReport(target_url=target_url, scan_depth=scan_depth)
    scan_start = datetime.now()

    # ── Node 1 (Non-AI): Validate target ─────────────────────────
    _notify(on_progress, "target", AgentStatus.RUNNING, "Checking target...")
    caller = HttpCaller()
    is_alive = await caller.health_check(target_url)
    if not is_alive:
        _notify(on_progress, "target", AgentStatus.FAILED, "Target unreachable")
        report.errors.append(f"Target {target_url} is not reachable")
        return report
    _notify(on_progress, "target", AgentStatus.COMPLETE, "Target is alive")

    # ── Node 2 (Non-AI): Initialize state ────────────────────────
    max_attacks_per_cat = DEPTH_MAP.get(scan_depth)
    scan_categories = categories or CATEGORIES
    state = ScanState(target_url=target_url, started_at=scan_start)
    for cat in scan_categories:
        state.agents[cat] = AgentState(category=cat)
    report.state = state

    # ── Node 3 (AI): Run scanners in parallel ─────────────────────
    semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_category(category: str) -> tuple[str, ScanResult | None]:
        """Run one scanner with state tracking and retry."""
        agent_state = state.agents[category]
        agent_state.status = AgentStatus.RUNNING
        agent_state.started_at = datetime.now()
        _notify(on_progress, category, AgentStatus.RUNNING, "Scanning...")

        for attempt in range(1 + max_retries):
            try:
                async with semaphore:
                    result = await run_scan(
                        target_url, category,
                        max_attacks=max_attacks_per_cat,
                        on_progress=on_progress,
                    )

                agent_state.status = AgentStatus.COMPLETE
                agent_state.findings_count = len(result.findings)
                agent_state.completed_at = datetime.now()
                _notify(
                    on_progress, category, AgentStatus.COMPLETE,
                    f"Found {len(result.findings)} issues"
                )
                if on_category_result:
                    on_category_result(category, result)
                return category, result

            except Exception as e:
                agent_state.retry_count = attempt + 1
                if attempt < max_retries:
                    agent_state.status = AgentStatus.RETRYING
                    _notify(on_progress, category, AgentStatus.RETRYING, f"Retry {attempt+1}")
                    await asyncio.sleep(2)  # Brief pause before retry
                else:
                    agent_state.status = AgentStatus.FAILED
                    agent_state.error = str(e)
                    agent_state.completed_at = datetime.now()
                    _notify(on_progress, category, AgentStatus.FAILED, str(e))
                    report.errors.append(f"{category}: {str(e)}")
                    return category, None

        return category, None

    # Launch all scans in parallel
    tasks = [scan_category(cat) for cat in scan_categories]
    results = await asyncio.gather(*tasks)

    # Collect raw findings
    all_findings: list[Finding] = []
    for category, result in results:
        if result:
            report.category_results[category] = result
            for f in result.findings:
                all_findings.append(f)

    # ── Node 4 (Non-AI): Deduplicate findings ────────────────────
    unique_findings = deduplicate_findings(all_findings)
    report.total_findings = len(unique_findings)

    # ── Node 4.5 (AI): RAG Enrichment — Knowledge Agent ───────────
    if unique_findings:
        _notify(on_progress, "knowledge", AgentStatus.RUNNING, "Retrieving OWASP context...")
        try:
            # Collect one (category, title) pair per unique category
            seen_categories: set[str] = set()
            cat_titles: list[tuple[str, str]] = []
            for finding in unique_findings:
                cat = finding.category
                if cat and cat not in seen_categories:
                    seen_categories.add(cat)
                    cat_titles.append((cat, finding.title))

            # Run all knowledge agent calls in parallel instead of sequentially
            contexts = await asyncio.gather(
                *[get_owasp_context(cat, title) for cat, title in cat_titles],
                return_exceptions=True,
            )
            for ctx in contexts:
                if not isinstance(ctx, Exception):
                    report.owasp_context.append(ctx)
            _notify(on_progress, "knowledge", AgentStatus.COMPLETE,
                    f"Retrieved {len(report.owasp_context)} OWASP contexts")
        except Exception as e:
            report.errors.append(f"Knowledge retrieval failed: {str(e)}")
            _notify(on_progress, "knowledge", AgentStatus.FAILED, str(e))

    # ── Node 5 (AI): Analyze findings ─────────────────────────────
    if unique_findings:
        _notify(on_progress, "analysis", AgentStatus.RUNNING, "Analyzing...")
        try:
            report.analysis = await analyze_findings(target_url, unique_findings)
            # LLM sometimes returns empty findings — fall back to scanner findings
            if not report.analysis.findings:
                report.analysis = _build_fallback_analysis(target_url, unique_findings)
            _notify(on_progress, "analysis", AgentStatus.COMPLETE, "Done")
        except Exception as e:
            report.errors.append(f"Analysis failed: {str(e)}")
            _notify(on_progress, "analysis", AgentStatus.FAILED, str(e))
            # Fallback: build AnalysisResult directly from raw scanner findings
            # so the dashboard always has findings to display
            report.analysis = _build_fallback_analysis(target_url, unique_findings)

    # ── Node 5.5 (AI): Threat Intel ───────────────────────────────
    if report.analysis and report.analysis.findings:
        _notify(on_progress, "threat_intel", AgentStatus.RUNNING, "Gathering threat intel...")
        try:
            report.threat_intel = await enrich_with_threat_intel(target_url, report.analysis.findings)
            _notify(on_progress, "threat_intel", AgentStatus.COMPLETE, "Done")
        except Exception as e:
            report.errors.append(f"Threat intel failed: {str(e)}")
            _notify(on_progress, "threat_intel", AgentStatus.FAILED, str(e))
            report.threat_intel = _build_fallback_threat_intel(target_url)

    # ── Node 6 (Non-AI): Score ────────────────────────────────────
    report.score = calculate_score(unique_findings)

    # Finalize
    state.completed_at = datetime.now()
    report.scan_duration_seconds = (
        state.completed_at - scan_start
    ).total_seconds()

    # ── Node 7 (Non-AI): Persist to Memory ────────────────────────
    try:
        memory = get_memory()
        grade = report.score.grade if report.score else "—"
        score_val = report.score.score if report.score else 0
        findings_summary = "; ".join(
            f"{f.title} ({f.severity})"
            for f in unique_findings[:5]  # top 5 findings
        )
        memory.save_scan(
            target_url=target_url,
            categories=scan_categories,
            score=score_val,
            grade=grade,
            findings_count=report.total_findings,
            findings_summary=findings_summary,
        )
    except Exception as e:
        report.errors.append(f"Memory save failed: {str(e)}")

    return report


async def run_single_scan(target_url: str, category: str) -> FullScanReport:
    """Run scan for a single category. Convenience wrapper."""
    return await run_full_scan(target_url, categories=[category])


def _build_fallback_analysis(target_url: str, raw_findings: list) -> "AnalysisResult":
    """Build a basic AnalysisResult from raw scanner findings when the LLM analysis fails."""
    from agent.analysis_agent import AnalysisResult, AnalyzedFinding

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in raw_findings:
        sev = f.severity if f.severity in counts else "medium"
        counts[sev] += 1

    if counts["critical"] > 0:
        risk_level = "CRITICAL"
    elif counts["high"] > 0:
        risk_level = "HIGH"
    elif counts["medium"] > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    total = len(raw_findings)
    summary_parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
    executive_summary = (
        f"Security scan identified {total} vulnerabilities "
        f"({', '.join(summary_parts)}). "
        "Review findings below and prioritize critical and high severity issues."
    )

    analyzed = [
        AnalyzedFinding(
            title=f.title,
            severity=f.severity,
            category=f.category,
            attack_used=f.attack_used,
            target_response=f.target_response,
            evidence=f.evidence,
            recommendation=f.recommendation,
        )
        for f in raw_findings
    ]

    return AnalysisResult(
        target_url=target_url,
        executive_summary=executive_summary,
        risk_level=risk_level,
        findings=analyzed,
        total_vulnerabilities=total,
        severity_breakdown=counts,
        top_recommendation="Address critical and high severity findings immediately.",
    )


def _build_fallback_threat_intel(target_url: str) -> "ThreatIntelReport":
    """Return a minimal ThreatIntelReport when the LLM agent fails."""
    return ThreatIntelReport(
        target_url=target_url,
        global_threat_summary=(
            "Threat intelligence enrichment was skipped — the local model could not "
            "produce structured output. Run a full scan with a capable model for MITRE mapping."
        ),
        likely_threat_actors=["Automated scanners", "Opportunistic attackers"],
        correlated_techniques=[],
    )


def _notify(
    callback: ProgressCallback,
    category: str,
    status: AgentStatus,
    message: str,
) -> None:
    """Send progress update if callback is provided."""
    if callback:
        callback(category, status, message)
