"""
SAIFE MCP Server
================
FastMCP server exposing SAIFE's security scanning capabilities
via the Model Context Protocol (MCP).

Architecture (from course):
  - Tools     → scan_target, quick_scan, get_history, list_attacks, get_owasp_guidance
  - Prompts   → security_audit, vulnerability_analysis, risk_report
  - Resources → owasp://knowledge, saife://attacks, saife://history

Usage:
    # Run as stdio server (Claude Desktop)
    python -m mcp_server.server

    # Run as HTTP server (remote)
    python -m mcp_server.server --transport streamable-http --port 8080

Claude Desktop config (~/.claude_desktop/config.json):
    {
      "mcpServers": {
        "saife": {
          "command": "python",
          "args": ["-m", "mcp_server.server"],
          "cwd": "/path/to/capstone/saife"
        }
      }
    }
"""
from __future__ import annotations

import asyncio
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import fastmcp
from fastmcp import FastMCP, Context

# Add parent dir to path so we can import SAIFE modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import settings
from nodes.memory_store import MemoryStore
from data.attack_prompts import ALL_ATTACKS, CATEGORIES as ATTACK_CATEGORIES, PROMPT_INJECTION, JAILBREAK, DATA_EXTRACTION, OUTPUT_HANDLING, RAG_POISONING, AVAILABILITY
from nodes.vector_store import get_store

# ── Server Init ───────────────────────────────────────────────────

mcp = FastMCP(
    name="saife-security-scanner",
    instructions="""
You are SAIFE (Secure AI Framework for Everyone), an AI security scanner.

You can:
- Scan LLM applications for OWASP Top 10 vulnerabilities
- Retrieve OWASP knowledge and security guidance
- Access scan history and security statistics
- List available attack categories and prompts

Available attack categories: prompt_injection, jailbreak, data_extraction,
output_handling, rag_poisoning, availability

All target bots must expose a POST /chat endpoint accepting {"message": "..."}.
""",
)


# ══════════════════════════════════════════════════════════════════
# TOOLS — Callable actions the LLM can invoke
# ══════════════════════════════════════════════════════════════════

@mcp.tool(
    description="Run a full security scan on a target LLM application across all 6 OWASP categories. Returns security score, grade, and all findings."
)
async def scan_target(target_url: str, ctx: Context = None) -> dict[str, Any]:
    """Full security scan across all categories.

    Args:
        target_url: URL of the target LLM app (e.g., http://localhost:9001)
        ctx: FastMCP Context for streaming progress
    """
    from engine.orchestrator import run_full_scan, AgentStatus

    def _progress_cb(category: str, status: AgentStatus, message: str) -> None:
        if ctx:
            ctx.info(f"[{category}] {status.upper()}: {message}")

    try:
        if ctx:
            ctx.info(f"Starting full scan on {target_url}...")
        report = await run_full_scan(
            target_url=target_url,
            categories=list(ATTACK_CATEGORIES.keys()),
            on_progress=_progress_cb
        )
        return {
            "status": "complete",
            "target": target_url,
            "score": report.score,
            "grade": report.grade,
            "total_findings": len(report.findings),
            "critical": sum(1 for f in report.findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in report.findings if f.severity == "HIGH"),
            "medium": sum(1 for f in report.findings if f.severity == "MEDIUM"),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "owasp_id": f.owasp_id,
                    "evidence": f.evidence[:200],
                }
                for f in report.findings
            ],
            "recommendations": report.recommendations,
            "executive_summary": report.executive_summary,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "target": target_url}


@mcp.tool(
    description="Run a quick scan on a single vulnerability category. Faster than a full scan. Categories: prompt_injection, jailbreak, data_extraction, output_handling, rag_poisoning, availability"
)
async def quick_scan(target_url: str, category: str, ctx: Context = None) -> dict[str, Any]:
    """Quick single-category scan.

    Args:
        target_url: URL of the target LLM app
        category: Vulnerability category to test
        ctx: FastMCP Context for streaming progress
    """
    valid = list(ATTACK_CATEGORIES.keys())
    if category not in valid:
        return {
            "status": "error",
            "error": f"Invalid category '{category}'. Valid: {valid}",
        }

    from engine.orchestrator import run_single_scan, AgentStatus
    
    def _progress_cb(cat: str, status: AgentStatus, message: str) -> None:
        if ctx:
            ctx.info(f"[{cat}] {status.upper()}: {message}")

    try:
        if ctx:
            ctx.info(f"Starting quick scan on {target_url} for {category}...")
        report = await run_single_scan(
            target_url=target_url, 
            category=category,
        )
        return {
            "status": "complete",
            "target": target_url,
            "category": category,
            "score": report.score,
            "grade": report.grade,
            "findings_count": len(report.findings),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "owasp_id": f.owasp_id,
                    "evidence": f.evidence[:200],
                }
                for f in report.findings
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool(
    description="Get scan history from the persistent memory store. Shows past scan results with scores and dates."
)
async def get_scan_history(limit: int = 10) -> dict[str, Any]:
    """Retrieve past scan records.

    Args:
        limit: Maximum number of records to return (default: 10)
    """
    try:
        store = MemoryStore()
        records = store.get_history(limit=limit)
        stats = store.get_stats()

        return {
            "total_scans": stats.get("total_scans", 0),
            "average_score": stats.get("avg_score", 0),
            "history": [
                {
                    "id": r.get("id"),
                    "target": r.get("target_url"),
                    "date": r.get("scanned_at"),
                    "score": r.get("score"),
                    "grade": r.get("grade"),
                    "categories": r.get("categories"),
                    "findings_count": r.get("findings_count"),
                }
                for r in records
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool(
    description="List all available attack categories and the number of attacks in each. Shows what SAIFE can test."
)
async def list_attack_categories() -> dict[str, Any]:
    """List all attack categories and their attack counts."""
    # OWASP ID mapping — CATEGORIES is a plain list[str], so we define the map here
    owasp_id_map = {
        "prompt_injection": "LLM01",
        "jailbreak": "LLM01",
        "data_extraction": "LLM02",
        "output_handling": "LLM05",
        "rag_poisoning": "LLM08",
        "availability": "LLM10",
    }
    _cat_map = {
        "prompt_injection": PROMPT_INJECTION,
        "jailbreak": JAILBREAK,
        "data_extraction": DATA_EXTRACTION,
        "output_handling": OUTPUT_HANDLING,
        "rag_poisoning": RAG_POISONING,
        "availability": AVAILABILITY,
    }
    result = {}
    # ALL_ATTACKS is a dict[str, list[str]] — safe to call .keys() on
    for category in ALL_ATTACKS.keys():
        attacks = _cat_map.get(category, [])
        result[category] = {
            "count": len(attacks),
            "owasp_id": owasp_id_map.get(category, "—"),
            "sample_attacks": [a[:80] + "..." if len(a) > 80 else a for a in attacks[:2]],
        }
    return {
        "total_categories": len(result),
        "total_attacks": sum(v["count"] for v in result.values()),
        "categories": result,
    }


@mcp.tool(
    description="Query the OWASP LLM Top 10 knowledge base for security guidance on a specific vulnerability or category."
)
async def get_owasp_guidance(query: str) -> dict[str, Any]:
    """Search OWASP knowledge base for security guidance.

    Args:
        query: Security topic or vulnerability to search for (e.g., 'prompt injection', 'data extraction')
    """
    try:
        store = get_store()
        store.initialize()
        chunks = store.search(query, n_results=3)

        if not chunks:
            return {"status": "not_found", "query": query}

        return {
            "query": query,
            "results": [
                {
                    "text": chunk.text[:400],
                    "source": chunk.source,
                    "relevance_score": round(chunk.score, 3),
                }
                for chunk in chunks
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool(
    description="Check if a target LLM application is reachable and responding before running a full scan."
)
async def check_target_health(target_url: str) -> dict[str, Any]:
    """Check if the target is alive and responding.

    Args:
        target_url: URL of the target LLM application
    """
    import httpx

    chat_url = target_url.rstrip("/") + "/chat"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                chat_url,
                json={"message": "hello"},
            )
            return {
                "status": "healthy" if resp.status_code == 200 else "unhealthy",
                "http_status": resp.status_code,
                "url": chat_url,
                "response_preview": resp.text[:100],
            }
    except httpx.ConnectError:
        return {"status": "unreachable", "url": chat_url, "error": "Connection refused"}
    except Exception as e:
        return {"status": "error", "url": chat_url, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# PROMPTS — Pre-built prompt templates for common tasks
# ══════════════════════════════════════════════════════════════════

@mcp.prompt(
    description="Generate a comprehensive security audit prompt for a given target LLM application."
)
def security_audit_prompt(target_url: str, focus_area: str = "all") -> str:
    """Security audit prompt template.

    Args:
        target_url: The LLM app to audit
        focus_area: Specific area to focus on (prompt_injection, data_extraction, etc.) or 'all'
    """
    categories = list(ATTACK_CATEGORIES.keys()) if focus_area == "all" else [focus_area]
    cats_str = ", ".join(categories)

    return f"""You are a security auditor using SAIFE to assess the LLM application at {target_url}.

Please perform the following security assessment:

1. First, check if the target is healthy using check_target_health("{target_url}")
2. Run a security scan: {"scan_target" if focus_area == "all" else "quick_scan"}("{target_url}"{f', "{focus_area}"' if focus_area != "all" else ""})
3. For each CRITICAL or HIGH finding, get OWASP guidance using get_owasp_guidance()
4. Summarize findings with:
   - Overall risk level
   - Top 3 vulnerabilities to fix immediately
   - Recommended mitigations per OWASP category ({cats_str})

Focus on actionable recommendations the development team can implement.
"""


@mcp.prompt(
    description="Generate a vulnerability analysis prompt for investigating a specific security finding."
)
def vulnerability_analysis_prompt(
    vulnerability_type: str,
    evidence: str,
    target_url: str = "",
) -> str:
    """Deep-dive vulnerability analysis prompt.

    Args:
        vulnerability_type: Type of vulnerability (e.g., 'prompt_injection', 'data_extraction')
        evidence: The evidence/payload that triggered the vulnerability
        target_url: Optional target URL for context
    """
    return f"""Analyze this security vulnerability found by SAIFE:

**Vulnerability Type**: {vulnerability_type}
**Evidence**: {evidence}
{"**Target**: " + target_url if target_url else ""}

Please:
1. Get OWASP guidance: get_owasp_guidance("{vulnerability_type}")
2. Explain WHY this is dangerous (business impact)
3. Rate the exploitability (Easy/Medium/Hard)
4. Provide 3 specific code-level mitigations
5. Suggest a test to verify the fix worked

Format your response as a security advisory report.
"""


@mcp.prompt(
    description="Generate a risk report prompt that compares multiple scan results from history."
)
def risk_trend_report_prompt(limit: int = 5) -> str:
    """Risk trend analysis prompt using scan history.

    Args:
        limit: Number of historical scans to analyze
    """
    return f"""Generate a security risk trend report using SAIFE's scan history.

Steps:
1. Get scan history: get_scan_history({limit})
2. Analyze the data to identify:
   - Security score trends (improving/declining?)
   - Most frequently found vulnerability categories
   - Targets with consistently low scores
3. Create a risk summary with:
   - Overall security posture (1-10)
   - Trend direction (Improving/Stable/Declining)
   - Top 3 recurring vulnerabilities
   - Priority targets for remediation

Present as an executive summary suitable for a security team meeting.
"""


# ══════════════════════════════════════════════════════════════════
# RESOURCES — Readable data exposed to MCP clients
# ══════════════════════════════════════════════════════════════════

@mcp.resource(
    uri="owasp://knowledge",
    description="Full OWASP LLM Top 10 knowledge base used by SAIFE's RAG agent.",
    mime_type="text/markdown",
)
def owasp_knowledge_resource() -> str:
    """Returns the OWASP LLM Top 10 knowledge base."""
    knowledge_path = Path(__file__).parent.parent / "data" / "owasp_knowledge.md"
    if knowledge_path.exists():
        return knowledge_path.read_text()
    return "# OWASP Knowledge Base\n\nKnowledge base not found."


@mcp.resource(
    uri="saife://attacks",
    description="Complete SAIFE attack library — all 32 attack prompts across 6 OWASP categories.",
    mime_type="application/json",
)
def attack_library_resource() -> str:
    """Returns all attack prompts organized by category."""
    _cat_map = {
        "prompt_injection": PROMPT_INJECTION,
        "jailbreak": JAILBREAK,
        "data_extraction": DATA_EXTRACTION,
        "output_handling": OUTPUT_HANDLING,
        "rag_poisoning": RAG_POISONING,
        "availability": AVAILABILITY,
    }
    library = {}
    for category, owasp_id in ATTACK_CATEGORIES.items():
        attacks = _cat_map.get(category, [])
        library[category] = {
            "owasp_id": owasp_id,
            "count": len(attacks),
            "attacks": attacks,
        }
    return json.dumps(library, indent=2)


@mcp.resource(
    uri="saife://history",
    description="Recent SAIFE scan history from persistent SQLite memory store.",
    mime_type="application/json",
)
def scan_history_resource() -> str:
    """Returns recent scan history as JSON."""
    try:
        store = MemoryStore()
        records = store.get_history(limit=20)
        stats = store.get_stats()
        return json.dumps({"stats": stats, "history": records}, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource(
    uri="saife://config",
    description="Current SAIFE configuration settings.",
    mime_type="application/json",
)
def saife_config_resource() -> str:
    """Returns SAIFE configuration (safe fields only)."""
    return json.dumps(
        {
            "llm_model": settings.llm_model,
            "max_concurrent_agents": settings.max_concurrent_agents,
            "max_retries": settings.max_retries,
            "enable_tracing": settings.enable_tracing,
            "memory_db_path": settings.memory_db_path,
            "chroma_db_path": settings.chroma_db_path,
        },
        indent=2,
    )


# ══════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SAIFE MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport type (default: stdio for Claude Desktop)",
    )
    parser.add_argument("--port", type=int, default=8080, help="Port for HTTP transport")
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP transport")
    args = parser.parse_args()

    if args.transport == "stdio":
        print("Starting SAIFE MCP Server (stdio)...", file=sys.stderr)
        mcp.run(transport="stdio")
    else:
        print(f"Starting SAIFE MCP Server (HTTP) on {args.host}:{args.port}...", file=sys.stderr)
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
