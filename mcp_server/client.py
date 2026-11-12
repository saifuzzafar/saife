"""
SAIFE MCP Client
================
Test client for the SAIFE MCP server.
Demonstrates connecting to the server, listing tools/prompts/resources,
and calling tools programmatically.

Usage:
    # First start the server in HTTP mode:
    python -m mcp_server.server --transport streamable-http --port 8080

    # Then run this client:
    python -m mcp_server.client
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


async def demo_mcp_client(server_url: str = "http://localhost:8080/mcp") -> None:
    """Demo client that connects to the SAIFE MCP server and exercises all capabilities."""

    print("=" * 60)
    print("SAIFE MCP Client Demo")
    print("=" * 60)

    transport = StreamableHttpTransport(server_url)

    async with Client(transport) as client:

        # ── 1. List all tools ──────────────────────────────────────
        print("\n📦 Available Tools:")
        tools = await client.list_tools()
        for tool in tools:
            print(f"  • {tool.name}: {tool.description[:70]}...")

        # ── 2. List all prompts ────────────────────────────────────
        print("\n💬 Available Prompts:")
        prompts = await client.list_prompts()
        for prompt in prompts:
            print(f"  • {prompt.name}: {prompt.description[:70]}...")

        # ── 3. List all resources ──────────────────────────────────
        print("\n📚 Available Resources:")
        resources = await client.list_resources()
        for resource in resources:
            print(f"  • {resource.uri}: {resource.description[:70]}...")

        # ── 4. Call: list_attack_categories ───────────────────────
        print("\n🗡️  Attack Categories:")
        result = await client.call_tool("list_attack_categories", {})
       ## data = json.loads(result[0].text) if result else {}
        data = json.loads(result.content[0].text) if result and result.content else {}
        print(f"  Total: {data.get('total_attacks', 0)} attacks across {data.get('total_categories', 0)} categories")
        for cat, info in data.get("categories", {}).items():
            print(f"  [{info['owasp_id']}] {cat}: {info['count']} attacks")

        # ── 5. Call: check_target_health ──────────────────────────
        print("\n🏥 Target Health Check:")
        result = await client.call_tool("check_target_health", {"target_url": "http://localhost:9001"})
        health = json.loads(result.content[0].text) if result and hasattr(result, 'content') and result.content else {}
        status = health.get("status", "unknown")
        print(f"  localhost:9001 → {status.upper()}")

        # ── 6. Call: get_owasp_guidance ───────────────────────────
        print("\n🔍 OWASP Guidance (prompt injection):")
        result = await client.call_tool("get_owasp_guidance", {"query": "prompt injection"})
        guidance = json.loads(result.content[0].text) if result and hasattr(result, 'content') and result.content else {}
        for r in guidance.get("results", [])[:1]:
            print(f"  Score: {r['relevance_score']} | {r['text'][:150]}...")

        # ── 7. Call: get_scan_history ─────────────────────────────
        print("\n📜 Scan History:")
        result = await client.call_tool("get_scan_history", {"limit": 3})
        history = json.loads(result.content[0].text) if result and hasattr(result, 'content') and result.content else {}
        print(f"  Total scans: {history.get('total_scans', 0)}")
        print(f"  Avg score: {history.get('average_score', 0):.1f}/100")
        for rec in history.get("history", [])[:2]:
            print(f"  [{rec.get('grade', '?')}] {rec.get('target', 'unknown')} — {rec.get('date', '')}")

        # ── 8. Read a resource ────────────────────────────────────
        print("\n📖 SAIFE Config Resource:")
        resource = await client.read_resource("saife://config")
        config = json.loads(resource.contents[0].text) if resource and hasattr(resource, 'contents') and resource.contents else {}
        print(f"  Model: {config.get('llm_model', 'unknown')}")
        print(f"  Max concurrent agents: {config.get('max_concurrent_agents', 'unknown')}")

        # ── 9. Get a prompt ───────────────────────────────────────
        print("\n📝 Security Audit Prompt (prompt_injection focus):")
        prompt_result = await client.get_prompt(
            "security_audit_prompt",
            {"target_url": "http://localhost:9001", "focus_area": "prompt_injection"},
        )
        print(f"  {prompt_result.messages[0].content.text[:200]}...")

    print("\n" + "=" * 60)
    print("✅ MCP Client demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SAIFE MCP Client")
    parser.add_argument(
        "--server",
        default="http://localhost:8080/mcp",
        help="MCP server URL",
    )
    args = parser.parse_args()

    asyncio.run(demo_mcp_client(args.server))
