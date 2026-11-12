# 🛡️ SAIFE — Secure AI Framework for Everyone

> A production-grade, multi-agent AI security scanner that autonomously tests LLM applications for OWASP LLM Top 10 vulnerabilities using PydanticAI, ChromaDB RAG, SQLite memory, and MCP.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Setup](#setup)
- [Usage](#usage)
- [MCP Server](#mcp-server)
- [Evaluation Suite](#evaluation-suite)
- [Project Structure](#project-structure)
- [Phase Map](#phase-map)

---

## Overview

SAIFE autonomously scans LLM chatbot applications for security vulnerabilities using a **4-agent hybrid architecture**:

1. **Scanner Agent** — Sends attack prompts, detects vulnerabilities, adapts strategy per response
2. **Analysis Agent** — Classifies severity, maps OWASP IDs, writes executive summaries
3. **Threat Intel Agent** — Correlates findings with MITRE ATT&CK techniques, CVEs, and threat actor profiles
4. **Knowledge Agent** — RAG-powered OWASP expert that retrieves grounded fix recommendations

**Results:** Scored 0-100 with letter grades (A-F), rich CLI output, and persistent scan history.

---

## Quick Start Commands

### 1. Web Dashboard (Next.js)
```bash
cd dashboard
npm run dev
```
Open `http://localhost:3000` to access the SAIFE Premium Web Dashboard. You can boot the test targets directly from the UI.

### 2. Manual CLI Commands
If you prefer running components manually from the terminal:
```bash
# Start test bots (ports 9001, 9002, 9003)
uvicorn target.vulnerable_chatbot:app --port 9001 &
uvicorn target.partial_chatbot:app --port 9002 &
uvicorn target.secure_chatbot:app --port 9003 &

# Run a Full Scan
python main.py scan --target http://localhost:9001

# Run the Evaluation Suite
python main.py eval --suite all

# Start the MCP Server (for Claude Desktop)
python main.py mcp
```

---

## Assessment

Run the capstone assessor from the `katas-exercises` root directory:

```bash
cd /Users/saifuzzafar/Desktop/project/AI/katas/katas-exercises
source .venv/bin/activate
katas assess capstone/saife
```

Report saved to: `capstone/saife/assessment_reports/assessment.html`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI (main.py)                              │
│        scan | quick | history | eval | mcp                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           ORCHESTRATOR (engine/orchestrator.py)               │
│                                                               │
│  DAG Flow:                                                    │
│  [Validate] → [Scan ║ Parallel x6] → [Deduplicate]           │
│           → [RAG Enrich] → [Analyze] → [Score] → [Persist]   │
└──────────────────────┬──────────────────────────────────────┘
           ┌───────────┼───────────┐
           ▼           ▼           ▼
  ┌──────────────┐ ┌──────────┐ ┌──────────┐
  │Scanner Agent │ │ Scanner  │ │ Scanner  │  ← 6 parallel
  │(AI) PydAI    │ │  (AI)    │ │  (AI)    │
  └──────┬───────┘ └────┬─────┘ └────┬─────┘
         │              │             │
  ┌──────▼──────────────▼─────────────▼──────┐
  │  Knowledge Agent (RAG) — ChromaDB         │
  │  OWASP LLM Top 10 → sentence-transformers │
  └──────────────────────┬────────────────────┘
                         │
  ┌──────────────────────▼────────────────────┐
  │  Memory Store + PII Guardrail              │
  │  SQLite scan_history | PII scrubbing       │
  └───────────────────────────────────────────┘
```

### Node Inventory

| # | Node | Type | Role |
|---|------|------|------|
| 1 | Scanner Agent | **AI** | Sends attacks, detects vulnerabilities |
| 2 | Analysis Agent | **AI** | Classifies severity, writes summaries |
| 3 | Threat Intel Agent | **AI** | Correlates findings with MITRE ATT&CK & CVEs |
| 4 | Knowledge Agent | **AI** | RAG retrieval from OWASP knowledge base |
| 5 | HTTP Caller | Non-AI | POSTs to target `/chat` endpoint |
| 6 | Response Parser | Non-AI | Keyword/regex detection of vulnerability signals |
| 7 | Scorer | Non-AI | Calculates 0-100 score with letter grade |
| 8 | Attack Library | Non-AI | 32 attack prompts across 6 OWASP categories |
| 9 | Deduplicator | Non-AI | Removes duplicate findings across categories |
| 10 | State Tracker | Non-AI | Tracks agent lifecycle (PENDING→RUNNING→COMPLETE) |
| 11 | Vector Store | Non-AI | ChromaDB + sentence-transformers embeddings |
| 12 | PII Guardrail | Non-AI | Strips PII (8 patterns) before storage |
| 13 | Memory Store | Non-AI | SQLite persistence for scan history |
| 14 | Observability | Non-AI | OTEL tracing via Pydantic Logfire |

**4 AI Nodes + 10 Non-AI Nodes = 14 Total Nodes**

---

## Features

| Feature | Implementation |
|---------|----------------|
| **Multi-agent AI** | 4 PydanticAI agents with structured Pydantic outputs |
| **32-attack library** | 6 OWASP categories: prompt injection, jailbreak, data extraction, output handling, RAG poisoning, availability |
| **RAG (ChromaDB)** | OWASP LLM Top 10 knowledge base, local embeddings, hybrid LLM+fallback retrieval |
| **Persistent Memory** | SQLite scan history with stats |
| **PII Guardrail** | 8-pattern regex: email, phone, SSN, credit card, IP, API key, bearer token, AWS key |
| **Evaluation Suite** | Pydantic Evals + LLMJudge + custom evaluators (avg faithfulness: 0.94) |
| **OTEL Tracing** | Pydantic Logfire integration (`SAIFE_ENABLE_TRACING=true`) |
| **MCP Server** | FastMCP server with 6 tools, 3 prompts, 4 resources |
| **Rich CLI** | Progress bars, color-coded tables, executive summaries |
| **Next.js Dashboard** | Real-time web UI with SSE streaming, live category grid, scan history, score sparkline |

---

## Setup

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai) running locally with `llama3.1`
- `uv` (recommended) or `pip`

### Install

```bash
# Clone and navigate
cd capstone/saife

# Install dependencies (from project root)
uv sync

# Pull the LLM model
ollama pull llama3.1

# Start Ollama
ollama serve
```

### Start Test Targets (optional)

> **All commands below must be run from the `capstone/saife/` directory.**

```bash
cd capstone/saife   # ← must be here, not the repo root

# Vulnerable bot (port 9001)
uvicorn target.vulnerable_chatbot:app --port 9001

# Partial bot (port 9002)
uvicorn target.partial_chatbot:app --port 9002

# Secure bot (port 9003)
uvicorn target.secure_chatbot:app --port 9003
```

---

## Web Dashboard

The dashboard is a Next.js 16 / React 19 app that provides a real-time UI on top of the Python backend.

### Start

```bash
cd dashboard
npm install      # first time only
npm run dev
```

Open `http://localhost:3000`. Make sure Ollama is running and at least one test target is up.

### Features

| Feature | Description |
|---------|-------------|
| **Scan form** | Enter a target URL, pick scan depth (quick / standard / full), hit Scan |
| **Live progress log** | Per-attack events streamed in real time via SSE — shows each prompt sent, response latency, signal detected |
| **Category status grid** | 6 boxes (one per OWASP category) that change colour as scanning progresses: grey → yellow → green/red |
| **Live findings card** | New findings appear as each category finishes, before the full scan completes |
| **Score & grade** | Final 0-100 score with letter grade (A/B/C/D/F), risk level badge |
| **Scan history table** | Previous scans with timestamp, target, score, grade — with a sparkline showing score trend over time |
| **Export JSON** | Download the full scan report as a `.json` file |
| **Re-run** | One-click re-scan of a previous target from history |
| **Cancel** | Aborts mid-scan cleanly — sends `SIGTERM` to the Python process to avoid zombie processes |
| **Browser notification** | Desktop notification when scan completes (requires browser permission) |

### How SSE streaming works

The Next.js API route (`/api/scan`) spawns `cli_json.py` as a subprocess. Python writes `PROGRESS:` and `RESULT_PARTIAL:` lines to stderr; the Node.js route reads these and forwards them to the browser as Server-Sent Events. The React frontend subscribes via `EventSource` and updates state as events arrive.

```
Python (stderr)  →  Node.js API route  →  EventSource  →  React state
PROGRESS: ...       /api/scan              SSE stream       category grid
RESULT_PARTIAL: ... (ReadableStream)                        findings card
```

---

## Usage

### Full Scan

```bash
python main.py scan --target http://localhost:9001
```

Output: Score, grade, findings table, OWASP guidance, recommendations.

### Quick Scan (single category)

```bash
python main.py quick --target http://localhost:9001 --category prompt_injection
```

Categories: `prompt_injection`, `jailbreak`, `data_extraction`, `output_handling`, `rag_poisoning`, `availability`

### View History

```bash
python main.py history
```

### List Attack Library

```bash
python main.py attacks
```

### Scoring Guide

```bash
python main.py score
```

### Run Evaluations

```bash
python main.py eval --suite all      # Scanner + RAG evals
python main.py eval --suite scanner  # Scanner accuracy only
python main.py eval --suite rag      # RAG faithfulness only

# To run a single evaluation file directly:
python -m evals.scanner_evals
python -m evals.rag_evals
```

---

## MCP Server

SAIFE exposes its scanning capabilities via the **Model Context Protocol (MCP)** using FastMCP.

### Tools

| Tool | Description |
|------|-------------|
| `scan_target` | Full security scan (all 6 categories) |
| `quick_scan` | Single-category scan |
| `get_scan_history` | Retrieve past scan records from SQLite |
| `list_attack_categories` | List all 32 attacks by category |
| `get_owasp_guidance` | Query OWASP knowledge base via RAG |
| `check_target_health` | Verify target is reachable before scanning |

### Prompts

| Prompt | Description |
|--------|-------------|
| `security_audit_prompt` | Full security audit workflow prompt |
| `vulnerability_analysis_prompt` | Deep-dive analysis for a specific finding |
| `risk_trend_report_prompt` | Risk trend analysis from scan history |

### Resources

| URI | Description |
|-----|-------------|
| `owasp://knowledge` | Full OWASP LLM Top 10 knowledge base (Markdown) |
| `saife://attacks` | Complete attack library (JSON) |
| `saife://history` | Recent scan history (JSON) |
| `saife://config` | SAIFE configuration settings |

### Start MCP Server

```bash
# stdio — for Claude Desktop
python main.py mcp

# HTTP — for remote access / testing
python main.py mcp --transport http --port 8080
```

### Connect Claude Desktop

Copy `mcp_server/claude_desktop_config.json` into your Claude Desktop config:

```bash
# macOS
cat mcp_server/claude_desktop_config.json
# Copy the "mcpServers" block into:
# ~/Library/Application Support/Claude/claude_desktop_config.json
```

### Test with MCP Client

```bash
# Start server in HTTP mode first
python main.py mcp --transport http &

# Run client demo
python -m mcp_server.client --server http://localhost:8080/mcp
```

---

## Evaluation Suite

```bash
python main.py eval --suite all
```

### Scanner Evals

- `FindingsInRange` — Vulnerable bot should have 3+ findings
- `NoCriticalOnSecure` — Secure bot should have 0 critical findings
- `FindingsHaveEvidence` — Every finding must have evidence
- `LLMJudge (security_accuracy)` — LLM rates finding accuracy 1-10
- `LLMJudge (evidence_quality)` — LLM rates evidence quality 1-10

### RAG Faithfulness Evals

**Average score: 0.94/1.0** across 6 OWASP cases:

| Case | Score |
|------|-------|
| prompt_injection | 1.00 ✅ |
| data_extraction | 1.00 ✅ |
| output_handling | 0.88 ✅ |
| excessive_agency | 0.88 ✅ |
| rag_poisoning | 1.00 ✅ |
| availability | 0.88 ✅ |

---

## Project Structure

```
capstone/saife/
├── main.py                    # CLI entry point (scan, quick, history, eval, mcp)
├── config.py                  # Settings via pydantic-settings
├── ARCHITECTURE.md            # Detailed architecture documentation
│
├── agent/                     # AI Agents (PydanticAI)
│   ├── scanner_agent.py       # Vulnerability scanner (hybrid architecture)
│   ├── analysis_agent.py      # Severity classifier + OWASP mapper
│   └── knowledge_agent.py     # RAG-powered OWASP expert
│
├── engine/
│   └── orchestrator.py        # DAG executor, parallel scan coordinator
│
├── nodes/                     # Non-AI processing nodes
│   ├── http_caller.py         # Target HTTP client
│   ├── response_parser.py     # Vulnerability signal detection
│   ├── scorer.py              # Security score calculator
│   ├── vector_store.py        # ChromaDB + sentence-transformers
│   ├── memory_store.py        # SQLite persistence
│   ├── pii_guardrail.py       # PII sanitizer (8 patterns)
│   └── observability.py       # OTEL/Logfire tracing
│
├── mcp_server/                # MCP Server (Phase 5)
│   ├── server.py              # FastMCP server (6 tools, 3 prompts, 4 resources)
│   ├── client.py              # Demo MCP client
│   └── claude_desktop_config.json  # Claude Desktop integration
│
├── evals/                     # Evaluation suite (Phase 5)
│   ├── scanner_evals.py       # Scanner accuracy + LLMJudge
│   ├── rag_evals.py           # RAG faithfulness evaluation
│   ├── evaluators/
│   │   └── vulnerability.py   # Custom Pydantic Evals evaluators
│   └── datasets/
│       └── security_qa.py     # Test dataset (vulnerable/partial/secure)
│
├── data/
│   ├── attack_prompts.py      # 32 attack prompts across 6 OWASP categories
│   └── owasp_knowledge.md     # OWASP LLM Top 10 knowledge base
│
└── target/                    # Test LLM applications
    ├── vulnerable_chatbot.py  # Score: ~30/100 (D) — all attacks succeed
    ├── partial_chatbot.py     # Score: ~60/100 (C) — some defenses
    └── secure_chatbot.py      # Score: ~95/100 (A) — full defenses
```

---

## Troubleshooting

### Scan takes too long / appears frozen

The dashboard scan runs a local LLM (llama3.1:8b via Ollama) for every attack category. Expected times:

| Depth | Attacks | Typical Time |
|-------|---------|-------------|
| Quick | ~12 | ~2-3 min |
| Standard | ~24 | ~3-5 min |
| Full | 32 | ~5-8 min |

Use the **✕ Cancel** button to abort mid-scan. This cleanly kills the Python process.

---

### Zombie scan processes

If a scan is interrupted without clicking Cancel (e.g. server restart, browser close, network drop), the Python backend process may keep running and compete with Ollama — making all subsequent scans slow.

**Check for zombie processes:**
```bash
ps aux | grep cli_json.py | grep -v grep
```

**Kill all zombie scans:**
```bash
pkill -f "cli_json.py"
```

Run this command any time scans feel unusually slow. After killing zombies, the next scan should complete at normal speed.

> **Why does this happen?** The dashboard API route (Next.js) spawns a Python subprocess. If the HTTP connection drops before the scan finishes, the subprocess keeps running. The Cancel button prevents this by sending SIGTERM to Python before disconnecting.

---

### Ollama not responding / model errors

```bash
# Check Ollama is running
ollama list

# If not running
ollama serve

# Verify the model is available
ollama pull llama3.1
```

---

## Phase Map

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | CLI, Target Bots, Core Infra | ✅ Complete |
| 2 | Scanner/Analysis Agents, Orchestrator, Evals | ✅ Complete |
| 3 | RAG — ChromaDB + Knowledge Agent | ✅ Complete |
| 4 | Memory (SQLite) + PII Guardrail | ✅ Complete |
| 5 | Pydantic Evals + LLMJudge | ✅ Complete |
| 6 | OTEL Observability (Logfire) | ✅ Complete |
| 7 | MCP Server (FastMCP) | ✅ Complete |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `SAIFE_LLM_MODEL` | `ollama:llama3.1` | LLM model to use |
| `SAIFE_ENABLE_TRACING` | `false` | Enable OTEL tracing |
| `SAIFE_MEMORY_DB` | `data/saife_memory.db` | SQLite database path |
| `SAIFE_CHROMA_DB` | `data/chroma_db` | ChromaDB vector store path |

---

*Built with: PydanticAI · FastMCP · ChromaDB · SQLite · Ollama (llama3.1) · Rich · Pydantic Evals*

---

## Troubleshooting

### ChromaDB Issues
If you encounter `chromadb` sqlite3 version errors (especially on macOS):
1. `pip install pysqlite3-binary`
2. Add `import pysqlite3; import sys; sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")` to the top of `main.py` OR upgrade your system Python.

### Ollama Connection Refused
Ensure Ollama is running and accessible:
```bash
ollama serve
curl http://localhost:11434/api/tags
```
If you're running SAIFE in Docker or WSL, you may need to set `OLLAMA_HOST=0.0.0.0` for Ollama.

### Claude Desktop MCP Connection Fails
If Claude Desktop fails to connect to the MCP server:
1. Verify paths in `claude_desktop_config.json` are absolute paths.
2. Check Claude Desktop logs at `~/Library/Logs/Claude/mcp*.log`.
3. Test the server via stdio manually: `python main.py mcp`.
