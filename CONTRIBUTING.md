# Contributing to SAIFE

Welcome to SAIFE (Secure AI Framework for Everyone)! We are excited to have you contribute to our production-grade AI security scanner.

## Architecture Overview

SAIFE is built using a Multi-Agent architecture driven by `PydanticAI` and an asynchronous Directed Acyclic Graph (DAG) orchestrator.

### Core Components:
1. **Scanner Agent**: Runs attack payloads (Prompt Injection, Jailbreak, etc.) and analyzes responses.
2. **Analysis Agent**: Classifies findings according to OWASP Top 10 for LLMs.
3. **Knowledge Agent (RAG)**: Retrieves security guidance from ChromaDB.
4. **Threat Intel Agent**: Correlates findings with CVEs, NVD, and MITRE ATT&CK.
5. **FastMCP Server**: Exposes tools, prompts, and resources to Claude Desktop and other MCP clients.
6. **Next.js Dashboard**: Visualizes scan results beautifully.

## Getting Started

1. **Clone & Setup**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run Ollama**:
   SAIFE requires Ollama running locally with `llama3.1`.
   ```bash
   ollama run llama3.1
   ```

3. **Run Tests (Evals)**:
   We use an Evaluation-Driven Development (EDD) approach. Start test targets and run the suite:
   ```bash
   uvicorn target.vulnerable_chatbot:app --port 9001 &
   python -m evals.scanner_evals
   ```

## Adding New Attacks

To add a new attack payload, update `data/attack_prompts.py`. The `Scanner Agent` will automatically pick it up during the next run.

## Adding a New Agent

1. Create a new file in `agent/`.
2. Define `Pydantic` models for structured output.
3. Define the `PydanticAI` Agent.
4. Integrate the agent into `engine/orchestrator.py` as a new node in the DAG.
5. Extract configuration numbers to `config.py`.

## Style Guide

- **Typing**: We enforce strict typing. Run `mypy .` before committing.
- **Config**: Do not hardcode magic numbers (timeouts, retries). Put them in `config.py`.
- **Docs**: Provide descriptive `docstrings` for all public functions.

Thank you for contributing!
