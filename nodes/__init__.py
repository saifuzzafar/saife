"""
SAIFE Non-AI Nodes
===================
Pure Python utility nodes — no LLM calls.

- http_caller.py      → Sends attack prompts to target via HTTP
- response_parser.py  → Analyzes target responses for vulnerability indicators
- scorer.py           → Calculates security score 0-100 with letter grades

These are used as PydanticAI tools by the scanner agent.
"""
