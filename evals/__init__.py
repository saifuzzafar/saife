"""
SAIFE Eval Suite
=================
pydantic-evals test suite for measuring scanner quality.

Approach: Compare SAIFE scanner vs a naive baseline across 3 test bots.
The scanner should:
- Find vulnerabilities in the vulnerable bot
- NOT find false positives in the secure bot
- Find SOME issues in the partial bot
"""
