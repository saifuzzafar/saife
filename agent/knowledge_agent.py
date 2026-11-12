"""
Knowledge Agent — OWASP Security Expert (Agent #3)
====================================================
A PydanticAI agent that retrieves OWASP knowledge via RAG
and provides expert security recommendations grounded in
the OWASP LLM Top 10 knowledge base.

This is the RAG agent: it uses a tool to search the vector store
and returns structured output with source_snippet attribution.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from config import get_llm_model
from nodes.vector_store import get_store, RetrievedChunk


# ── Structured Output ────────────────────────────────────────────

class KnowledgeResponse(BaseModel):
    """Structured output from the knowledge agent."""
    answer: str = Field(
        default="No relevant OWASP guidance found.",
        description="Expert security recommendation based on retrieved context",
    )
    source_snippet: str = Field(
        default="",
        description="The most relevant text snippet from the knowledge base",
    )
    owasp_id: str = Field(
        default="—",
        description="The OWASP LLM Top 10 ID (e.g., LLM01, LLM02)",
    )
    confidence: float = Field(
        default=0.0,
        description="Confidence score 0.0-1.0 based on retrieval relevance",
    )


# ── Agent Definition ─────────────────────────────────────────────

knowledge_agent = Agent(
    model=get_llm_model(),
    output_type=KnowledgeResponse,
    retries=1,
    system_prompt="""You are an OWASP security expert specializing in LLM application security.

Your role:
1. Use the search_knowledge tool to retrieve relevant OWASP guidance
2. Based on the retrieved context, provide expert security recommendations
3. Always cite which OWASP LLM Top 10 category applies (LLM01-LLM10)
4. Return structured output with the answer, source snippet, OWASP ID, and confidence

Be concise and actionable. Focus on practical mitigations.
If the retrieved context doesn't match the query, say so honestly.

OWASP LLM Top 10 IDs:
- LLM01: Prompt Injection
- LLM02: Sensitive Information Disclosure
- LLM05: Improper Output Handling
- LLM06: Excessive Agency
- LLM07: System Prompt Leakage
- LLM08: Vector/Embedding Weaknesses (RAG Poisoning)
- LLM10: Unbounded Consumption / DoS
""",
)


# ── Tools ─────────────────────────────────────────────────────────

@knowledge_agent.tool
async def search_knowledge(ctx: RunContext, query: str) -> str:
    """Search the OWASP knowledge base for relevant security guidance.

    Args:
        query: The security topic or vulnerability to search for.

    Returns:
        Retrieved knowledge chunks with relevance scores.
    """
    store = get_store()
    # Ensure initialized
    store.initialize()

    chunks: list[RetrievedChunk] = store.search(query, n_results=3)

    if not chunks:
        return "No relevant knowledge found in the OWASP database."

    # Format results for the LLM
    results = []
    for i, chunk in enumerate(chunks, 1):
        results.append(
            f"--- Result {i} (score: {chunk.score}) ---\n"
            f"Source: {chunk.source}\n"
            f"{chunk.text}\n"
        )

    return "\n".join(results)


# ── Public API ────────────────────────────────────────────────────

async def get_owasp_context(finding_category: str, finding_title: str) -> KnowledgeResponse:
    """Query the knowledge agent for OWASP context about a finding.

    This is the main entry point called by the orchestrator.
    Uses the hybrid approach: tries LLM first, falls back to direct retrieval.
    If the LLM returns weak output (default values), falls back to deterministic search.
    """
    query = f"Security vulnerability: {finding_category}. Issue: {finding_title}. What OWASP guidance applies?"

    try:
        result = await knowledge_agent.run(query)
        output = result.output

        # Validate LLM output quality — if it returned defaults, use fallback
        is_weak = (
            output.owasp_id == "—"
            or output.confidence == 0.0
            or not output.source_snippet
            or output.answer == "No relevant OWASP guidance found."
        )

        if is_weak:
            # LLM returned poor output, use deterministic fallback
            fallback = _fallback_search(finding_category, finding_title)
            # Merge: keep any good LLM fields, fill gaps from fallback
            return KnowledgeResponse(
                answer=output.answer if output.answer != "No relevant OWASP guidance found." else fallback.answer,
                source_snippet=output.source_snippet or fallback.source_snippet,
                owasp_id=output.owasp_id if output.owasp_id != "—" else fallback.owasp_id,
                confidence=max(output.confidence, fallback.confidence),
            )

        return output

    except Exception:
        # Full fallback: direct vector search without LLM
        return _fallback_search(finding_category, finding_title)


def _fallback_search(category: str, title: str) -> KnowledgeResponse:
    """Direct vector search fallback when LLM is unavailable or returns weak results.

    Always returns a grounded response with source_snippet from the knowledge base.
    """
    store = get_store()
    store.initialize()

    # Search with multiple query variations for better coverage
    queries = [
        f"{category} {title}",
        f"{category} vulnerability mitigation",
        title,
    ]

    best_chunk = None
    best_score = 0.0

    for q in queries:
        chunks = store.search(q, n_results=1)
        if chunks and chunks[0].score > best_score:
            best_chunk = chunks[0]
            best_score = chunks[0].score

    # Infer OWASP ID from category
    owasp_map = {
        "prompt_injection": "LLM01",
        "jailbreak": "LLM01",
        "data_extraction": "LLM02",
        "output_handling": "LLM05",
        "rag_poisoning": "LLM08",
        "availability": "LLM10",
    }

    if best_chunk:
        return KnowledgeResponse(
            answer=f"OWASP guidance: {best_chunk.text[:300]}",
            source_snippet=best_chunk.text[:200],
            owasp_id=owasp_map.get(category, "—"),
            confidence=best_chunk.score,
        )

    return KnowledgeResponse(
        owasp_id=owasp_map.get(category, "—"),
    )
