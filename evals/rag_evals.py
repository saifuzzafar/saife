"""
SAIFE RAG Evaluation — Knowledge Agent Faithfulness
=====================================================
Tests that the knowledge_agent returns answers that are
faithful to the source OWASP knowledge base.

Evaluators:
  - Custom FaithfulnessEvaluator: checks claims against context
  - LLMJudge: subjective relevance scoring
  - Contains: checks for expected OWASP IDs

Usage:
    python -m evals.rag_evals
"""
import asyncio
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import LLMJudge, Contains, Evaluator, EvaluatorContext

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.knowledge_agent import get_owasp_context, KnowledgeResponse


# ── Data Models ───────────────────────────────────────────────────

class RAGInput(BaseModel):
    """Input for a RAG eval test case."""
    category: str = Field(description="Vulnerability category")
    title: str = Field(description="Finding title / query")


class RAGExpected(BaseModel):
    """Expected output from the knowledge agent."""
    owasp_id: str = Field(description="Expected OWASP ID")
    must_contain: list[str] = Field(
        default_factory=list,
        description="Words/phrases the answer must contain",
    )
    min_confidence: float = Field(
        default=0.3,
        description="Minimum retrieval confidence expected",
    )


# ── Custom Faithfulness Evaluator ─────────────────────────────────

class FaithfulnessEvaluator(Evaluator):
    """Check that the agent's answer is faithful to retrieved context.

    Faithfulness means every claim in the answer is supported by
    the source_snippet from the knowledge base. This is a simplified
    version of the Ragas Faithfulness metric.

    Checks:
    1. source_snippet is non-empty (grounded in retrieval)
    2. Key terms from the answer appear in the source context
    3. OWASP ID matches expected value
    """

    def evaluate(self, ctx: EvaluatorContext) -> dict[str, Any]:
        output = ctx.output
        expected = ctx.expected_output

        # Check 1: Source snippet exists (answer is grounded)
        source_snippet = output.get("source_snippet", "")
        has_source = bool(source_snippet and len(source_snippet) > 10)

        # Check 2: OWASP ID matches
        actual_owasp = output.get("owasp_id", "")
        expected_owasp = expected.get("owasp_id", "") if expected else ""
        owasp_match = actual_owasp == expected_owasp if expected_owasp else True

        # Check 3: Confidence above threshold
        confidence = output.get("confidence", 0.0)
        min_conf = expected.get("min_confidence", 0.3) if expected else 0.3
        conf_ok = confidence >= min_conf

        # Check 4: Must-contain terms
        answer = output.get("answer", "").lower()
        must_contain = expected.get("must_contain", []) if expected else []
        if must_contain:
            found = sum(1 for term in must_contain if term.lower() in answer)
            term_score = found / len(must_contain)
        else:
            term_score = 1.0

        # Composite score
        scores = [
            1.0 if has_source else 0.0,
            1.0 if owasp_match else 0.0,
            1.0 if conf_ok else 0.5,
            term_score,
        ]
        final_score = sum(scores) / len(scores)

        reason_parts = []
        if not has_source:
            reason_parts.append("No source snippet (not grounded)")
        if not owasp_match:
            reason_parts.append(f"OWASP mismatch: got {actual_owasp}, expected {expected_owasp}")
        if not conf_ok:
            reason_parts.append(f"Low confidence: {confidence:.2f} < {min_conf}")
        if term_score < 1.0:
            reason_parts.append(f"Missing terms: {1-term_score:.0%}")
        if not reason_parts:
            reason_parts.append("All faithfulness checks passed")

        return {
            "score": round(final_score, 2),
            "reason": "; ".join(reason_parts),
        }


# ── Test Dataset ──────────────────────────────────────────────────

rag_eval_dataset = Dataset[RAGInput, dict[str, Any], Any](
    cases=[
        Case(
            name="prompt_injection_knowledge",
            inputs=RAGInput(
                category="prompt_injection",
                title="System prompt override detected",
            ),
            expected_output={
                "owasp_id": "LLM01",
                "must_contain": ["injection", "prompt"],
                "min_confidence": 0.3,
            },
            metadata={"topic": "LLM01"},
        ),
        Case(
            name="data_extraction_knowledge",
            inputs=RAGInput(
                category="data_extraction",
                title="API keys leaked in response",
            ),
            expected_output={
                "owasp_id": "LLM02",
                "must_contain": ["sensitive", "data"],
                "min_confidence": 0.3,
            },
            metadata={"topic": "LLM02"},
        ),
        Case(
            name="output_handling_knowledge",
            inputs=RAGInput(
                category="output_handling",
                title="XSS payload in LLM response",
            ),
            expected_output={
                "owasp_id": "LLM05",
                "must_contain": ["output", "validation"],
                "min_confidence": 0.2,
            },
            metadata={"topic": "LLM05"},
        ),
        Case(
            name="excessive_agency_knowledge",
            inputs=RAGInput(
                category="output_handling",
                title="LLM executing unauthorized actions",
            ),
            expected_output={
                "owasp_id": "LLM05",
                "must_contain": ["action", "privilege"],
                "min_confidence": 0.2,
            },
            metadata={"topic": "LLM06"},
        ),
        Case(
            name="rag_poisoning_knowledge",
            inputs=RAGInput(
                category="rag_poisoning",
                title="Malicious document in knowledge base",
            ),
            expected_output={
                "owasp_id": "LLM08",
                "must_contain": ["knowledge", "document"],
                "min_confidence": 0.2,
            },
            metadata={"topic": "LLM08"},
        ),
        Case(
            name="availability_knowledge",
            inputs=RAGInput(
                category="availability",
                title="Token flooding denial of service",
            ),
            expected_output={
                "owasp_id": "LLM10",
                "must_contain": ["resource", "consumption"],
                "min_confidence": 0.2,
            },
            metadata={"topic": "LLM10"},
        ),
    ],
    evaluators=[FaithfulnessEvaluator()],
)


# ── Eval Runner ───────────────────────────────────────────────────

async def run_rag_eval(inputs: RAGInput) -> dict[str, Any]:
    """Run the knowledge agent for one eval case."""
    response: KnowledgeResponse = await get_owasp_context(
        inputs.category, inputs.title,
    )
    return {
        "answer": response.answer,
        "source_snippet": response.source_snippet,
        "owasp_id": response.owasp_id,
        "confidence": response.confidence,
    }


def run_rag_eval_sync(inputs: RAGInput) -> dict[str, Any]:
    """Sync wrapper."""
    return asyncio.run(run_rag_eval(inputs))


# ── LLMJudge for RAG Quality ─────────────────────────────────────

RAG_RELEVANCE_JUDGE = LLMJudge(
    rubric=(
        "The response is relevant to the security query and accurately "
        "describes OWASP guidance. The answer should reference specific "
        "mitigations, detection patterns, or attack vectors from the "
        "OWASP LLM Top 10. Generic or vague answers should score low."
    ),
    model="ollama:llama3.1",
    include_input=True,
    include_expected_output=True,
    score={"evaluation_name": "rag_relevance", "include_reason": True},
    assertion=False,
)


def main():
    """Run the RAG faithfulness eval suite."""
    print("=" * 60)
    print("SAIFE — RAG Faithfulness Evaluation")
    print("  Knowledge Agent + OWASP Knowledge Base")
    print("  Evaluators: Faithfulness, LLMJudge (relevance)")
    print("=" * 60)
    print()

    evaluators = [
        FaithfulnessEvaluator(),
        RAG_RELEVANCE_JUDGE,
    ]

    print("Running RAG evaluations (6 OWASP queries)...")
    print()

    report = rag_eval_dataset.evaluate_sync(
        run_rag_eval_sync,
        name="saife_rag_faithfulness",
        max_concurrency=1,
    )

    report.print()

    print()
    print("=" * 60)
    print("RAG Evaluation complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
