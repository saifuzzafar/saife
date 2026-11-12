"""
SAIFE Threat Intel Agent
========================
PydanticAI agent that correlates vulnerabilities with MITRE ATT&CK
techniques and threat actor profiles.

4th specialized agent in SAIFE — adds depth beyond the minimum 3-agent requirement.

Usage:
    from agent.threat_intel_agent import enrich_with_threat_intel
    report = await enrich_with_threat_intel(target_url, findings)
"""
import sys
from pathlib import Path
from pydantic import BaseModel, Field
from pydantic_ai import Agent

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import get_llm_model


# ── Structured Output ─────────────────────────────────────────────

class CorrelatedTechnique(BaseModel):
    """One MITRE ATT&CK technique correlated to the scan findings."""
    mitre_technique_id: str = Field(default="T1059", description="MITRE ATT&CK ID e.g. T1059")
    mitre_technique_name: str = Field(default="Command and Scripting Interpreter")
    description: str = Field(default="", description="How this technique applies to the finding")
    cve_examples: list[str] = Field(default_factory=list, description="Relevant CVE IDs if known")


class ThreatIntelReport(BaseModel):
    """Threat intelligence report enriching scanner findings."""
    target_url: str
    global_threat_summary: str = Field(
        default="",
        description="Overall risk assessment and attacker attractiveness of this target",
    )
    likely_threat_actors: list[str] = Field(
        default_factory=list,
        description="Threat actor profiles likely to exploit these vulnerabilities",
    )
    correlated_techniques: list[CorrelatedTechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques mapped to the findings",
    )


# ── The Threat Intel Agent ────────────────────────────────────────

threat_intel_agent = Agent(
    model=get_llm_model(),
    output_type=ThreatIntelReport,
    retries=1,
    instructions="""You are a senior Cyber Threat Intelligence analyst reviewing LLM security findings.

Given a list of vulnerabilities, produce a ThreatIntelReport with exactly these fields:

1. global_threat_summary: One paragraph assessing the overall risk and how attractive this target is to attackers.

2. likely_threat_actors: A list of 2-3 short strings naming likely attacker profiles, e.g.:
   ["Opportunistic Script Kiddies", "Automated Scanners", "Insider Threats"]

3. correlated_techniques: A list of MITRE ATT&CK techniques, one per distinct vulnerability category. Each entry needs:
   - mitre_technique_id: The ATT&CK technique ID (e.g. T1059, T1190, T1566)
   - mitre_technique_name: The technique name
   - description: One sentence on how it applies here
   - cve_examples: List of 1-2 real CVE IDs, or empty list if none apply

Keep it concise. Do not repeat the same technique ID twice.
""",
)


async def enrich_with_threat_intel(
    target_url: str,
    findings: list,
) -> ThreatIntelReport:
    """Enrich findings with MITRE ATT&CK threat intelligence.

    Args:
        target_url: The scanned target URL
        findings: List of AnalyzedFinding objects or dicts

    Returns:
        ThreatIntelReport with correlated techniques and actor profiles
    """
    if not findings:
        return ThreatIntelReport(
            target_url=target_url,
            global_threat_summary="No vulnerabilities detected. Target presents low value to attackers.",
            likely_threat_actors=["Automated scanners only"],
            correlated_techniques=[],
        )

    findings_text = "\n\n".join(
        f"Finding {i+1}:\n"
        f"  Title: {f.get('title', 'Unknown') if isinstance(f, dict) else getattr(f, 'title', 'Unknown')}\n"
        f"  Severity: {f.get('severity', 'unknown') if isinstance(f, dict) else getattr(f, 'severity', 'unknown')}\n"
        f"  OWASP ID: {f.get('owasp_id', 'Unknown') if isinstance(f, dict) else getattr(f, 'owasp_id', 'Unknown')}\n"
        f"  Summary: {f.get('explanation', '') if isinstance(f, dict) else getattr(f, 'explanation', '')}"
        for i, f in enumerate(findings[:8])  # cap at 8 to avoid context overflow
    )

    prompt = (
        f"Produce a ThreatIntelReport for vulnerabilities found at {target_url}:\n\n"
        f"{findings_text}"
    )

    result = await threat_intel_agent.run(prompt)
    return result.output
