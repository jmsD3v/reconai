"""
AI Analyzer — AI provider integration.

Receives the aggregated ReconResult and generates:
  1. A narrative analysis of the attack surface
  2. Prioritized attack paths for further manual testing
  3. MITRE ATT&CK technique mapping per finding

The actual provider (Anthropic Claude, Google Gemini, or OpenAI) is
auto-detected from environment variables — see reconai/core/ai_provider.py.
"""

from __future__ import annotations

from reconai.core.ai_provider import get_ai_completion
from reconai.types.findings import Finding, FindingType, ReconResult, Severity


def _build_prompt(result: ReconResult) -> str:
    high_sev = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    findings_summary = "\n".join(
        f"- [{f.severity.value.upper()}] {f.agent}: {f.title} — {f.description}"
        for f in result.sorted_findings()[:40]  # cap context
    )

    return f"""You are a senior penetration tester reviewing reconnaissance results for an authorized assessment.

Target: {result.target}
Total findings: {len(result.findings)}
Critical/High: {len(high_sev)}

FINDINGS:
{findings_summary}

Your task:
1. Write a concise executive summary of the attack surface (3-5 sentences).
2. List the top 3-5 attack paths worth investigating manually, ordered by likelihood of success.
3. For each attack path, reference the specific finding(s) that support it.
4. Note any findings that suggest misconfiguration or missing security controls.

Format your response as plain text. Be specific — reference actual hostnames, IPs, ports, or records from the findings. This is for a professional pentest report."""


async def analyze_with_ai(result: ReconResult) -> None:
    """Enrich result with AI narrative analysis. Modifies result in place."""
    try:
        result.ai_analysis = await get_ai_completion(_build_prompt(result), max_tokens=1024)

        # Extract attack paths (lines starting with numbered list)
        import re
        paths = re.findall(r"^\d+\.\s+(.+)$", result.ai_analysis, re.MULTILINE)
        result.ai_attack_paths = paths[:5]

    except RuntimeError as exc:
        result.ai_analysis = f"AI analysis skipped — {exc}"
    except Exception as exc:
        result.ai_analysis = f"AI analysis failed: {exc}"
