"""
AI Analyzer — Claude integration.

Receives the aggregated ReconResult and generates:
  1. A narrative analysis of the attack surface
  2. Prioritized attack paths for further manual testing
  3. MITRE ATT&CK technique mapping per finding
"""

from __future__ import annotations

import json
import os

import anthropic

from reconai.types.findings import Finding, FindingType, ReconResult, Severity

_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set. Add it to your .env file."
            )
        _client = anthropic.AsyncAnthropic(api_key=api_key)
    return _client


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
        client = _get_client()

        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": _build_prompt(result)}],
        )
        result.ai_analysis = message.content[0].text

        # Extract attack paths (lines starting with numbered list)
        import re
        paths = re.findall(r"^\d+\.\s+(.+)$", result.ai_analysis, re.MULTILINE)
        result.ai_attack_paths = paths[:5]

    except RuntimeError as exc:
        result.ai_analysis = f"AI analysis skipped — {exc}"
    except anthropic.AuthenticationError:
        result.ai_analysis = "AI analysis skipped — invalid ANTHROPIC_API_KEY."
    except Exception as exc:
        result.ai_analysis = f"AI analysis failed: {exc}"
