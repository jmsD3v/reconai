from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from reconai.types.findings import ReconResult, Severity

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent
_TEMPLATE_NAME = "template.html"


def _build_context(result: ReconResult) -> dict:
    now = datetime.now(timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    if result.completed_at and result.started_at:
        secs = (result.completed_at - result.started_at).total_seconds()
        duration = f"{secs:.1f}s"
    else:
        duration = "N/A"

    findings_by_severity = {
        "critical": result.by_severity(Severity.CRITICAL),
        "high": result.by_severity(Severity.HIGH),
        "medium": result.by_severity(Severity.MEDIUM),
        "low": result.by_severity(Severity.LOW),
        "info": result.by_severity(Severity.INFO),
    }

    return {
        "result": result,
        "generated_at": generated_at,
        "findings_by_severity": findings_by_severity,
        "duration": duration,
    }


def _render_html(result: ReconResult) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
    )

    def tojson_filter(value, indent: int = 2) -> str:
        return json.dumps(value, indent=indent, default=str)

    env.filters["tojson"] = tojson_filter

    template = env.get_template(_TEMPLATE_NAME)
    context = _build_context(result)
    return template.render(**context)


def _write_pdf(html_content: str, output_path: Path) -> None:
    from weasyprint import HTML
    HTML(string=html_content).write_pdf(str(output_path))


async def generate_report(
    result: ReconResult,
    output_path: Path,
    fmt: str = "pdf",
) -> Path:
    html_content = _render_html(result)

    if fmt == "html":
        output_path = output_path.with_suffix(".html")
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report written to %s", output_path)
        return output_path

    pdf_path = output_path.with_suffix(".pdf")

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _write_pdf, html_content, pdf_path)
        logger.info("PDF report written to %s", pdf_path)
        return pdf_path
    except ImportError:
        logger.warning(
            "WeasyPrint is not installed — falling back to HTML output. "
            "Install it with: pip install weasyprint"
        )
        fallback_path = output_path.with_suffix(".html")
        fallback_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML fallback report written to %s", fallback_path)
        return fallback_path
