from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reconai.types.findings import ReconResult


def _is_configured() -> bool:
    return bool(os.getenv("SUPABASE_URL")) and bool(os.getenv("SUPABASE_ANON_KEY"))


async def persist_scan(result: ReconResult) -> str | None:
    """
    Write scan + findings to Supabase.
    Returns the scan UUID or None if Supabase is not configured.
    Silently skips on any error — persistence is best-effort.
    """
    if not _is_configured():
        return None

    try:
        from supabase import acreate_client

        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_ANON_KEY"]
        client = await acreate_client(url, key)

        scan_row = {
            "target": result.target,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "duration_seconds": result.duration_seconds,
            "ai_analysis": result.ai_analysis,
            "ai_attack_paths": result.ai_attack_paths,
            "error_count": result.error_count,
        }

        scan_resp = await client.table("scans").insert(scan_row).execute()
        scan_id: str = scan_resp.data[0]["id"]

        if result.findings:
            finding_rows = [
                {
                    "scan_id": scan_id,
                    "agent": f.agent,
                    "type": f.type.value if hasattr(f.type, "value") else str(f.type),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "data": _sanitize_data(f.data),
                    "mitre_techniques": f.mitre_techniques,
                    "raw": f.raw,
                    "found_at": f.timestamp.isoformat(),
                }
                for f in result.findings
            ]
            await client.table("findings").insert(finding_rows).execute()

        return scan_id

    except Exception:
        return None


def _sanitize_data(data: dict) -> dict:
    # Strip screenshot b64 — too large for DB
    if "screenshot_b64" in data:
        return {k: v for k, v in data.items() if k != "screenshot_b64"}
    return data
