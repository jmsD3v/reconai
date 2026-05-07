from __future__ import annotations

import base64
from typing import Any

from reconai.agents.base import BaseAgent
from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity

_INTERESTING_KEYWORDS = {"admin", "login", "dashboard", "panel", "phpmyadmin", "jenkins", "grafana", "kibana"}
_ERROR_KEYWORDS = {"error", "403", "401", "unauthorized"}


class ScreenshotAgent(BaseAgent):
    name = "screenshot"
    description = "Headless browser screenshot of HTTP/HTTPS services"

    async def run(self, target: Target, result: ReconResult) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.add(Finding(
                agent=self.name,
                type=FindingType.ERROR,
                title="Playwright not installed",
                description="Install with: pip install playwright && playwright install chromium",
                severity=Severity.INFO,
                data={"install_cmd": "pip install playwright && playwright install chromium"},
                mitre_techniques=["T1593"],
            ))
            return

        host = target.host
        if target.port:
            urls_http = [f"http://{host}:{target.port}"]
            urls_https = [f"https://{host}:{target.port}"]
        else:
            urls_http = [f"http://{host}", f"http://{host}:8080"]
            urls_https = [f"https://{host}", f"https://{host}:8443"]

        http_done = False
        https_done = False
        any_success = False

        async with async_playwright() as p:
            for url in urls_http + urls_https:
                scheme = "https" if url.startswith("https") else "http"
                if scheme == "http" and http_done:
                    continue
                if scheme == "https" and https_done:
                    continue

                try:
                    browser = await p.chromium.launch(headless=True)
                    try:
                        page = await browser.new_page()
                        await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                        screenshot_bytes = await page.screenshot(full_page=False)
                        page_title = await page.title()
                    finally:
                        await browser.close()
                except Exception:
                    continue

                b64 = base64.b64encode(screenshot_bytes).decode()
                title_lower = page_title.lower()

                if any(kw in title_lower for kw in _INTERESTING_KEYWORDS):
                    severity = Severity.MEDIUM
                elif any(kw in title_lower for kw in _ERROR_KEYWORDS):
                    severity = Severity.LOW
                else:
                    severity = Severity.INFO

                result.add(Finding(
                    agent=self.name,
                    type=FindingType.SCREENSHOT,
                    title=f"Screenshot captured — {url}",
                    description=f"Web service responding at {url} with title: {page_title!r}",
                    severity=severity,
                    data={"url": url, "title": page_title, "screenshot_b64": b64},
                    mitre_techniques=["T1593"],
                ))

                any_success = True
                if scheme == "http":
                    http_done = True
                else:
                    https_done = True

        if not any_success:
            result.add(Finding(
                agent=self.name,
                type=FindingType.INFO,
                title=f"No web service found — {host}",
                description=f"All HTTP/HTTPS attempts to {host} timed out or failed",
                severity=Severity.INFO,
                data={"host": host},
                mitre_techniques=["T1593"],
            ))
