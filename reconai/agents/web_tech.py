from __future__ import annotations

import re
from typing import Any

import httpx

from reconai.agents.base import BaseAgent
from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity

_MITRE = ["T1592.002"]
_UA = "Mozilla/5.0 (compatible; ReconAI/1.0)"
_TIMEOUT = 5.0

_WAF_HEADERS: dict[str, str | None] = {
    "CF-Ray": "Cloudflare",
    "X-Sucuri-ID": "Sucuri WAF",
    "X-CDN": "CDN detected",
    "Via": "Proxy/CDN layer",
}

_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Missing HSTS header", Severity.MEDIUM),
    ("X-Frame-Options", "Missing X-Frame-Options", Severity.LOW),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options", Severity.LOW),
    ("Content-Security-Policy", "Missing CSP header", Severity.MEDIUM),
]


class WebTechAgent(BaseAgent):
    name = "web_tech"
    description = "HTTP headers, server banner, tech stack fingerprinting"

    async def run(self, target: Target, result: ReconResult) -> None:
        host = target.host

        if target.port:
            scheme = "https" if target.port == 443 else "http"
            urls = [f"{scheme}://{host}:{target.port}"]
        else:
            urls = [f"http://{host}", f"https://{host}"]

        any_responded = False

        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:
            for url in urls:
                headers = await self._fetch_headers(client, url)
                if headers is None:
                    continue

                any_responded = True
                final_url: str = url

                # detect HTTP→HTTPS redirect
                if url.startswith("http://") and not url.startswith("https://"):
                    try:
                        resp = await client.head(url, follow_redirects=True)
                        final_url = str(resp.url)
                        if final_url.startswith("https://"):
                            result.add(Finding(
                                agent=self.name,
                                type=FindingType.TECH,
                                title=f"HTTP→HTTPS redirect — {host}",
                                description=f"HTTP requests to {url} redirect to HTTPS.",
                                severity=Severity.INFO,
                                data={"from": url, "to": final_url},
                                mitre_techniques=_MITRE,
                            ))
                    except Exception:
                        pass

                self._analyze_headers(host, url, headers, result)
                self._check_security_headers(host, headers, result)

        if not any_responded:
            result.add(Finding(
                agent=self.name,
                type=FindingType.TECH,
                title=f"Web server not responding — {host}",
                description=f"No HTTP/HTTPS response received from {host}.",
                severity=Severity.INFO,
                data={"host": host, "urls_tried": urls},
                mitre_techniques=_MITRE,
            ))

    async def _fetch_headers(
        self, client: httpx.AsyncClient, url: str
    ) -> dict[str, str] | None:
        for method in ("HEAD", "GET"):
            try:
                if method == "HEAD":
                    resp = await client.head(url, follow_redirects=True)
                else:
                    resp = await client.get(url, follow_redirects=True)
                return dict(resp.headers)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout):
                if method == "HEAD":
                    continue
                return None
            except Exception:
                return None
        return None

    def _analyze_headers(
        self,
        host: str,
        url: str,
        headers: dict[str, str],
        result: ReconResult,
    ) -> None:
        # server banner
        server = headers.get("server") or headers.get("Server")
        if server:
            has_version = bool(re.search(r"\d", server))
            result.add(Finding(
                agent=self.name,
                type=FindingType.TECH,
                title=f"Server banner — {server}",
                description=f"Server header exposes banner: {server!r}",
                severity=Severity.LOW if has_version else Severity.INFO,
                data={"header": "Server", "value": server, "url": url},
                mitre_techniques=_MITRE,
            ))

        # X-Powered-By
        powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")
        if powered_by:
            result.add(Finding(
                agent=self.name,
                type=FindingType.TECH,
                title=f"X-Powered-By — {powered_by}",
                description=f"X-Powered-By header leaks technology stack: {powered_by!r}",
                severity=Severity.LOW,
                data={"header": "X-Powered-By", "value": powered_by, "url": url},
                mitre_techniques=_MITRE,
            ))

        # X-Generator
        generator = headers.get("x-generator") or headers.get("X-Generator")
        if generator:
            result.add(Finding(
                agent=self.name,
                type=FindingType.TECH,
                title=f"Generator — {generator}",
                description=f"X-Generator header reveals CMS/framework: {generator!r}",
                severity=Severity.LOW,
                data={"header": "X-Generator", "value": generator, "url": url},
                mitre_techniques=_MITRE,
            ))

        # CMS headers (X-Drupal-*, X-WordPress-*)
        for hdr, val in headers.items():
            hdr_lower = hdr.lower()
            if hdr_lower.startswith("x-drupal-"):
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.TECH,
                    title=f"Drupal CMS detected — {hdr}",
                    description=f"Header {hdr!r} indicates Drupal CMS (value: {val!r})",
                    severity=Severity.MEDIUM,
                    data={"header": hdr, "value": val, "url": url},
                    mitre_techniques=_MITRE,
                ))
            elif hdr_lower.startswith("x-wordpress-"):
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.TECH,
                    title=f"WordPress CMS detected — {hdr}",
                    description=f"Header {hdr!r} indicates WordPress CMS (value: {val!r})",
                    severity=Severity.MEDIUM,
                    data={"header": hdr, "value": val, "url": url},
                    mitre_techniques=_MITRE,
                ))

        # ASP.NET version exposure
        aspnet = (
            headers.get("x-aspnet-version")
            or headers.get("X-AspNet-Version")
            or headers.get("x-aspnetmvc-version")
            or headers.get("X-AspNetMvc-Version")
        )
        if aspnet:
            result.add(Finding(
                agent=self.name,
                type=FindingType.TECH,
                title=f"ASP.NET version exposed — {aspnet}",
                description=f"ASP.NET version header leaks framework version: {aspnet!r}",
                severity=Severity.MEDIUM,
                data={"value": aspnet, "url": url},
                mitre_techniques=_MITRE,
            ))

        # WAF / CDN detection
        for waf_header, label in _WAF_HEADERS.items():
            val = headers.get(waf_header.lower()) or headers.get(waf_header)
            if val:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.WAF,
                    title=f"{label} detected — {host}",
                    description=f"Header {waf_header!r} present (value: {val!r})",
                    severity=Severity.MEDIUM,
                    data={"header": waf_header, "value": val, "url": url},
                    mitre_techniques=_MITRE,
                ))

        # X-Cache caching layer
        x_cache = headers.get("x-cache") or headers.get("X-Cache")
        if x_cache and ("HIT" in x_cache.upper() or "MISS" in x_cache.upper()):
            result.add(Finding(
                agent=self.name,
                type=FindingType.WAF,
                title=f"Caching layer detected — {host}",
                description=f"X-Cache header indicates a caching layer: {x_cache!r}",
                severity=Severity.MEDIUM,
                data={"header": "X-Cache", "value": x_cache, "url": url},
                mitre_techniques=_MITRE,
            ))

    def _check_security_headers(
        self,
        host: str,
        headers: dict[str, str],
        result: ReconResult,
    ) -> None:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header_name, title_prefix, severity in _SECURITY_HEADERS:
            if header_name.lower() not in headers_lower:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.TECH,
                    title=f"{title_prefix} — {host}",
                    description=f"Security header {header_name!r} is absent from the HTTP response.",
                    severity=severity,
                    data={"missing_header": header_name, "host": host},
                    mitre_techniques=_MITRE,
                ))
