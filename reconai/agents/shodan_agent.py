from __future__ import annotations

import asyncio
import os
import socket
from typing import Any

import shodan

from reconai.agents.base import BaseAgent
from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity


class ShodanAgent(BaseAgent):
    name = "shodan_agent"
    description = "Shodan passive recon — historical ports, vulns, and banners"

    async def run(self, target: Target, result: ReconResult) -> None:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            result.add(Finding(
                agent=self.name,
                type=FindingType.OSINT,
                title="Shodan skipped — no API key (set SHODAN_API_KEY)",
                description="Set the SHODAN_API_KEY environment variable to enable Shodan recon.",
                severity=Severity.INFO,
                data={},
                mitre_techniques=["T1596.005"],
            ))
            return

        loop = asyncio.get_event_loop()

        ip: str = target.host
        if not target.is_ip:
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, target.host)
            except Exception as exc:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.ERROR,
                    title=f"Shodan — DNS resolution failed for {target.host}",
                    description=str(exc),
                    severity=Severity.INFO,
                    data={"host": target.host, "error": str(exc)},
                    mitre_techniques=["T1596.005"],
                ))
                return

        api = shodan.Shodan(api_key)

        try:
            host_data: dict[str, Any] = await loop.run_in_executor(None, api.host, ip)
        except shodan.APIError as exc:
            msg = str(exc)
            if "No information available" in msg:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.OSINT,
                    title=f"No Shodan data for {ip}",
                    description=msg,
                    severity=Severity.INFO,
                    data={"ip": ip},
                    mitre_techniques=["T1596.005"],
                ))
            else:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.ERROR,
                    title=f"Shodan API error for {ip}",
                    description=msg,
                    severity=Severity.INFO,
                    data={"ip": ip, "error": msg},
                    mitre_techniques=["T1596.005"],
                ))
            return
        except Exception as exc:
            result.add(Finding(
                agent=self.name,
                type=FindingType.ERROR,
                title=f"Shodan unexpected error for {ip}",
                description=str(exc),
                severity=Severity.INFO,
                data={"ip": ip, "error": str(exc)},
                mitre_techniques=["T1596.005"],
            ))
            return

        ports: list[int] = host_data.get("ports", [])
        hostnames: list[str] = host_data.get("hostnames", [])
        org: str = host_data.get("org", "")
        country: str = host_data.get("country_name", "")
        port_count = len(ports)

        result.add(Finding(
            agent=self.name,
            type=FindingType.OSINT,
            title=f"Shodan — {ip} ({port_count} ports)",
            description=f"Open ports found via Shodan for {ip}.",
            severity=Severity.INFO,
            data={
                "ip": ip,
                "ports": ports,
                "hostnames": hostnames,
                "org": org,
                "country": country,
            },
            mitre_techniques=["T1596.005"],
        ))

        if org:
            result.add(Finding(
                agent=self.name,
                type=FindingType.OSINT,
                title=f"Shodan org — {org}",
                description=f"Organization associated with {ip} according to Shodan.",
                severity=Severity.INFO,
                data={"ip": ip, "org": org, "country": country},
                mitre_techniques=["T1596.005"],
            ))

        host_vulns: dict[str, Any] = host_data.get("vulns", {})
        for cve in host_vulns:
            result.add(Finding(
                agent=self.name,
                type=FindingType.OSINT,
                title=f"Shodan vuln — {cve}",
                description=f"CVE {cve} reported by Shodan for {ip}.",
                severity=Severity.HIGH,
                data={"cve": cve, "ip": ip},
                mitre_techniques=["T1596.005"],
            ))

        for service in host_data.get("data", []):
            port: int = service.get("port", 0)

            service_vulns: dict[str, Any] = service.get("vulns", {})
            for cve in service_vulns:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.OSINT,
                    title=f"Shodan vuln — {cve}",
                    description=f"CVE {cve} reported by Shodan on port {port} of {ip}.",
                    severity=Severity.HIGH,
                    data={"cve": cve, "port": port, "ip": ip},
                    mitre_techniques=["T1596.005"],
                ))

            product: str = service.get("product", "")
            if product:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.TECH,
                    title=f"Shodan service — {port}/tcp — {product}",
                    description=f"Service banner product '{product}' detected on {ip}:{port} via Shodan.",
                    severity=Severity.INFO,
                    data={"ip": ip, "port": port, "product": product},
                    mitre_techniques=["T1596.005"],
                ))
