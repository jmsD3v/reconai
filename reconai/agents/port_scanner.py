from __future__ import annotations

import asyncio
from typing import Any

import nmap

from reconai.agents.base import BaseAgent
from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity

_CRITICAL_PORTS: frozenset[int] = frozenset({21, 23, 512, 513, 514, 1099})
_HIGH_PORTS: frozenset[int] = frozenset({22, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017})
_MEDIUM_PORTS: frozenset[int] = frozenset({25, 80, 110, 143, 443, 8080, 8443, 8888})


def _classify_severity(port: int) -> Severity:
    if port in _CRITICAL_PORTS:
        return Severity.CRITICAL
    if port in _HIGH_PORTS:
        return Severity.HIGH
    if port in _MEDIUM_PORTS:
        return Severity.MEDIUM
    return Severity.LOW


def _run_nmap_scan(host: str) -> dict[str, Any]:
    scanner = nmap.PortScanner()
    scanner.scan(hosts=host, arguments="-sV -T4 --top-ports 1000")
    return scanner[host] if host in scanner.all_hosts() else {}


class PortScannerAgent(BaseAgent):
    name = "port_scanner"
    description = "TCP/UDP port scan with service fingerprinting"

    async def run(self, target: Target, result: ReconResult) -> None:
        host = target.host
        loop = asyncio.get_running_loop()

        try:
            scan_data = await loop.run_in_executor(None, _run_nmap_scan, host)
        except nmap.PortScannerError as exc:
            result.add(
                Finding(
                    agent=self.name,
                    type=FindingType.ERROR,
                    title="nmap not available or scan failed",
                    description=(
                        "nmap binary not found or scan returned an error. "
                        f"Ensure nmap is installed and in PATH. Detail: {exc}"
                    ),
                    severity=Severity.INFO,
                    data={"exception": type(exc).__name__, "detail": str(exc)},
                )
            )
            return
        except Exception as exc:
            result.add(
                Finding(
                    agent=self.name,
                    type=FindingType.ERROR,
                    title="Port scan error",
                    description=str(exc),
                    severity=Severity.INFO,
                    data={"exception": type(exc).__name__},
                )
            )
            return

        open_ports: list[dict[str, Any]] = []

        for proto in ("tcp", "udp"):
            proto_data: dict[int, Any] = scan_data.get(proto, {})
            for port, port_info in proto_data.items():
                if port_info.get("state") != "open":
                    continue

                service = port_info.get("name", "unknown")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                port_int = int(port)

                open_ports.append(
                    {
                        "port": port_int,
                        "protocol": proto,
                        "state": "open",
                        "service": service,
                        "product": product,
                        "version": version,
                    }
                )

                label_parts = [service]
                if product:
                    label_parts.append(product)
                if version:
                    label_parts.append(version)
                label = " ".join(label_parts)

                result.add(
                    Finding(
                        agent=self.name,
                        type=FindingType.PORT,
                        title=f"Open port {port_int}/{proto} — {label}",
                        description=(
                            f"Port {port_int}/{proto} is open on {host}. "
                            f"Service: {label}."
                        ),
                        severity=_classify_severity(port_int),
                        data={
                            "port": port_int,
                            "protocol": proto,
                            "state": "open",
                            "service": service,
                            "version": version,
                            "product": product,
                        },
                        mitre_techniques=["T1046"],
                    )
                )

        if not open_ports:
            result.add(
                Finding(
                    agent=self.name,
                    type=FindingType.PORT,
                    title="No open ports found (top 1000)",
                    description=f"nmap top-1000 TCP scan found no open ports on {host}.",
                    severity=Severity.INFO,
                    data={"host": host, "ports_scanned": "top-1000"},
                    mitre_techniques=["T1046"],
                )
            )
            return

        port_list = sorted(f"{p['port']}/{p['protocol']}" for p in open_ports)
        result.add(
            Finding(
                agent=self.name,
                type=FindingType.PORT,
                title=f"Port scan summary — {len(open_ports)} open port(s)",
                description=(
                    f"Found {len(open_ports)} open port(s) on {host}: "
                    f"{', '.join(port_list)}."
                ),
                severity=Severity.INFO,
                data={
                    "host": host,
                    "open_port_count": len(open_ports),
                    "open_ports": port_list,
                },
                mitre_techniques=["T1046"],
            )
        )
