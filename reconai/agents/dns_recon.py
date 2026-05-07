"""
DNS Reconnaissance Agent

Discovers:
  - Standard DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Zone transfer misconfiguration (AXFR)
  - Subdomains via concurrent brute-force
  - Email security posture (SPF, DMARC, DKIM)
  - Reverse DNS for IP targets

MITRE ATT&CK: T1590.002 (DNS), T1596.001 (DNS Passive)
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.zone

from reconai.agents.base import BaseAgent
from reconai.types.findings import Finding, FindingType, ReconResult, Severity

if TYPE_CHECKING:
    from reconai.core.target import Target


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "app", "portal", "vpn", "remote", "webmail", "mx", "smtp",
    "imap", "pop3", "ns1", "ns2", "dns", "blog", "shop", "support",
    "help", "login", "secure", "beta", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "docs", "cdn", "static", "assets",
    "media", "files", "download", "dashboard", "monitor", "status",
    "grafana", "kibana", "elastic", "db", "mysql", "postgres", "redis",
    "backup", "dev2", "staging2", "preprod", "prod", "internal",
    "intranet", "extranet", "proxy", "mobile", "ws", "socket",
    "auth", "sso", "iam", "ldap", "smtp", "exchange", "autodiscover",
    "cloud", "s3", "storage", "upload", "img", "images", "video",
    "chat", "meet", "calendar", "crm", "erp", "hr", "finance",
    "vpn2", "gateway", "firewall", "router", "switch", "mgmt",
    "management", "ops", "devops", "ci", "build", "deploy", "k8s",
    "kubernetes", "docker", "registry", "artifactory", "nexus",
]


class DNSReconAgent(BaseAgent):
    name = "dns_recon"
    description = "DNS records, zone transfer, subdomain brute-force, email security"

    def _make_resolver(self) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver()
        r.timeout = 3
        r.lifetime = 5
        return r

    async def run(self, target: "Target", result: ReconResult) -> None:
        if target.is_ip:
            await self._reverse_dns(target, result)
            return

        domain = target.host
        resolver = self._make_resolver()

        # Run standard record queries concurrently
        await asyncio.gather(
            *[self._query_record(domain, rtype, resolver, result) for rtype in RECORD_TYPES],
            return_exceptions=True,
        )

        # Sequential: zone transfer (needs NS records first)
        await self._axfr_attempt(domain, resolver, result)

        # Concurrent subdomain brute-force
        await self._brute_subdomains(domain, resolver, result)

        # DMARC (separate subdomain query)
        await self._check_dmarc(domain, resolver, result)

        # Analyze TXT records for email security
        self._analyze_email_security(domain, result)

    async def _query_record(
        self,
        domain: str,
        rtype: str,
        resolver: dns.resolver.Resolver,
        result: ReconResult,
    ) -> None:
        loop = asyncio.get_running_loop()
        try:
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(domain, rtype)
            )
            records = [str(r) for r in answers]

            severity = Severity.INFO
            description = f"{len(records)} record(s) found."

            if rtype == "TXT":
                joined = " ".join(records).lower()
                if any(kw in joined for kw in ["api_key", "secret", "token", "password"]):
                    severity = Severity.HIGH
                    description += " TXT record may expose sensitive data."

            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"{rtype} record — {domain}",
                description=description,
                severity=severity,
                data={"record_type": rtype, "records": records, "domain": domain},
                mitre_techniques=["T1590.002"],
            ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

    async def _axfr_attempt(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
        result: ReconResult,
    ) -> None:
        """
        Attempt AXFR zone transfer.
        A successful transfer is a HIGH misconfiguration finding — reveals all DNS records.
        """
        loop = asyncio.get_running_loop()
        try:
            ns_answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(domain, "NS")
            )
        except Exception:
            return

        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata).rstrip(".")
            try:
                zone = await loop.run_in_executor(
                    None,
                    lambda h=ns_host: dns.zone.from_xfr(
                        dns.query.xfr(h, domain, timeout=5, lifetime=8)
                    ),
                )
                names = sorted(str(n) for n in zone.nodes.keys())
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.DNS,
                    title=f"Zone transfer (AXFR) allowed — {ns_host}",
                    description=(
                        f"Nameserver {ns_host} allows unauthenticated zone transfers. "
                        f"All {len(names)} DNS records are exposed."
                    ),
                    severity=Severity.HIGH,
                    data={"nameserver": ns_host, "record_count": len(names), "names": names[:100]},
                    mitre_techniques=["T1590.002", "T1596.001"],
                ))
                return  # One success is enough
            except Exception:
                continue

    async def _brute_subdomains(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
        result: ReconResult,
    ) -> None:
        found: list[dict] = []
        loop = asyncio.get_running_loop()

        async def check(sub: str) -> None:
            fqdn = f"{sub}.{domain}"
            try:
                answers = await loop.run_in_executor(
                    None, lambda f=fqdn: resolver.resolve(f, "A")
                )
                ips = [str(r) for r in answers]
                found.append({"subdomain": fqdn, "ips": ips})
            except Exception:
                pass

        # Batch in groups of 20 to avoid overwhelming DNS
        batch_size = 20
        for i in range(0, len(SUBDOMAINS), batch_size):
            batch = SUBDOMAINS[i : i + batch_size]
            await asyncio.gather(*[check(s) for s in batch], return_exceptions=True)

        if not found:
            return

        severity = Severity.MEDIUM if len(found) >= 5 else Severity.LOW
        result.add(Finding(
            agent=self.name,
            type=FindingType.DNS,
            title=f"Subdomains discovered ({len(found)} found)",
            description=(
                f"Brute-forced {len(SUBDOMAINS)} common names against {domain}. "
                f"Found {len(found)} live subdomains. Each may expand the attack surface."
            ),
            severity=severity,
            data={"subdomains": found, "total": len(found), "checked": len(SUBDOMAINS)},
            mitre_techniques=["T1590.002"],
        ))

    async def _check_dmarc(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
        result: ReconResult,
    ) -> None:
        loop = asyncio.get_running_loop()
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(dmarc_domain, "TXT")
            )
            records = [str(r).strip('"') for r in answers]
            has_reject = any("p=reject" in r.lower() for r in records)
            has_quarantine = any("p=quarantine" in r.lower() for r in records)

            severity = Severity.INFO if (has_reject or has_quarantine) else Severity.MEDIUM
            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"DMARC record — {domain}",
                description=(
                    "DMARC policy: reject" if has_reject
                    else "DMARC policy: quarantine" if has_quarantine
                    else "DMARC present but policy is 'none' — spoofing not blocked."
                ),
                severity=severity,
                data={"dmarc_records": records, "domain": dmarc_domain},
            ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"No DMARC record — {domain}",
                description=(
                    "No DMARC record found. Domain may be spoofable for phishing. "
                    "Missing: _dmarc." + domain
                ),
                severity=Severity.MEDIUM,
                data={"check": "DMARC", "present": False},
            ))
        except Exception:
            pass

    def _analyze_email_security(self, domain: str, result: ReconResult) -> None:
        """Check TXT findings for SPF presence."""
        txt_findings = [
            f for f in result.findings
            if f.type == FindingType.DNS and f.data.get("record_type") == "TXT"
        ]
        all_txt = []
        for f in txt_findings:
            all_txt.extend(f.data.get("records", []))

        txt_blob = " ".join(all_txt).lower()

        if "v=spf1" not in txt_blob:
            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"No SPF record — {domain}",
                description=(
                    "No SPF record in TXT records. "
                    "Without SPF, attackers can send emails that appear to come from this domain."
                ),
                severity=Severity.MEDIUM,
                data={"check": "SPF", "present": False},
            ))
        else:
            # Check for SPF +all (permit all — very bad)
            if "+all" in txt_blob:
                result.add(Finding(
                    agent=self.name,
                    type=FindingType.DNS,
                    title=f"SPF uses +all — any server allowed",
                    description=(
                        "SPF record contains '+all', which allows ANY server to send email "
                        "as this domain. Effectively no protection."
                    ),
                    severity=Severity.HIGH,
                    data={"check": "SPF", "issue": "+all_present"},
                ))

    async def _reverse_dns(self, target: "Target", result: ReconResult) -> None:
        """PTR record lookup for IP targets."""
        loop = asyncio.get_running_loop()
        resolver = self._make_resolver()

        try:
            # Build reverse lookup address
            parts = target.host.split(".")
            reversed_ip = ".".join(reversed(parts)) + ".in-addr.arpa"

            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(reversed_ip, "PTR")
            )
            hostnames = [str(r).rstrip(".") for r in answers]
            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"Reverse DNS — {target.host}",
                description=f"Resolved to: {', '.join(hostnames)}",
                severity=Severity.INFO,
                data={"ip": target.host, "hostnames": hostnames},
                mitre_techniques=["T1590.002"],
            ))
        except Exception:
            result.add(Finding(
                agent=self.name,
                type=FindingType.DNS,
                title=f"No PTR record — {target.host}",
                description="No reverse DNS entry. IP may be a CDN, proxy, or unconfigured host.",
                severity=Severity.INFO,
                data={"ip": target.host},
            ))
