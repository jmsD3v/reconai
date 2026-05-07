from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import whois

from reconai.agents.base import BaseAgent
from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity


def _format_date(d: Any) -> str | None:
    if d is None:
        return None
    if isinstance(d, list):
        d = d[0] if d else None
    if d is None:
        return None
    if isinstance(d, datetime):
        return d.isoformat()
    return str(d)


class WHOISAgent(BaseAgent):
    name = "whois_agent"
    description = "Domain registration, registrar, expiry, and abuse contact discovery"

    async def run(self, target: Target, result: ReconResult) -> None:
        loop = asyncio.get_running_loop()

        try:
            data = await loop.run_in_executor(None, whois.whois, target.host)
        except Exception as exc:
            result.add(Finding(
                agent=self.name,
                type=FindingType.ERROR,
                title=f"WHOIS error — {target.host}",
                description=str(exc),
                severity=Severity.INFO,
                data={"error": str(exc)},
                mitre_techniques=["T1590.001"],
            ))
            return

        if data is None or (not getattr(data, "domain_name", None) and not getattr(data, "org", None)):
            result.add(Finding(
                agent=self.name,
                type=FindingType.OSINT,
                title=f"No WHOIS data — {target.host}",
                description=f"WHOIS query returned no usable data for {target.host}.",
                severity=Severity.INFO,
                data={},
                mitre_techniques=["T1590.001"],
            ))
            return

        if target.is_ip:
            self._handle_ip(target, data, result)
        else:
            self._handle_domain(target, data, result)

    def _handle_ip(self, target: Target, data: Any, result: ReconResult) -> None:
        org = getattr(data, "org", None) or getattr(data, "nets", None)
        if isinstance(org, list):
            org = org[0] if org else None
        if isinstance(org, dict):
            org = org.get("name") or org.get("org")

        country = getattr(data, "country", None)
        if isinstance(country, list):
            country = country[0] if country else None

        cidr = getattr(data, "cidr", None)
        if isinstance(cidr, list):
            cidr = cidr[0] if cidr else None

        address = getattr(data, "address", None)
        if isinstance(address, list):
            address = address[0] if address else None

        result.add(Finding(
            agent=self.name,
            type=FindingType.OSINT,
            title=f"WHOIS — {target.host}",
            description=(
                f"IP WHOIS for {target.host}: "
                f"org={org or 'N/A'}, country={country or 'N/A'}, cidr={cidr or 'N/A'}"
            ),
            severity=Severity.INFO,
            data={
                "org": str(org) if org else None,
                "country": str(country) if country else None,
                "cidr": str(cidr) if cidr else None,
                "address": str(address) if address else None,
            },
            mitre_techniques=["T1590.001"],
        ))

    def _handle_domain(self, target: Target, data: Any, result: ReconResult) -> None:
        domain = target.host

        registrar = getattr(data, "registrar", None)
        creation_date = _format_date(getattr(data, "creation_date", None))
        expiration_date_raw = getattr(data, "expiration_date", None)
        expiration_date = _format_date(expiration_date_raw)
        updated_date = _format_date(getattr(data, "updated_date", None))

        name_servers = getattr(data, "name_servers", None)
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif isinstance(name_servers, (list, set)):
            name_servers = sorted({str(ns).lower() for ns in name_servers if ns})

        emails = getattr(data, "emails", None)
        if isinstance(emails, str):
            emails = [emails]
        elif isinstance(emails, (list, set)):
            emails = sorted({str(e).lower() for e in emails if e})

        org = getattr(data, "org", None)
        country = getattr(data, "country", None)
        if isinstance(country, list):
            country = country[0] if country else None

        result.add(Finding(
            agent=self.name,
            type=FindingType.OSINT,
            title=f"WHOIS — {domain}",
            description=(
                f"Registrar: {registrar or 'N/A'}. "
                f"Created: {creation_date or 'N/A'}. "
                f"Expires: {expiration_date or 'N/A'}."
            ),
            severity=Severity.INFO,
            data={
                "registrar": str(registrar) if registrar else None,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "updated_date": updated_date,
                "name_servers": name_servers,
                "emails": emails,
                "org": str(org) if org else None,
                "country": str(country) if country else None,
            },
            mitre_techniques=["T1590.001"],
        ))

        # Expiry check
        if expiration_date_raw is not None:
            exp_dt = expiration_date_raw
            if isinstance(exp_dt, list):
                exp_dt = exp_dt[0] if exp_dt else None
            if isinstance(exp_dt, datetime):
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                days_left = (exp_dt - now).days
                if days_left < 30:
                    result.add(Finding(
                        agent=self.name,
                        type=FindingType.OSINT,
                        title=f"Domain expires soon — {days_left} days",
                        description=(
                            f"{domain} expires in {days_left} days ({expiration_date}). "
                            "An attacker could register the domain after expiry."
                        ),
                        severity=Severity.HIGH,
                        data={"expiration_date": expiration_date, "days_left": days_left},
                        mitre_techniques=["T1590.001"],
                    ))
                elif days_left <= 90:
                    result.add(Finding(
                        agent=self.name,
                        type=FindingType.OSINT,
                        title=f"Domain expiring in {days_left} days",
                        description=(
                            f"{domain} expires in {days_left} days ({expiration_date})."
                        ),
                        severity=Severity.MEDIUM,
                        data={"expiration_date": expiration_date, "days_left": days_left},
                        mitre_techniques=["T1590.001"],
                    ))

        # Privacy / WHOIS guard check
        privacy_keywords = ("privacy", "whoisguard", "protect", "redacted")
        all_emails = emails or []
        registrant_email = " ".join(all_emails).lower()
        registrar_str = str(registrar).lower() if registrar else ""
        combined = registrant_email + " " + registrar_str
        if any(kw in combined for kw in privacy_keywords):
            result.add(Finding(
                agent=self.name,
                type=FindingType.OSINT,
                title=f"WHOIS privacy enabled — {domain}",
                description=(
                    f"WHOIS data for {domain} appears to use a privacy/guard service. "
                    "Registrant identity is redacted."
                ),
                severity=Severity.LOW,
                data={"emails": emails, "registrar": str(registrar) if registrar else None},
                mitre_techniques=["T1590.001"],
            ))
