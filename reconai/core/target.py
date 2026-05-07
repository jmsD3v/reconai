"""
Target parsing and scope validation.

This is the ethical gate of ReconAI. Every scan must pass through here.
Targets outside known lab ranges require explicit --force-scope to proceed.

Authorized lab ranges (no flag needed):
  - HackTheBox VPN: 10.10.10.0/24, 10.10.11.0/24
  - TryHackMe VPN: 10.10.0.0/16, 10.8.0.0/16
  - All RFC1918 private networks (your own infra)
  - .htb, .thm, .local TLDs (lab DNS conventions)
  - localhost / 127.x.x.x

Everything else needs --force-scope + written authorization.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


LAB_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.10.10.0/24"),   # HackTheBox
    ipaddress.IPv4Network("10.10.11.0/24"),   # HackTheBox
    ipaddress.IPv4Network("10.10.0.0/16"),    # TryHackMe
    ipaddress.IPv4Network("10.8.0.0/16"),     # TryHackMe OpenVPN
    ipaddress.IPv4Network("192.168.0.0/16"),  # RFC1918
    ipaddress.IPv4Network("172.16.0.0/12"),   # RFC1918
    ipaddress.IPv4Network("10.0.0.0/8"),      # RFC1918
    ipaddress.IPv4Network("127.0.0.0/8"),     # Loopback
]

LAB_TLD_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(.+\.)?htb$"),
    re.compile(r"^(.+\.)?thm$"),
    re.compile(r"^(.+\.)?local$"),
    re.compile(r"^localhost$"),
]


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""
    pass


@dataclass
class Target:
    raw: str
    host: str = ""
    port: int | None = None
    is_ip: bool = False
    scope_confirmed: bool = False
    authorized_scope: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, raw: str) -> "Target":
        cleaned = raw.strip()

        # Strip protocol if present (https://target.com → target.com)
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.netloc or parsed.path

        # Strip port if present (target.com:8080 → target.com, port=8080)
        port: int | None = None
        if ":" in cleaned and not cleaned.startswith("["):
            parts = cleaned.rsplit(":", 1)
            if parts[1].isdigit():
                cleaned = parts[0]
                port = int(parts[1])

        t = cls(raw=raw, port=port)
        t.host = cleaned.lower().lstrip("www.") if cleaned.lower().startswith("www.") else cleaned.lower()

        try:
            ipaddress.ip_address(t.host)
            t.is_ip = True
        except ValueError:
            pass

        # Load any authorized scopes from environment
        env_scope = os.getenv("AUTHORIZED_SCOPE", "")
        if env_scope:
            t.authorized_scope = [s.strip() for s in env_scope.split(",") if s.strip()]

        return t

    def is_in_default_scope(self) -> bool:
        """Return True if this target is in a known authorized lab range."""
        if self.is_ip:
            try:
                addr = ipaddress.ip_address(self.host)
                return any(addr in net for net in LAB_NETWORKS)
            except ValueError:
                return False

        return any(p.match(self.host) for p in LAB_TLD_PATTERNS)

    def is_in_env_scope(self) -> bool:
        """Return True if this target matches AUTHORIZED_SCOPE from env."""
        for entry in self.authorized_scope:
            try:
                # CIDR check
                net = ipaddress.ip_network(entry, strict=False)
                if self.is_ip and ipaddress.ip_address(self.host) in net:
                    return True
            except ValueError:
                # Domain pattern check
                if self.host == entry or self.host.endswith(f".{entry}"):
                    return True
        return False

    def validate_scope(self, force: bool = False) -> None:
        """
        Raise ScopeError if the target is not in an authorized range.

        Args:
            force: If True, bypass the check (user confirmed authorization).
        """
        if self.is_in_default_scope() or self.is_in_env_scope():
            self.scope_confirmed = True
            return

        if force:
            self.scope_confirmed = True
            return

        raise ScopeError(
            f"\n[!] Target '{self.raw}' is not in a recognized lab range.\n\n"
            f"    Authorized by default: HTB (10.10.10-11.x), THM (10.10.x.x, 10.8.x.x),\n"
            f"    RFC1918 (192.168.x.x, 172.16.x.x, 10.x.x.x), .htb / .thm / .local\n\n"
            f"    If you have WRITTEN AUTHORIZATION to test '{self.raw}', re-run with:\n"
            f"      reconai scan {self.raw} --force-scope\n\n"
            f"    You can also add it to AUTHORIZED_SCOPE in your .env file.\n"
        )

    def __str__(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host
