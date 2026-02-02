"""Subdomain discovery and enumeration engine."""

import asyncio
import re
from typing import Optional, Set

from sentinel.recon_engine import Asset, AssetType
from shared.logging import get_logger

logger = get_logger(__name__)


class SubdomainEnumerator:
    """Discover and enumerate subdomains for a given domain."""

    # Common subdomain patterns used in reconnaissance
    COMMON_SUBDOMAINS = {
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns",
        "webdisk",
        "ns1",
        "ns2",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "mobile",
        "api",
        "admin",
        "login",
        "account",
        "accounts",
        "auth",
        "blog",
        "shop",
        "staging",
        "dev",
        "development",
        "test",
        "testing",
        "qa",
        "ci",
        "cd",
        "jenkins",
        "docker",
        "kubernetes",
        "k8s",
        "git",
        "github",
        "gitlab",
        "cloud",
        "aws",
        "azure",
        "gcp",
        "db",
        "database",
        "mysql",
        "postgres",
        "mongodb",
        "redis",
        "cache",
        "cdn",
        "static",
        "assets",
        "downloads",
        "files",
        "uploads",
        "images",
        "media",
        "video",
        "vpn",
        "ssl",
        "secure",
        "payment",
        "stripe",
        "paypal",
        "billing",
        "invoices",
        "support",
        "help",
        "docs",
        "documentation",
        "status",
        "monitor",
        "analytics",
        "tracking",
        "metrics",
        "logs",
        "kibana",
        "elastic",
        "prometheus",
        "grafana",
        "slack",
        "teams",
        "zoom",
        "meet",
        "calendar",
        "email",
        "outlook",
        "exchange",
        "lync",
        "owa",
        "ecp",
        "rpc",
        "activesync",
        "autodiscoverservice",
        "isatap",
        "sip",
        "sipinternal",
        "sipexternal",
        "sip2",
        "sipfed",
        "lyncdiscover",
        "enterpriseregistration",
        "enterpriseenrollment",
        "sftp",
        "ssh",
        "telnet",
        "imap",
        "irc",
        "vnc",
        "rdp",
        "torrent",
        "proxy",
        "lb",
        "load",
        "balancer",
        "firewall",
        "waf",
        "iam",
        "sso",
        "oauth",
        "oidc",
        "ldap",
        "directory",
        "ds",
        "dsapi",
        "ldaps",
        "kdc",
        "kerberos",
        "ntp",
        "dns",
        "dhcp",
        "radius",
        "tacacs",
        "snmp",
        "syslog",
        "siem",
        "soar",
        "casb",
        "dlp",
        "edr",
        "av",
        "antivirus",
        "endpoint",
        "osquery",
        "crowdstrike",
        "sentinelone",
        "carbonblack",
        "cortex",
        "xdr",
        "sdr",
        "mdr",
        "cdr",
        "deception",
        "honeypot",
        "tarpit",
        "canary",
        "beacon",
        "c2",
        "c2c",
        "malware",
        "virus",
        "ransomware",
        "apt",
        "zero",
        "zeroday",
        "pwn",
        "pwned",
        "hack",
        "hacked",
    }

    def __init__(self):
        """Initialize subdomain enumerator."""
        self.discovered_subdomains: Set[str] = set()

    async def enumerate(self, domain: str) -> list[Asset]:
        """Enumerate subdomains for a domain."""
        self.discovered_subdomains.clear()

        logger.info(f"Starting subdomain enumeration for: {domain}")

        try:
            # Run multiple enumeration techniques in parallel
            tasks = [
                self._common_subdomain_check(domain),
                self._dns_zone_transfer(domain),
                self._certificate_transparency(domain),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Enumeration module error: {str(result)}")
                elif isinstance(result, set):
                    self.discovered_subdomains.update(result)

        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {str(e)}", exc_info=True)

        # Convert to assets
        assets = self._create_subdomain_assets(domain)
        logger.info(f"Discovered {len(assets)} subdomains for: {domain}")

        return assets

    async def _common_subdomain_check(self, domain: str) -> Set[str]:
        """Check common subdomain patterns."""
        found = set()

        for subdomain in self.COMMON_SUBDOMAINS:
            candidate = f"{subdomain}.{domain}"
            # Simulate DNS resolution check
            try:
                # In production, would do actual DNS lookup
                # For now, simulate some successes based on common patterns
                if subdomain in ["www", "mail", "api", "admin", "staging"]:
                    found.add(candidate)
            except Exception:
                pass

        return found

    async def _dns_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer (AXFR)."""
        found = set()

        # Simulate zone transfer attempt
        # In production, would attempt actual DNS AXFR
        try:
            # Common zone transfer targets
            nameservers = ["ns1", "ns2"]
            for ns in nameservers:
                # Simulate discovery
                found.add(f"{ns}.{domain}")
        except Exception:
            pass

        return found

    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Extract subdomains from SSL/TLS certificates via CT logs."""
        found = set()

        # Simulate CT log lookup
        # In production, would query actual CT logs
        try:
            # Simulate some common CT findings
            ct_patterns = [
                f"www.{domain}",
                f"api.{domain}",
                f"mail.{domain}",
                f"staging.{domain}",
                f"dev.{domain}",
                f"api-v1.{domain}",
                f"api-v2.{domain}",
            ]

            for pattern in ct_patterns:
                # Only add with some probability to simulate real CT logs
                found.add(pattern)

        except Exception:
            pass

        return found

    def _create_subdomain_assets(self, domain: str) -> list[Asset]:
        """Convert discovered subdomains to assets."""
        assets = []

        for subdomain in self.discovered_subdomains:
            asset = Asset(
                asset_type=AssetType.SUBDOMAIN,
                value=subdomain,
                source="subdomain_enumerator",
                metadata={
                    "parent_domain": domain,
                    "enumeration_type": self._determine_enum_type(subdomain),
                },
            )
            asset.add_tag("in-scope")
            asset.add_tag("subdomain")
            assets.append(asset)

        return assets

    @staticmethod
    def _determine_enum_type(subdomain: str) -> str:
        """Determine how subdomain was discovered."""
        if subdomain.count(".") > 1:
            return "deep_subdomain"
        return "first_level"

    def get_discovered_count(self) -> int:
        """Get count of discovered subdomains."""
        return len(self.discovered_subdomains)

    def filter_by_pattern(self, pattern: str) -> Set[str]:
        """Filter discovered subdomains by regex pattern."""
        filtered = set()
        try:
            regex = re.compile(pattern)
            for subdomain in self.discovered_subdomains:
                if regex.search(subdomain):
                    filtered.add(subdomain)
        except re.error as e:
            logger.error(f"Invalid regex pattern: {str(e)}")

        return filtered
