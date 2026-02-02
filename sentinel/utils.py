"""
Sentinel utilities for defensive URL validation and SSRF prevention.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Dict, Iterable, List, Optional, Set

from sentinel.config import config

DEFAULT_ALLOWED_SCHEMES = {"https"}
DEFAULT_ALLOWED_PORTS = {443}
DEFAULT_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class SafeUrlError(ValueError):
    """Raised when URL validation fails."""


def canonicalize_and_validate_url(
    raw_url: str,
    *,
    allowed_hosts: Dict[str, List[str]],
    allowed_schemes: Optional[Set[str]] = None,
    allowed_ports: Optional[Set[int]] = None,
    blocked_nets: Optional[Iterable[ipaddress._BaseNetwork]] = None,
) -> str:
    """
    Canonicalize and validate a URL against allow-list and DNS pinning.

    Returns a normalized URL safe for outbound requests.
    """
    if not raw_url:
        raise SafeUrlError("empty_url")

    parsed = urllib.parse.urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if parsed.username or parsed.password:
        raise SafeUrlError("userinfo_not_allowed")

    schemes = allowed_schemes or DEFAULT_ALLOWED_SCHEMES
    ports = allowed_ports or DEFAULT_ALLOWED_PORTS
    nets = list(blocked_nets) if blocked_nets is not None else DEFAULT_BLOCKED_NETS

    if scheme not in schemes:
        raise SafeUrlError("scheme_not_allowed")

    if host not in allowed_hosts:
        raise SafeUrlError("host_not_allowed")

    port = parsed.port or (443 if scheme == "https" else None)
    if port not in ports:
        raise SafeUrlError("port_not_allowed")

    # Canonicalize path (remove dot segments and normalize slashes)
    normalized_path = urllib.parse.urljoin("/", parsed.path or "/")

    # DNS pinning + internal IP block
    resolved_ips = set()
    for _, _, _, _, sockaddr in socket.getaddrinfo(host, port):
        ip = ipaddress.ip_address(sockaddr[0])
        if any(ip in net for net in nets):
            raise SafeUrlError("blocked_internal_ip")
        resolved_ips.add(str(ip))

    allowed_ips = set(allowed_hosts[host])
    if not resolved_ips.issubset(allowed_ips):
        raise SafeUrlError("dns_pin_mismatch")

    # Rebuild safe URL without userinfo or fragments
    safe_url = urllib.parse.urlunsplit(
        (
            scheme,
            host if port == 443 else f"{host}:{port}",
            normalized_path,
            parsed.query,
            "",
        )
    )
    return safe_url


def validate_production_egress(url: str) -> str:
    """
    Enforce URI canonicalization and DNS pinning using configured allow-list.

    Returns the normalized URL if allowed.
    """
    return canonicalize_and_validate_url(
        url,
        allowed_hosts=config.ssrf.safe_url_allowlist,
    )
