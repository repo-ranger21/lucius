"""Sentinel configuration management."""

import json
import os
from dataclasses import dataclass, field


@dataclass
class NVDConfig:
    """NVD API configuration."""

    api_key: str | None = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit: float = 0.6  # seconds between requests (without API key)
    rate_limit_with_key: float = 0.1  # seconds between requests (with API key)
    timeout: int = 30
    max_retries: int = 3

    @property
    def effective_rate_limit(self) -> float:
        """Get the effective rate limit based on API key presence."""
        return self.rate_limit_with_key if self.api_key else self.rate_limit


@dataclass
class TalonConfig:
    """Talon API configuration."""

    api_url: str = field(
        default_factory=lambda: os.getenv("TALON_API_URL", "http://localhost:5000")
    )
    api_key: str | None = field(default_factory=lambda: os.getenv("TALON_API_KEY"))
    timeout: int = 30
    max_retries: int = 3


@dataclass
class CacheConfig:
    """Cache configuration."""

    enabled: bool = True
    directory: str = field(default_factory=lambda: os.getenv("CACHE_DIR", "/tmp/sentinel_cache"))
    ttl: int = 3600  # 1 hour


@dataclass
class ScanConfig:
    """Scan configuration."""

    max_concurrent_requests: int = 5
    max_rps: int = 50
    batch_size: int = 100
    include_dev_dependencies: bool = False
    severity_threshold: str = "low"  # low, medium, high, critical
    output_format: str = "json"  # json, cyclonedx, spdx


def _default_safe_url_allowlist() -> dict[str, list[str]]:
    return {
        "api.nnip.com": [],
        "docs.gs.com": [],
    }


def _load_safe_url_allowlist() -> dict[str, list[str]]:
    raw = os.getenv("SENTINEL_SAFE_URL_ALLOWLIST")
    if not raw:
        return _default_safe_url_allowlist()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _default_safe_url_allowlist()

    allowlist: dict[str, list[str]] = {}
    if isinstance(data, dict):
        for host, ips in data.items():
            if isinstance(host, str) and isinstance(ips, list):
                allowlist[host.lower()] = [str(ip) for ip in ips]
    return allowlist or _default_safe_url_allowlist()


@dataclass
class SSRFConfig:
    """SSRF defensive configuration."""

    safe_url_allowlist: dict[str, list[str]] = field(default_factory=_load_safe_url_allowlist)


@dataclass
class Config:
    """Main configuration container."""

    nvd: NVDConfig = field(default_factory=NVDConfig)
    talon: TalonConfig = field(default_factory=TalonConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    ssrf: SSRFConfig = field(default_factory=SSRFConfig)
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls()


# Global configuration instance
config = Config.from_env()
