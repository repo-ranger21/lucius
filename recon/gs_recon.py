"""
GS Acquisition Reconnaissance Module (gs_recon.py)

Performs passive and controlled active reconnaissance on nnip.com (authorized).

Compliance & Safety:
- LuciusClient wrapper for all HTTP traffic with X-HackerOne-Research header
- Rate limiting: 50 RPS max (token bucket)
- No pivoting: inventory-only, no exploitation
- Logs all findings to logs/nnip_inventory.json

Modules:
- Subdomain Discovery: crt.sh, Wayback Machine API
- Tech Fingerprinting: HTTP headers, robots.txt parsing
- ASN Mapping: Autonomous System identification
- Reporting: JSON inventory export
"""

import json
import logging
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from core.client import LuciusClient, SafetyException

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "gs_recon.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ============================================================================
# TECH STACK FINGERPRINTING DATABASE
# ============================================================================

TECH_STACK_SIGNATURES = {
    "Apache": {
        "headers": ["Server"],
        "patterns": [r"Apache/[\d.]+"],
        "robots_markers": [],
    },
    "Nginx": {
        "headers": ["Server"],
        "patterns": [r"nginx/[\d.]+"],
        "robots_markers": [],
    },
    "Node.js": {
        "headers": ["X-Powered-By"],
        "patterns": [r"(Express|Node\.js|koa|fastify)"],
        "robots_markers": [],
    },
    "Python": {
        "headers": ["X-Powered-By"],
        "patterns": [r"(Django|Flask|FastAPI|Pyramid)"],
        "robots_markers": [],
    },
    "PHP": {
        "headers": ["X-Powered-By"],
        "patterns": [r"PHP/[\d.]+"],
        "robots_markers": ["index.php"],
    },
    "Java": {
        "headers": ["X-Powered-By", "Server"],
        "patterns": [r"(Tomcat|JBoss|Jetty|WebLogic)"],
        "robots_markers": [],
    },
    "ASP.NET": {
        "headers": ["X-Powered-By", "Server", "X-AspNet-Version"],
        "patterns": [r"(ASP\.NET|IIS)"],
        "robots_markers": [],
    },
    "Go": {
        "headers": ["X-Powered-By"],
        "patterns": [r"(Go-http-server|Gin|Echo)"],
        "robots_markers": [],
    },
    "Ruby": {
        "headers": ["X-Powered-By"],
        "patterns": [r"(Ruby|Rails|Sinatra)"],
        "robots_markers": [],
    },
    "AWS": {
        "headers": ["Server"],
        "patterns": [r"(AmazonS3|awselb)"],
        "robots_markers": [],
    },
    "Cloudflare": {
        "headers": ["Server"],
        "patterns": [r"cloudflare"],
        "robots_markers": [],
    },
    "Content-Management": {
        "headers": [],
        "patterns": [],
        "robots_markers": [
            "wordpress",
            "joomla",
            "drupal",
            "sharepoint",
            "plone",
        ],
    },
}

# ASN Database (partial - for GS and major cloud providers)
ASN_DATABASE = {
    "14061": {"name": "Google", "owner": "GOOGLE", "scope": "out-of-scope"},
    "16509": {"name": "Amazon", "owner": "AMAZON-02", "scope": "out-of-scope"},
    "8994": {"name": "Microsoft", "owner": "MICROSOFT-CORP-MSN", "scope": "out-of-scope"},
    "2635": {
        "name": "Goldman Sachs",
        "owner": "GOLDMAN-SACHS",
        "scope": "in-scope",
    },
    "395087": {
        "name": "Fastly",
        "owner": "FASTLY",
        "scope": "potentially-out-of-scope",
    },
}


# ============================================================================
# CORE RECONNAISSANCE CLASSES
# ============================================================================


class TokenBucket:
    """Thread-safe token bucket for rate limiting."""

    def __init__(self, rate: int = 50, capacity: int = 50):
        """
        Initialize token bucket.

        Args:
            rate: Tokens per second
            capacity: Maximum tokens in bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1, timeout: float = 30.0) -> bool:
        """Acquire tokens, blocking if necessary."""
        start_time = time.time()
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.capacity,
                    self.tokens + elapsed * self.rate,
                )
                self.last_refill = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

            if time.time() - start_time > timeout:
                logger.warning(f"Token acquisition timeout after {timeout}s")
                return False

            time.sleep(0.01)


class SubdomainDiscovery:
    """Passive subdomain discovery from public sources."""

    def __init__(self, client: LuciusClient):
        """Initialize discovery with LuciusClient."""
        self.client = client
        self.discovered_domains: Set[str] = set()

    def query_crt_sh(self, domain: str) -> Set[str]:
        """Query certificate transparency logs via crt.sh."""
        logger.info(f"Querying crt.sh for domain: {domain}")
        subdomains = set()

        try:
            # crt.sh query - wildcard and exact domain
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.client.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            for entry in data:
                # Extract certificate names
                name_value = entry.get("name_value", "")
                for subdomain in name_value.split("\n"):
                    subdomain = subdomain.strip().lower()
                    if subdomain and domain in subdomain:
                        subdomains.add(subdomain)
                        logger.debug(f"  Found: {subdomain}")

            logger.info(f"crt.sh discovered {len(subdomains)} unique subdomains")
        except Exception as e:
            logger.error(f"crt.sh query failed: {e}")

        self.discovered_domains.update(subdomains)
        return subdomains

    def query_wayback_machine(self, domain: str) -> Set[str]:
        """Query Wayback Machine for historical subdomains."""
        logger.info(f"Querying Wayback Machine for domain: {domain}")
        subdomains = set()

        try:
            # Wayback Machine API for URLs
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&matchType=domain&output=json&collapse=urlkey&filter=statuscode:200"
            response = self.client.get(url, timeout=15)
            response.raise_for_status()

            data = response.json()
            # Skip header row
            if len(data) > 1:
                for row in data[1:]:
                    url_str = row[2] if len(row) > 2 else ""
                    if url_str:
                        parsed = urlparse(url_str)
                        subdomain = parsed.netloc.lower()
                        if subdomain and domain in subdomain:
                            subdomains.add(subdomain)
                            logger.debug(f"  Found: {subdomain}")

            logger.info(f"Wayback Machine discovered {len(subdomains)} unique subdomains")
        except Exception as e:
            logger.error(f"Wayback Machine query failed: {e}")

        self.discovered_domains.update(subdomains)
        return subdomains

    def query_dnsdumpster(self, domain: str) -> Set[str]:
        """Query DNS Dumpster for subdomains (passive)."""
        logger.info(f"Querying DNS Dumpster for domain: {domain}")
        subdomains = set()

        try:
            # DNS Dumpster API
            url = f"https://api.dnsdumpster.com/v1/dns?domain={domain}"
            response = self.client.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            # Extract subdomains from response
            if "subdomains" in data:
                for sub in data["subdomains"]:
                    subdomains.add(sub.lower())
                    logger.debug(f"  Found: {sub}")

            logger.info(f"DNS Dumpster discovered {len(subdomains)} unique subdomains")
        except Exception as e:
            logger.debug(f"DNS Dumpster query failed (may be rate limited): {e}")

        self.discovered_domains.update(subdomains)
        return subdomains

    def get_all_subdomains(self, domain: str) -> Set[str]:
        """Execute all discovery methods."""
        logger.info(f"Starting subdomain discovery for: {domain}")
        all_subdomains = set()

        # Execute discovery methods
        all_subdomains.update(self.query_crt_sh(domain))
        time.sleep(1)  # Courtesy delay between APIs

        all_subdomains.update(self.query_wayback_machine(domain))
        time.sleep(1)

        # DNS Dumpster may not work reliably, catch gracefully
        try:
            all_subdomains.update(self.query_dnsdumpster(domain))
        except Exception:
            pass

        logger.info(f"Total unique subdomains discovered: {len(all_subdomains)}")
        return all_subdomains


class TechFingerprinter:
    """Identify technology stack from HTTP responses."""

    def __init__(self, client: LuciusClient):
        """Initialize fingerprinter with LuciusClient."""
        self.client = client

    def get_tech_stack(self, url: str) -> Dict[str, Any]:
        """Detect technology stack for a given URL."""
        tech_stack = {
            "url": url,
            "live": False,
            "status_code": None,
            "headers": {},
            "detected_tech": [],
            "framework": None,
            "server": None,
            "robots_txt": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            # Add timeout and error handling
            response = self.client.get(url, timeout=10, allow_redirects=True)
            tech_stack["status_code"] = response.status_code
            tech_stack["live"] = 200 <= response.status_code < 400

            if not tech_stack["live"]:
                logger.debug(f"  [{url}] - Status: {response.status_code} (not in range)")
                return tech_stack

            # Collect headers
            important_headers = [
                "Server",
                "X-Powered-By",
                "X-AspNet-Version",
                "X-Runtime",
                "X-Rack-Cache",
                "X-Frame-Options",
                "Content-Security-Policy",
            ]
            for header in important_headers:
                if header in response.headers:
                    tech_stack["headers"][header] = response.headers[header]

            # Extract server info
            if "Server" in response.headers:
                tech_stack["server"] = response.headers["Server"]

            # Analyze headers and content for tech signatures
            tech_stack["detected_tech"] = self._analyze_signatures(response)

            # Try to fetch robots.txt
            tech_stack["robots_txt"] = self._fetch_robots_txt(url)

            logger.info(
                f"  [{url}] - Status: {response.status_code}, Tech: {tech_stack['detected_tech']}"
            )

        except requests.exceptions.Timeout:
            logger.debug(f"  [{url}] - Timeout")
        except requests.exceptions.ConnectionError:
            logger.debug(f"  [{url}] - Connection error")
        except SafetyException as e:
            logger.error(f"  [{url}] - Safety violation: {e}")
        except Exception as e:
            logger.debug(f"  [{url}] - Error: {e}")

        return tech_stack

    def _analyze_signatures(self, response: requests.Response) -> List[str]:
        """Analyze response for technology signatures."""
        detected = []

        for tech_name, signatures in TECH_STACK_SIGNATURES.items():
            found = False

            # Check headers
            for header in signatures["headers"]:
                if header in response.headers:
                    header_value = response.headers[header]
                    for pattern in signatures["patterns"]:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            detected.append(tech_name)
                            found = True
                            break
            if found:
                continue

            # Check content for markers
            try:
                content = response.text.lower()
                for marker in signatures["robots_markers"]:
                    if marker.lower() in content:
                        detected.append(tech_name)
                        break
            except Exception:
                pass

        return list(set(detected))  # Remove duplicates

    def _fetch_robots_txt(self, url: str) -> Optional[str]:
        """Fetch and parse robots.txt from URL."""
        try:
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            robots_url = urljoin(base_url, "/robots.txt")
            response = self.client.get(robots_url, timeout=5)

            if response.status_code == 200:
                # Return first 500 chars of robots.txt for analysis
                return response.text[:500]
        except Exception:
            pass

        return None


class ASNMapper:
    """Map domain to Autonomous System Number (ASN)."""

    def __init__(self, client: LuciusClient):
        """Initialize ASN mapper with LuciusClient."""
        self.client = client

    def resolve_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        import socket

        ips = []
        try:
            result = socket.getaddrinfo(domain, None)
            ips = list(set([item[4][0] for item in result]))
            logger.info(f"  Resolved {domain} to IPs: {ips}")
        except socket.gaierror as e:
            logger.debug(f"  Failed to resolve {domain}: {e}")

        return ips

    def get_asn_info(self, ip: str) -> Optional[Dict[str, str]]:
        """Query IP to ASN mapping."""
        try:
            # Using ASINFO API (free tier available)
            url = f"https://api.asinfo.io/ip/{ip}"
            response = self.client.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                asn = data.get("asn", "").replace("AS", "")

                if asn in ASN_DATABASE:
                    logger.info(f"  IP {ip} -> ASN {asn} ({ASN_DATABASE[asn]['name']})")
                    return {
                        "ip": ip,
                        "asn": asn,
                        "owner": ASN_DATABASE[asn]["owner"],
                        "scope": ASN_DATABASE[asn]["scope"],
                    }
                else:
                    logger.debug(f"  IP {ip} -> ASN {asn} (unknown)")
                    return {
                        "ip": ip,
                        "asn": asn,
                        "owner": "UNKNOWN",
                        "scope": "unknown",
                    }
        except Exception as e:
            logger.debug(f"  ASN lookup failed for {ip}: {e}")

        return None

    def map_domain_to_asn(self, domain: str) -> List[Dict[str, str]]:
        """Map domain to all ASNs."""
        logger.info(f"Mapping domain {domain} to ASN(s)")
        asn_info = []

        ips = self.resolve_ips(domain)
        for ip in ips:
            info = self.get_asn_info(ip)
            if info:
                asn_info.append(info)
                time.sleep(0.5)  # Rate limit between lookups

        return asn_info


class GSReconInventory:
    """Main reconnaissance orchestrator for GS targets."""

    def __init__(self, rate_limit: int = 50):
        """Initialize reconnaissance suite."""
        self.client = LuciusClient(rate_limit=rate_limit)
        self.subdomain_discovery = SubdomainDiscovery(self.client)
        self.tech_fingerprinter = TechFingerprinter(self.client)
        self.asn_mapper = ASNMapper(self.client)
        self.inventory: Dict[str, Any] = {
            "target": None,
            "discovery_timestamp": None,
            "subdomains": [],
            "live_hosts": [],
            "tech_stack": [],
            "asn_mapping": [],
            "summary": {},
        }

    def run_reconnaissance(
        self, target_domain: str, max_hosts: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute full reconnaissance workflow."""
        logger.info("=" * 70)
        logger.info(f"Starting GS Acquisition Reconnaissance on {target_domain}")
        logger.info("=" * 70)

        self.inventory["target"] = target_domain
        self.inventory["discovery_timestamp"] = datetime.utcnow().isoformat()

        # Phase 1: Subdomain Discovery
        logger.info("\n[PHASE 1] Subdomain Discovery")
        logger.info("-" * 70)
        subdomains = self.subdomain_discovery.get_all_subdomains(target_domain)
        self.inventory["subdomains"] = sorted(list(subdomains))

        # Phase 2: Tech Fingerprinting
        logger.info("\n[PHASE 2] Technology Fingerprinting")
        logger.info("-" * 70)
        hosts_to_scan = list(subdomains)
        if max_hosts:
            hosts_to_scan = hosts_to_scan[:max_hosts]

        logger.info(f"Scanning {len(hosts_to_scan)} hosts for tech stack...")
        tech_results = []
        for i, hostname in enumerate(hosts_to_scan, 1):
            logger.info(f"  [{i}/{len(hosts_to_scan)}] Fingerprinting {hostname}")

            for scheme in ["https", "http"]:
                url = f"{scheme}://{hostname}"
                result = self.tech_fingerprinter.get_tech_stack(url)

                if result["live"]:
                    tech_results.append(result)
                    break  # Got a live host, don't try http

            time.sleep(0.5)  # Courtesy delay between hosts

        self.inventory["live_hosts"] = [
            {
                "hostname": r["url"],
                "status": r["status_code"],
                "tech_stack": r["detected_tech"],
                "server": r["server"],
            }
            for r in tech_results
            if r["live"]
        ]
        self.inventory["tech_stack"] = tech_results

        # Phase 3: ASN Mapping
        logger.info("\n[PHASE 3] ASN Mapping")
        logger.info("-" * 70)
        asn_results = self.asn_mapper.map_domain_to_asn(target_domain)
        self.inventory["asn_mapping"] = asn_results

        # Generate summary
        self._generate_summary()

        logger.info("\n" + "=" * 70)
        logger.info("Reconnaissance Complete")
        logger.info("=" * 70)

        return self.inventory

    def _generate_summary(self) -> None:
        """Generate inventory summary."""
        live_count = len(self.inventory["live_hosts"])
        subdomain_count = len(self.inventory["subdomains"])

        # Aggregate tech stack
        tech_aggregation = {}
        for host in self.inventory["live_hosts"]:
            for tech in host["tech_stack"]:
                tech_aggregation[tech] = tech_aggregation.get(tech, 0) + 1

        # Check ASN scope
        in_scope_ips = [
            asn for asn in self.inventory["asn_mapping"] if asn.get("scope") == "in-scope"
        ]
        out_of_scope_ips = [
            asn for asn in self.inventory["asn_mapping"] if asn.get("scope") == "out-of-scope"
        ]

        self.inventory["summary"] = {
            "total_subdomains_discovered": subdomain_count,
            "live_hosts_found": live_count,
            "tech_stack_aggregation": tech_aggregation,
            "asn_in_scope_count": len(in_scope_ips),
            "asn_out_of_scope_count": len(out_of_scope_ips),
            "recommended_next_steps": [
                f"Investigate {live_count} live hosts for service enumeration",
                f"Cross-reference {subdomain_count} subdomains with org charts",
                f"Verify {len(in_scope_ips)} in-scope ASN(s) for legacy infrastructure",
            ],
        }

    def export_inventory(self, output_path: Optional[str] = None) -> str:
        """Export inventory to JSON file."""
        if output_path is None:
            output_path = str(
                LOG_DIR / f"nnip_inventory_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            )

        with open(output_path, "w") as f:
            json.dump(self.inventory, f, indent=2)

        logger.info(f"\nInventory exported to: {output_path}")
        return output_path

    def print_report(self) -> None:
        """Print human-readable reconnaissance report."""
        print("\n" + "=" * 70)
        print("GS ACQUISITION RECONNAISSANCE REPORT")
        print("=" * 70)

        print(f"\nTarget: {self.inventory['target']}")
        print(f"Discovery Time: {self.inventory['discovery_timestamp']}")

        print("\n[SUMMARY]")
        summary = self.inventory["summary"]
        print(f"  Total Subdomains Discovered: {summary['total_subdomains_discovered']}")
        print(f"  Live Hosts Found: {summary['live_hosts_found']}")
        print(f"  In-Scope ASNs: {summary['asn_in_scope_count']}")
        print(f"  Out-of-Scope ASNs: {summary['asn_out_of_scope_count']}")

        if self.inventory["live_hosts"]:
            print("\n[LIVE HOSTS]")
            for host in self.inventory["live_hosts"]:
                print(f"  • {host['hostname']} ({host['status']})")
                if host["tech_stack"]:
                    print(f"    Tech: {', '.join(host['tech_stack'])}")
                if host["server"]:
                    print(f"    Server: {host['server']}")

        if self.inventory["asn_mapping"]:
            print("\n[ASN MAPPING]")
            for asn in self.inventory["asn_mapping"]:
                scope_marker = "✓ IN-SCOPE" if asn["scope"] == "in-scope" else "✗ OUT"
                print(f"  • {asn['ip']} -> ASN{asn['asn']} ({asn['owner']}) [{scope_marker}]")

        print("\n[RECOMMENDED NEXT STEPS]")
        for step in summary["recommended_next_steps"]:
            print(f"  → {step}")

        print("\n" + "=" * 70)


# ============================================================================
# CLI INTERFACE
# ============================================================================


def main():
    """Command-line interface for reconnaissance."""
    import argparse

    parser = argparse.ArgumentParser(
        description="GS Acquisition Reconnaissance (Passive & Active)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gs_recon.py nnip.com
  python gs_recon.py nnip.com --max-hosts 20 --output custom_report.json
        """,
    )

    parser.add_argument(
        "domain",
        help="Target domain (must be authorized)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        help="Maximum hosts to fingerprint (default: all)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=50,
        help="Requests per second limit (default: 50, max: 50)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: auto-generated)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate rate limit
    if args.rate_limit > 50:
        logger.warning("Rate limit exceeds GS threshold (50 RPS). Capping at 50.")
        args.rate_limit = 50

    # Run reconnaissance
    try:
        recon = GSReconInventory(rate_limit=args.rate_limit)
        inventory = recon.run_reconnaissance(args.domain, max_hosts=args.max_hosts)

        # Export results
        output_file = recon.export_inventory(output_path=args.output)

        # Print report
        recon.print_report()

        print(f"\n✓ Reconnaissance completed successfully!")
        print(f"✓ Full inventory: {output_file}")

    except SafetyException as e:
        logger.error(f"Safety violation detected: {e}")
        return 1
    except Exception as e:
        logger.error(f"Reconnaissance failed: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
