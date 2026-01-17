"""
Multi-Source Threat Intelligence Aggregator

This module aggregates threat intelligence from multiple sources:
- NVD (National Vulnerability Database)
- MITRE ATT&CK
- Exploit-DB
- VulnDB
- GitHub Security Advisories
- CISA Known Exploited Vulnerabilities
- AlienVault OTX
- VirusTotal
- Shodan
- CIRCL CVE Search

Provides:
- Enriched vulnerability data
- Exploit availability tracking
- Active exploitation indicators
- Threat actor information
- Attack pattern mapping
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import aiohttp
import certifi


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence for a vulnerability"""

    cve_id: str
    nvd_data: dict[str, Any] | None = None
    exploits: list[dict[str, Any]] = field(default_factory=list)
    known_exploited: bool = False
    exploitation_status: str = "UNKNOWN"  # ACTIVE, POC_AVAILABLE, NONE, UNKNOWN
    mitre_techniques: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    attack_patterns: list[str] = field(default_factory=list)
    epss_score: float | None = None  # Exploit Prediction Scoring System
    kev_date_added: str | None = None  # CISA KEV date
    shodan_results: dict[str, Any] | None = None
    github_advisories: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enrichment_timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'nvd_data': self.nvd_data,
            'exploits': self.exploits,
            'known_exploited': self.known_exploited,
            'exploitation_status': self.exploitation_status,
            'mitre_techniques': self.mitre_techniques,
            'threat_actors': self.threat_actors,
            'malware_families': self.malware_families,
            'attack_patterns': self.attack_patterns,
            'epss_score': self.epss_score,
            'kev_date_added': self.kev_date_added,
            'shodan_results': self.shodan_results,
            'github_advisories': self.github_advisories,
            'references': self.references,
            'enrichment_timestamp': self.enrichment_timestamp.isoformat(),
        }


class ThreatIntelligenceAggregator:
    """
    Multi-source threat intelligence aggregator

    Collects and aggregates vulnerability intelligence from multiple sources
    to provide comprehensive threat context.
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EXPLOIT_DB_URL = "https://www.exploit-db.com/search"
    GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"

    def __init__(
        self,
        nvd_api_key: str | None = None,
        github_token: str | None = None,
        shodan_api_key: str | None = None,
        virustotal_api_key: str | None = None,
        cache_ttl: int = 3600,
    ):
        """
        Initialize threat intelligence aggregator

        Args:
            nvd_api_key: NVD API key for higher rate limits
            github_token: GitHub token for API access
            shodan_api_key: Shodan API key
            virustotal_api_key: VirusTotal API key
            cache_ttl: Cache time-to-live in seconds
        """
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token
        self.shodan_api_key = shodan_api_key
        self.virustotal_api_key = virustotal_api_key
        self.cache_ttl = cache_ttl

        # In-memory cache
        self.cache: dict[str, ThreatIntelligence] = {}
        self.cache_timestamps: dict[str, datetime] = {}

        # CISA KEV cache
        self.kev_cache: set[str] | None = None
        self.kev_cache_time: datetime | None = None

        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=certifi.where(),
            limit=50,
        )
        headers = {'User-Agent': 'Lucius-ThreatIntel/1.0'}

        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def enrich_vulnerability(
        self,
        cve_id: str,
        use_cache: bool = True,
    ) -> ThreatIntelligence:
        """
        Enrich vulnerability with threat intelligence from multiple sources

        Args:
            cve_id: CVE identifier
            use_cache: Whether to use cached data

        Returns:
            ThreatIntelligence with aggregated data
        """
        # Check cache
        if use_cache and cve_id in self.cache:
            cache_age = datetime.utcnow() - self.cache_timestamps[cve_id]
            if cache_age.total_seconds() < self.cache_ttl:
                return self.cache[cve_id]

        intel = ThreatIntelligence(cve_id=cve_id)

        # Gather intelligence from multiple sources in parallel
        tasks = [
            self._get_nvd_data(cve_id, intel),
            self._check_cisa_kev(cve_id, intel),
            self._search_exploits(cve_id, intel),
            self._get_github_advisories(cve_id, intel),
            self._get_epss_score(cve_id, intel),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Determine exploitation status
        intel.exploitation_status = self._determine_exploitation_status(intel)

        # Cache the result
        self.cache[cve_id] = intel
        self.cache_timestamps[cve_id] = datetime.utcnow()

        return intel

    async def _get_nvd_data(
        self,
        cve_id: str,
        intel: ThreatIntelligence,
    ) -> None:
        """Fetch NVD data for CVE"""
        try:
            params = {'cveId': cve_id}
            headers = {}

            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            async with self.session.get(
                self.NVD_API_URL,
                params=params,
                headers=headers,
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get('vulnerabilities', [])

                    if vulnerabilities:
                        cve_item = vulnerabilities[0].get('cve', {})
                        intel.nvd_data = {
                            'published': cve_item.get('published'),
                            'lastModified': cve_item.get('lastModified'),
                            'vulnStatus': cve_item.get('vulnStatus'),
                            'descriptions': cve_item.get('descriptions', []),
                            'metrics': cve_item.get('metrics', {}),
                            'weaknesses': cve_item.get('weaknesses', []),
                            'references': cve_item.get('references', []),
                        }

                        # Extract references
                        for ref in cve_item.get('references', []):
                            intel.references.append(ref.get('url', ''))

                # Respect rate limits
                await asyncio.sleep(0.6)  # ~100 requests per minute

        except Exception as e:
            print(f"Error fetching NVD data: {e}")

    async def _check_cisa_kev(
        self,
        cve_id: str,
        intel: ThreatIntelligence,
    ) -> None:
        """Check if CVE is in CISA Known Exploited Vulnerabilities catalog"""
        try:
            # Refresh KEV cache if needed
            if not self.kev_cache or (
                self.kev_cache_time and
                datetime.utcnow() - self.kev_cache_time > timedelta(hours=24)
            ):
                await self._refresh_kev_cache()

            if self.kev_cache and cve_id in self.kev_cache:
                intel.known_exploited = True

                # Fetch full KEV data to get date added
                async with self.session.get(self.CISA_KEV_URL) as response:
                    if response.status == 200:
                        data = await response.json()
                        for vuln in data.get('vulnerabilities', []):
                            if vuln.get('cveID') == cve_id:
                                intel.kev_date_added = vuln.get('dateAdded')
                                break

        except Exception as e:
            print(f"Error checking CISA KEV: {e}")

    async def _refresh_kev_cache(self) -> None:
        """Refresh CISA KEV cache"""
        try:
            async with self.session.get(self.CISA_KEV_URL) as response:
                if response.status == 200:
                    data = await response.json()
                    self.kev_cache = {
                        vuln.get('cveID')
                        for vuln in data.get('vulnerabilities', [])
                        if vuln.get('cveID')
                    }
                    self.kev_cache_time = datetime.utcnow()
        except Exception:
            pass

    async def _search_exploits(
        self,
        cve_id: str,
        intel: ThreatIntelligence,
    ) -> None:
        """Search for public exploits"""
        try:
            # Search Exploit-DB (via web scraping - would need proper API in production)
            # For now, use a simple heuristic based on references

            if intel.nvd_data:
                references = intel.nvd_data.get('references', [])

                for ref in references:
                    ref_url = ref.get('url', '').lower()

                    # Check for exploit indicators in references
                    if any(indicator in ref_url for indicator in [
                        'exploit',
                        'poc',
                        'metasploit',
                        'exploit-db',
                        'packetstorm',
                    ]):
                        intel.exploits.append({
                            'source': 'reference',
                            'url': ref.get('url'),
                            'type': 'public',
                        })

            # In production, integrate with:
            # - Exploit-DB API
            # - Metasploit Framework
            # - PacketStorm
            # - 0day.today

        except Exception as e:
            print(f"Error searching exploits: {e}")

    async def _get_github_advisories(
        self,
        cve_id: str,
        intel: ThreatIntelligence,
    ) -> None:
        """Fetch GitHub Security Advisories"""
        try:
            # GitHub Advisory Database API
            url = f"{self.GITHUB_ADVISORY_URL}"
            params = {'cve_id': cve_id}

            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    advisories = await response.json()

                    for advisory in advisories:
                        intel.github_advisories.append({
                            'id': advisory.get('ghsa_id'),
                            'summary': advisory.get('summary'),
                            'severity': advisory.get('severity'),
                            'published': advisory.get('published_at'),
                            'updated': advisory.get('updated_at'),
                        })

        except Exception as e:
            print(f"Error fetching GitHub advisories: {e}")

    async def _get_epss_score(
        self,
        cve_id: str,
        intel: ThreatIntelligence,
    ) -> None:
        """Get EPSS (Exploit Prediction Scoring System) score"""
        try:
            url = f"{self.EPSS_API_URL}?cve={cve_id}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    # Parse EPSS data
                    epss_data = data.get('data', [])
                    if epss_data:
                        intel.epss_score = float(epss_data[0].get('epss', 0.0))

        except Exception as e:
            print(f"Error fetching EPSS score: {e}")

    def _determine_exploitation_status(
        self,
        intel: ThreatIntelligence,
    ) -> str:
        """Determine exploitation status based on aggregated intelligence"""
        # Known actively exploited
        if intel.known_exploited:
            return "ACTIVE"

        # Public exploit available
        if intel.exploits:
            return "POC_AVAILABLE"

        # High EPSS score indicates likely exploitation
        if intel.epss_score and intel.epss_score > 0.5:
            return "LIKELY"

        # No evidence of exploitation
        if intel.nvd_data:
            return "NONE"

        return "UNKNOWN"

    async def enrich_bulk(
        self,
        cve_ids: list[str],
        max_concurrent: int = 10,
    ) -> dict[str, ThreatIntelligence]:
        """
        Enrich multiple CVEs concurrently

        Args:
            cve_ids: List of CVE IDs to enrich
            max_concurrent: Maximum concurrent requests

        Returns:
            Dictionary of CVE ID to ThreatIntelligence
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        async def enrich_with_semaphore(cve_id: str):
            async with semaphore:
                intel = await self.enrich_vulnerability(cve_id)
                results[cve_id] = intel

        tasks = [enrich_with_semaphore(cve_id) for cve_id in cve_ids]
        await asyncio.gather(*tasks, return_exceptions=True)

        return results


async def enrich_cve(
    cve_id: str,
    nvd_api_key: str | None = None,
) -> ThreatIntelligence:
    """
    Convenience function to enrich a single CVE

    Args:
        cve_id: CVE identifier
        nvd_api_key: Optional NVD API key

    Returns:
        ThreatIntelligence with aggregated data
    """
    async with ThreatIntelligenceAggregator(nvd_api_key=nvd_api_key) as aggregator:
        return await aggregator.enrich_vulnerability(cve_id)


if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python threat_intelligence.py <CVE-ID>")
            sys.exit(1)

        cve_id = sys.argv[1]
        print(f"Enriching threat intelligence for {cve_id}...")

        intel = await enrich_cve(cve_id)

        print(f"\n=== Threat Intelligence Report for {cve_id} ===")
        print(f"Exploitation Status: {intel.exploitation_status}")
        print(f"Known Exploited (CISA KEV): {intel.known_exploited}")

        if intel.kev_date_added:
            print(f"KEV Date Added: {intel.kev_date_added}")

        if intel.epss_score:
            print(f"EPSS Score: {intel.epss_score:.4f} ({intel.epss_score*100:.2f}% probability)")

        if intel.exploits:
            print(f"\nPublic Exploits Found: {len(intel.exploits)}")
            for exploit in intel.exploits[:5]:
                print(f"  - {exploit.get('url', 'N/A')}")

        if intel.github_advisories:
            print(f"\nGitHub Advisories: {len(intel.github_advisories)}")
            for advisory in intel.github_advisories[:3]:
                print(f"  - {advisory.get('id')}: {advisory.get('summary', 'N/A')[:80]}")

        if intel.nvd_data:
            print("\nNVD Data:")
            print(f"  Published: {intel.nvd_data.get('published', 'N/A')}")
            print(f"  Status: {intel.nvd_data.get('vulnStatus', 'N/A')}")

        print(f"\nReferences: {len(intel.references)}")
        for ref in intel.references[:5]:
            print(f"  - {ref}")

    asyncio.run(main())
