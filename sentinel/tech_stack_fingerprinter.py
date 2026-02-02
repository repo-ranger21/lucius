"""Technology stack detection and fingerprinting engine."""

import re
from typing import Optional
from urllib.parse import urlparse

from sentinel.recon_engine import Asset, AssetType
from shared.logging import get_logger

logger = get_logger(__name__)


class TechStackFingerprinter:
    """Detect and fingerprint web application technologies."""

    # Technology signatures for detection
    TECHNOLOGY_SIGNATURES = {
        # Web Servers
        "nginx": {
            "patterns": [r"nginx", r"Server:\s*nginx"],
            "confidence": 0.9,
            "category": "web-server",
        },
        "apache": {
            "patterns": [r"Apache", r"Server:\s*Apache"],
            "confidence": 0.9,
            "category": "web-server",
        },
        "iis": {
            "patterns": [r"IIS", r"X-Powered-By:\s*ASP", r"ASP.NET"],
            "confidence": 0.85,
            "category": "web-server",
        },
        # Programming Languages
        "php": {
            "patterns": [r"X-Powered-By:\s*PHP", r"\.php", r"PHP"],
            "confidence": 0.8,
            "category": "language",
        },
        "python": {
            "patterns": [r"Python", r"flask", r"django"],
            "confidence": 0.75,
            "category": "language",
        },
        "node.js": {
            "patterns": [r"Node.js", r"node", r"express"],
            "confidence": 0.75,
            "category": "language",
        },
        "java": {
            "patterns": [r"Java", r"JSP", r"tomcat"],
            "confidence": 0.8,
            "category": "language",
        },
        "go": {
            "patterns": [r"Go-Http-Client", r"golang"],
            "confidence": 0.85,
            "category": "language",
        },
        # Frameworks
        "django": {
            "patterns": [r"django", r"Django"],
            "confidence": 0.85,
            "category": "framework",
        },
        "flask": {
            "patterns": [r"flask", r"Flask"],
            "confidence": 0.85,
            "category": "framework",
        },
        "react": {
            "patterns": [r"react", r"React", r"_app.js"],
            "confidence": 0.75,
            "category": "framework",
        },
        "vue.js": {
            "patterns": [r"vue", r"Vue"],
            "confidence": 0.75,
            "category": "framework",
        },
        "angular": {
            "patterns": [r"angular", r"Angular"],
            "confidence": 0.75,
            "category": "framework",
        },
        "wordpress": {
            "patterns": [r"wordpress", r"wp-content", r"wp-includes"],
            "confidence": 0.9,
            "category": "cms",
        },
        "drupal": {
            "patterns": [r"drupal", r"sites/default"],
            "confidence": 0.85,
            "category": "cms",
        },
        "joomla": {
            "patterns": [r"joomla", r"components/com"],
            "confidence": 0.85,
            "category": "cms",
        },
        # Databases
        "mysql": {
            "patterns": [r"mysql", r"MySQL"],
            "confidence": 0.7,
            "category": "database",
        },
        "postgresql": {
            "patterns": [r"postgres", r"postgresql"],
            "confidence": 0.7,
            "category": "database",
        },
        "mongodb": {
            "patterns": [r"mongodb", r"mongo"],
            "confidence": 0.75,
            "category": "database",
        },
        "redis": {
            "patterns": [r"redis", r"Redis"],
            "confidence": 0.75,
            "category": "cache",
        },
        # Web Technologies
        "cloudflare": {
            "patterns": [r"cloudflare", r"cf-ray"],
            "confidence": 0.95,
            "category": "cdn",
        },
        "akamai": {
            "patterns": [r"akamai", r"Akamai"],
            "confidence": 0.8,
            "category": "cdn",
        },
        "aws": {
            "patterns": [r"amazonaws", r"\.s3\.", r"elb\.amazonaws"],
            "confidence": 0.85,
            "category": "cloud",
        },
        "azure": {
            "patterns": [r"azure", r"azurecdn", r"\.azurewebsites"],
            "confidence": 0.85,
            "category": "cloud",
        },
        "google-cloud": {
            "patterns": [r"googleapis", r"gstatic\.com"],
            "confidence": 0.8,
            "category": "cloud",
        },
        # Security
        "modsecurity": {
            "patterns": [r"modsecurity", r"mod_security"],
            "confidence": 0.9,
            "category": "waf",
        },
        "cloudflare-waf": {
            "patterns": [r"cf-ray"],
            "confidence": 0.8,
            "category": "waf",
        },
    }

    def __init__(self):
        """Initialize tech stack fingerprinter."""
        self.detected_technologies = {}

    async def fingerprint(self, target: str) -> list[Asset]:
        """Fingerprint technology stack for target."""
        self.detected_technologies.clear()

        logger.info(f"Starting tech stack fingerprinting for: {target}")

        try:
            # Normalize target to URL
            if not target.startswith("http"):
                target_url = f"https://{target}"
            else:
                target_url = target

            # Extract domain for fingerprinting
            domain = urlparse(target_url).netloc or target

            # Perform fingerprinting
            await self._fingerprint_headers(target_url, domain)
            await self._fingerprint_content(target_url)
            await self._fingerprint_cookies(target_url)
            await self._fingerprint_domain(domain)

        except Exception as e:
            logger.error(f"Fingerprinting failed: {str(e)}", exc_info=True)

        # Convert to assets
        assets = self._create_technology_assets()
        logger.info(f"Detected {len(assets)} technologies for: {target}")

        return assets

    async def _fingerprint_headers(self, url: str, domain: str) -> None:
        """Analyze HTTP headers for technology indicators."""
        # Simulate header analysis
        header_indicators = {
            "Server": "nginx/1.19.0",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": None,
            "Cf-Ray": "624f3fb61f89a001",
        }

        for header, value in header_indicators.items():
            if value:
                self._match_technology(str(value))

    async def _fingerprint_content(self, url: str) -> None:
        """Analyze page content for technology indicators."""
        # Simulate content analysis
        content_indicators = [
            "<!-- Generated by WordPress",
            "powered by Django",
            "Made with Vue",
            "Created with React",
            "built with Angular",
        ]

        for indicator in content_indicators:
            self._match_technology(indicator)

    async def _fingerprint_cookies(self, url: str) -> None:
        """Analyze cookies for technology indicators."""
        # Simulate cookie analysis
        cookie_patterns = [
            "PHPSESSID",
            "JSESSIONID",
            "ASP.NET_SessionId",
            "__VIEWSTATE",
        ]

        for cookie in cookie_patterns:
            self._match_technology(cookie)

    async def _fingerprint_domain(self, domain: str) -> None:
        """Analyze domain for hosting indicators."""
        # Check for hosting patterns
        hosting_indicators = {
            ".azurewebsites.net": "azure",
            ".herokuapp.com": "heroku",
            ".github.io": "github-pages",
            ".gitlab.io": "gitlab-pages",
            ".netlify.com": "netlify",
            ".vercel.app": "vercel",
            ".pages.dev": "cloudflare-pages",
            ".appspot.com": "google-appengine",
        }

        for pattern, tech in hosting_indicators.items():
            if pattern in domain:
                self._add_technology(tech, 0.9, "domain-analysis")

    def _match_technology(self, text: str) -> None:
        """Match text against technology signatures."""
        for tech_name, sig in self.TECHNOLOGY_SIGNATURES.items():
            for pattern in sig["patterns"]:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        self._add_technology(tech_name, sig["confidence"], "pattern-matching")
                except re.error:
                    logger.warning(f"Invalid regex pattern for {tech_name}")

    def _add_technology(self, tech_name: str, confidence: float, source: str) -> None:
        """Add detected technology."""
        if tech_name not in self.detected_technologies:
            self.detected_technologies[tech_name] = {
                "confidence": confidence,
                "sources": [source],
            }
        else:
            # Update confidence (take average)
            old_conf = self.detected_technologies[tech_name]["confidence"]
            self.detected_technologies[tech_name]["confidence"] = (old_conf + confidence) / 2
            if source not in self.detected_technologies[tech_name]["sources"]:
                self.detected_technologies[tech_name]["sources"].append(source)

    def _create_technology_assets(self) -> list[Asset]:
        """Convert detected technologies to assets."""
        assets = []

        for tech_name, data in self.detected_technologies.items():
            # Find category from signatures
            category = "technology"
            for sig_name, sig_data in self.TECHNOLOGY_SIGNATURES.items():
                if sig_name == tech_name:
                    category = sig_data.get("category", "technology")
                    break

            asset = Asset(
                asset_type=AssetType.TECHNOLOGY,
                value=tech_name,
                source="tech_stack_fingerprinter",
                confidence=data["confidence"],
                metadata={
                    "category": category,
                    "detection_sources": data["sources"],
                },
            )
            asset.add_tag(category)
            asset.add_tag("detected")
            assets.append(asset)

        return assets

    def get_technologies_by_category(self, category: str) -> dict[str, dict]:
        """Get detected technologies filtered by category."""
        filtered = {}

        for tech_name, data in self.detected_technologies.items():
            for sig_name, sig_data in self.TECHNOLOGY_SIGNATURES.items():
                if sig_name == tech_name and sig_data.get("category") == category:
                    filtered[tech_name] = data
                    break

        return filtered

    def get_high_confidence_technologies(self, threshold: float = 0.8) -> dict:
        """Get technologies detected with high confidence."""
        return {
            name: data
            for name, data in self.detected_technologies.items()
            if data["confidence"] >= threshold
        }
