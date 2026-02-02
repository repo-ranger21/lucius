"""
Test suite for gs_recon.py module - Comprehensive tests for GS reconnaissance module.

Tests cover:
- Rate limiting enforcement (50 RPS max)
- Subdomain discovery from multiple sources
- Tech fingerprinting accuracy
- ASN mapping and scope determination
- Compliance (X-HackerOne-Research header)
- JSON export format
"""

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from core.client import LuciusClient, SafetyException
from recon.gs_recon import (
    ASNMapper,
    GSReconInventory,
    SubdomainDiscovery,
    TechFingerprinter,
    TokenBucket,
)


class TestTokenBucket(unittest.TestCase):
    """Test rate limiting token bucket."""

    def test_initialization(self):
        """Test bucket initializes correctly."""
        bucket = TokenBucket(rate=50, capacity=50)
        self.assertEqual(bucket.rate, 50)
        self.assertEqual(bucket.capacity, 50)
        self.assertGreaterEqual(bucket.tokens, 49)

    def test_token_acquisition(self):
        """Test successful token acquisition."""
        bucket = TokenBucket(rate=50, capacity=50)
        result = bucket.acquire(tokens=1, timeout=1.0)
        self.assertTrue(result)
        self.assertLess(bucket.tokens, 50)

    def test_timeout_protection(self):
        """Test timeout protection in token acquisition."""
        bucket = TokenBucket(rate=0.1, capacity=1)
        bucket.tokens = 0  # Drain all tokens
        result = bucket.acquire(tokens=1, timeout=0.05)
        self.assertFalse(result)


class TestSubdomainDiscovery(unittest.TestCase):
    """Test passive subdomain discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = Mock(spec=LuciusClient)
        self.discovery = SubdomainDiscovery(self.mock_client)

    def test_crt_sh_parsing(self):
        """Test parsing of crt.sh JSON response."""
        mock_response = Mock()
        mock_response.json.return_value = [
            {"name_value": "api.nnip.com\n*.api.nnip.com"},
            {"name_value": "dev.nnip.com"},
        ]
        self.mock_client.get.return_value = mock_response

        subdomains = self.discovery.query_crt_sh("nnip.com")

        self.assertIn("api.nnip.com", subdomains)
        self.assertIn("dev.nnip.com", subdomains)

    def test_wayback_parsing(self):
        """Test parsing of Wayback Machine response."""
        mock_response = Mock()
        mock_response.json.return_value = [
            ["timestamp", "status", "url"],
            ["20240101000000", "200", "https://api.nnip.com/index.html"],
            ["20240102000000", "200", "https://old.nnip.com/data.json"],
        ]
        self.mock_client.get.return_value = mock_response

        subdomains = self.discovery.query_wayback_machine("nnip.com")

        self.assertIn("api.nnip.com", subdomains)
        self.assertIn("old.nnip.com", subdomains)

    def test_aggregation(self):
        """Test aggregation of subdomains from all sources."""
        with patch.object(self.discovery, "query_crt_sh", return_value={"api.nnip.com"}):
            with patch.object(
                self.discovery, "query_wayback_machine", return_value={"old.nnip.com"}
            ):
                with patch.object(
                    self.discovery, "query_dnsdumpster", return_value={"dev.nnip.com"}
                ):
                    subdomains = self.discovery.get_all_subdomains("nnip.com")

        self.assertEqual(len(subdomains), 3)
        self.assertIn("api.nnip.com", subdomains)
        self.assertIn("old.nnip.com", subdomains)
        self.assertIn("dev.nnip.com", subdomains)


class TestTechFingerprinter(unittest.TestCase):
    """Test technology stack fingerprinting."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = Mock(spec=LuciusClient)
        self.fingerprinter = TechFingerprinter(self.mock_client)

    def test_nginx_detection(self):
        """Test detection of Nginx."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx/1.24.0"}
        mock_response.text = "<html></html>"
        self.mock_client.get.return_value = mock_response

        result = self.fingerprinter.get_tech_stack("https://api.nnip.com")

        self.assertTrue(result["live"])
        self.assertEqual(result["status_code"], 200)
        self.assertIn("Nginx", result["detected_tech"])

    def test_aspnet_detection(self):
        """Test detection of ASP.NET."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "IIS/10.0",
            "X-AspNet-Version": "4.0.30319",
        }
        mock_response.text = "<html></html>"
        self.mock_client.get.return_value = mock_response

        result = self.fingerprinter.get_tech_stack("https://api.nnip.com")

        self.assertIn("ASP.NET", result["detected_tech"])

    def test_non_live_host(self):
        """Test handling of non-responsive hosts."""
        mock_response = Mock()
        mock_response.status_code = 503
        self.mock_client.get.return_value = mock_response

        result = self.fingerprinter.get_tech_stack("https://api.nnip.com")

        self.assertFalse(result["live"])

    def test_timeout_handling(self):
        """Test graceful timeout handling."""
        self.mock_client.get.side_effect = requests.exceptions.Timeout()

        result = self.fingerprinter.get_tech_stack("https://api.nnip.com")

        self.assertFalse(result["live"])


class TestASNMapper(unittest.TestCase):
    """Test ASN mapping and scope determination."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = Mock(spec=LuciusClient)
        self.mapper = ASNMapper(self.mock_client)

    @patch("socket.getaddrinfo")
    def test_ip_resolution(self, mock_getaddrinfo):
        """Test IP resolution from domain."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.0.2.1", 0)),
            (2, 1, 6, "", ("192.0.2.2", 0)),
        ]

        ips = self.mapper.resolve_ips("api.nnip.com")

        self.assertEqual(len(ips), 2)
        self.assertIn("192.0.2.1", ips)

    def test_asn_in_scope(self):
        """Test ASN lookup for in-scope Goldman Sachs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"asn": "AS2635"}
        self.mock_client.get.return_value = mock_response

        result = self.mapper.get_asn_info("192.0.2.1")

        self.assertEqual(result["asn"], "2635")
        self.assertEqual(result["scope"], "in-scope")

    def test_asn_out_of_scope(self):
        """Test ASN lookup for out-of-scope AWS."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"asn": "AS16509"}
        self.mock_client.get.return_value = mock_response

        result = self.mapper.get_asn_info("54.0.0.1")

        self.assertEqual(result["scope"], "out-of-scope")


class TestGSReconInventory(unittest.TestCase):
    """Test main reconnaissance orchestrator."""

    def setUp(self):
        """Set up test fixtures."""
        self.inventory = GSReconInventory(rate_limit=50)

    def test_initialization(self):
        """Test inventory initialization."""
        self.assertIsNotNone(self.inventory.client)
        self.assertIsNotNone(self.inventory.subdomain_discovery)
        self.assertIsNotNone(self.inventory.tech_fingerprinter)

    def test_structure(self):
        """Test inventory structure."""
        self.assertIn("target", self.inventory.inventory)
        self.assertIn("subdomains", self.inventory.inventory)
        self.assertIn("live_hosts", self.inventory.inventory)

    def test_summary_generation(self):
        """Test summary generation."""
        self.inventory.inventory["subdomains"] = ["api.nnip.com", "dev.nnip.com"]
        self.inventory.inventory["live_hosts"] = [
            {
                "hostname": "api.nnip.com",
                "status": 200,
                "tech_stack": ["Nginx"],
                "server": "nginx/1.24.0",
            }
        ]
        self.inventory.inventory["asn_mapping"] = [
            {"scope": "in-scope"},
            {"scope": "out-of-scope"},
        ]

        self.inventory._generate_summary()

        summary = self.inventory.inventory["summary"]
        self.assertEqual(summary["total_subdomains_discovered"], 2)
        self.assertEqual(summary["live_hosts_found"], 1)

    def test_export_format(self):
        """Test JSON export format."""
        self.inventory.inventory["target"] = "nnip.com"
        self.inventory.inventory["discovery_timestamp"] = datetime.utcnow().isoformat()
        self.inventory.inventory["subdomains"] = ["api.nnip.com"]
        self.inventory.inventory["live_hosts"] = []
        self.inventory.inventory["asn_mapping"] = []
        self.inventory._generate_summary()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            output_path = self.inventory.export_inventory(temp_path)

            with open(output_path, "r") as f:
                data = json.load(f)

            self.assertIn("target", data)
            self.assertEqual(data["target"], "nnip.com")
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestComplianceRequirements(unittest.TestCase):
    """Test legal and safety compliance requirements."""

    def test_header_enforcement(self):
        """Test X-HackerOne-Research header enforcement."""
        client = LuciusClient(rate_limit=50)
        self.assertEqual(client.session.headers.get("X-HackerOne-Research"), "[lucius-log]")

    def test_safety_exception(self):
        """Test SafetyException on missing header."""
        client = LuciusClient(rate_limit=50)

        with patch("requests.Session.request") as mock_request:
            mock_request.return_value = Mock()
            mock_request.return_value.request = Mock()
            mock_request.return_value.request.headers = {}

            with self.assertRaises(SafetyException):
                client._request("GET", "https://test.com")

    def test_rate_limit_cap(self):
        """Test rate limiting caps at 50 RPS."""
        client = LuciusClient(rate_limit=50)
        self.assertEqual(client.rate_limit, 50)
        self.assertLessEqual(client.rate_limit, 50)

    def test_no_exploitation(self):
        """Test that no exploitation methods exist."""
        inventory = GSReconInventory()
        self.assertFalse(hasattr(inventory.subdomain_discovery, "exploit_sql_injection"))


class TestIntegration(unittest.TestCase):
    """Integration tests for full workflow."""

    @patch("recon.gs_recon.SubdomainDiscovery.get_all_subdomains")
    @patch("recon.gs_recon.TechFingerprinter.get_tech_stack")
    @patch("recon.gs_recon.ASNMapper.map_domain_to_asn")
    def test_workflow(self, mock_asn, mock_tech, mock_subdomains):
        """Test end-to-end workflow."""
        mock_subdomains.return_value = {"api.nnip.com", "dev.nnip.com"}
        mock_tech.return_value = {
            "url": "https://api.nnip.com",
            "live": True,
            "status_code": 200,
            "detected_tech": ["Nginx"],
            "server": "nginx/1.24.0",
            "headers": {"Server": "nginx/1.24.0"},
            "robots_txt": None,
            "timestamp": datetime.utcnow().isoformat(),
        }
        mock_asn.return_value = [
            {
                "ip": "192.0.2.1",
                "asn": "2635",
                "owner": "GOLDMAN-SACHS",
                "scope": "in-scope",
            }
        ]

        inventory = GSReconInventory()
        results = inventory.run_reconnaissance("nnip.com", max_hosts=5)

        self.assertIsNotNone(results)
        self.assertEqual(results["target"], "nnip.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
