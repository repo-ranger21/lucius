"""Tests for Sentinel NVD client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from sentinel.nvd_client import NVDClient


class TestNVDClient:
    """Tests for NVD API client."""

    @pytest.fixture
    def client(self):
        """Create NVD client instance."""
        return NVDClient()

    def test_init_with_api_key(self):
        """Test client initialization with API key."""
        with patch("sentinel.nvd_client.config.nvd.api_key", "test-key"):
            client = NVDClient()
            headers = client._get_headers()
            assert "apiKey" in headers
            assert headers["apiKey"] == "test-key"

    def test_init_without_api_key(self):
        """Test client initialization without API key."""
        with patch("sentinel.nvd_client.config.nvd.api_key", None):
            client = NVDClient()
            headers = client._get_headers()
            assert "apiKey" not in headers

    @patch("sentinel.nvd_client.requests.Session.get")
    def test_search_by_cpe(self, mock_get, client, sample_vulnerability):
        """Test searching vulnerabilities by CPE."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_vulnerability
        mock_get.return_value = mock_response

        results = client.search_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

        assert len(results) == 1
        assert results[0]["cve"]["id"] == "CVE-2023-12345"

    @patch("sentinel.nvd_client.requests.Session.get")
    def test_search_by_keyword(self, mock_get, client, sample_vulnerability):
        """Test searching vulnerabilities by keyword."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_vulnerability
        mock_get.return_value = mock_response

        results = client.search_by_keyword("lodash")

        assert len(results) == 1

    @patch("sentinel.nvd_client.requests.Session.get")
    def test_get_cve(self, mock_get, client, sample_vulnerability):
        """Test getting specific CVE."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_vulnerability
        mock_get.return_value = mock_response

        cve = client.get_cve("CVE-2023-12345")

        assert cve["id"] == "CVE-2023-12345"

    @patch("sentinel.nvd_client.requests.Session.get")
    def test_get_cve_not_found(self, mock_get, client):
        """Test getting non-existent CVE."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        cve = client.get_cve("CVE-0000-00000")

        assert cve is None

    @patch("sentinel.nvd_client.requests.Session.get")
    def test_rate_limiting(self, mock_get, client):
        """Test rate limiting behavior."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"Retry-After": "1"}
        mock_get.return_value = mock_response

        with pytest.raises(httpx.HTTPStatusError):
            client.search_by_keyword("test")

    def test_build_cpe(self, client):
        """Test CPE string building."""
        cpe = client.build_cpe(vendor="lodash", product="lodash", version="4.17.0")
        assert cpe.startswith("cpe:2.3:a:")
        assert "lodash" in cpe
        assert "4.17.0" in cpe

    def test_parse_severity(self, client, sample_vulnerability):
        """Test parsing CVSS severity."""
        vuln = sample_vulnerability["vulnerabilities"][0]["cve"]
        severity = client.parse_severity(vuln)

        assert severity["score"] == 7.5
        assert severity["severity"] == "HIGH"
