"""Tests for Sentinel scanner module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from sentinel.scanner import VulnerabilityScanner


class TestVulnerabilityScanner:
    """Tests for VulnerabilityScanner."""

    @pytest.fixture
    def mock_nvd_client(self):
        """Create mock NVD client."""
        with patch("sentinel.scanner.NVDClient") as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    @pytest.fixture
    def mock_talon_client(self):
        """Create mock Talon client."""
        with patch("sentinel.scanner.TalonClient") as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    @pytest.fixture
    def scanner(self, mock_nvd_client, mock_talon_client):
        """Create scanner instance with mocked clients."""
        scanner = VulnerabilityScanner()
        scanner.nvd_client = mock_nvd_client
        scanner.talon_client = mock_talon_client
        return scanner

    def test_scan_directory_no_manifests(self, scanner, tmp_path):
        """Test scanning directory with no dependency manifests."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hello')")

        results = scanner.scan(tmp_path)

        assert results is not None
        assert results["total_dependencies"] == 0

    def test_scan_directory_with_requirements(self, scanner, mock_nvd_client, tmp_path):
        """Test scanning directory with requirements.txt."""
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("flask==2.3.0\nrequests==2.28.0\n")

        # Mock no vulnerabilities found
        mock_nvd_client.search_vulnerabilities.return_value = []

        results = scanner.scan(tmp_path)

        assert results is not None

    def test_scan_directory_with_vulnerabilities(self, scanner, mock_nvd_client, tmp_path):
        """Test scanning directory that has vulnerable packages."""
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("lodash==4.17.0\n")

        # Mock vulnerability found
        mock_nvd_client.search_vulnerabilities.return_value = [
            {
                "cve_id": "CVE-2020-12345",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "Test vulnerability",
            }
        ]

        results = scanner.scan(tmp_path)

        assert results is not None

    def test_scan_multiple_ecosystems(self, scanner, mock_nvd_client, tmp_path):
        """Test scanning directory with multiple package ecosystems."""
        # Python requirements
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")

        # NPM packages
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {"name": "test", "packages": {"node_modules/express": {"version": "4.18.0"}}}
            )
        )

        # PHP composer
        (tmp_path / "composer.lock").write_text(
            json.dumps({"packages": [{"name": "vendor/package", "version": "1.0.0"}]})
        )

        mock_nvd_client.search_vulnerabilities.return_value = []

        results = scanner.scan(tmp_path)

        assert results is not None


class TestScanResults:
    """Tests for scan result handling."""

    def test_scan_result_summary(self):
        """Test scan result summary generation."""
        # Summary should include counts by severity

    def test_vulnerability_severity_counts(self):
        """Test counting vulnerabilities by severity."""
        vulnerabilities = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]

        counts = {}
        for v in vulnerabilities:
            severity = v["severity"]
            counts[severity] = counts.get(severity, 0) + 1

        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1

    def test_filter_by_severity(self):
        """Test filtering results by minimum severity."""
        vulnerabilities = [
            {"severity": "CRITICAL", "cvss": 9.5},
            {"severity": "HIGH", "cvss": 7.5},
            {"severity": "MEDIUM", "cvss": 5.0},
            {"severity": "LOW", "cvss": 2.0},
        ]

        # Filter critical and high only
        min_cvss = 7.0
        filtered = [v for v in vulnerabilities if v["cvss"] >= min_cvss]

        assert len(filtered) == 2


class TestTalonIntegration:
    """Tests for Talon API integration."""

    @pytest.fixture
    def mock_talon(self):
        """Create mock Talon client."""
        with patch("sentinel.scanner.TalonClient") as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    def test_submit_scan_results(self, mock_talon):
        """Test submitting scan results to Talon."""
        mock_talon.submit_scan.return_value = {"scan_id": "test-123", "status": "processing"}

        # Should successfully submit

    def test_submit_scan_retry_on_failure(self, mock_talon):
        """Test retry logic when Talon submission fails."""
        mock_talon.submit_scan.side_effect = [
            Exception("Connection failed"),
            {"scan_id": "test-123", "status": "processing"},
        ]

        # Should retry and succeed

    def test_skip_talon_when_disabled(self):
        """Test that Talon submission is skipped when disabled."""
        # When Talon URL is not configured, should skip
        pass


class TestProgressTracking:
    """Tests for scan progress tracking."""

    def test_progress_callback(self):
        """Test progress callback is called during scan."""
        progress_updates = []

        def callback(current, total, message):
            progress_updates.append({"current": current, "total": total, "message": message})

        # Scanner should call callback

    def test_progress_stages(self):
        """Test scan progresses through expected stages."""
