"""
Comprehensive tests for BountyPipeline orchestrator.

Tests verify:
- Recon engine is called during pipeline execution
- API scanner discovers and tests endpoints
- Findings are processed and added to report
- Reports are exported in both HTML and JSON formats
- PII redaction is triggered for sensitive data
- Pipeline handles errors gracefully
"""

import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from sentinel.api_tester import (
    APIEndpoint,
    APITestResult,
    APIVulnerabilityScanner,
    HTTPMethod,
    ParameterType,
    VulnerabilityType,
)
from sentinel.bounty_pipeline import BountyPipeline, CVSSScorer, PipelineResult
from sentinel.cvss_scorer import (
    AttackComplexity,
    AttackVector,
    Availability,
    Confidentiality,
    CVSSScore,
    CVSSv31Scorer,
    CVSSVersion,
    Integrity,
    PrivilegesRequired,
    Scope,
    UserInteraction,
)
from sentinel.evidence_manager import (
    EncryptionStatus,
    Evidence,
    EvidenceMetadata,
    EvidenceStorage,
    EvidenceType,
    PIIType,
)
from sentinel.recon_engine import Asset, AssetType, ReconEngine, ReconScan, ReconTarget, ScanStatus
from sentinel.report_generator import (
    BugBountyReport,
    ReportFinding,
    ReportFormat,
    ReportGenerator,
    ReportSeverity,
)


class TestCVSSScorer:
    """Test CVSS Scorer adapter."""

    def test_calculate_sql_injection_score(self):
        """Test CVSS score calculation for SQL injection."""
        scorer = CVSSScorer()

        # Create a mock finding
        finding = Mock(spec=APITestResult)
        finding.vulnerability_type = VulnerabilityType.SQL_INJECTION
        finding.endpoint = Mock()
        finding.endpoint.url = "https://example.com/api/users"
        finding.parameter_tested = "id"
        finding.evidence = "SQL syntax error detected"

        score = scorer.calculate_score(finding)

        assert score is not None
        assert isinstance(score, CVSSScore)
        assert 0.0 <= score.score <= 10.0
        assert score.score > 7.0  # SQL injection should be HIGH severity

    def test_calculate_xss_score(self):
        """Test CVSS score calculation for XSS."""
        scorer = CVSSScorer()

        finding = Mock(spec=APITestResult)
        finding.vulnerability_type = VulnerabilityType.XSS
        finding.endpoint = Mock()
        finding.endpoint.url = "https://example.com/search"

        score = scorer.calculate_score(finding)

        assert score is not None
        assert isinstance(score, CVSSScore)
        assert 0.0 <= score.score <= 10.0
        # XSS can range from LOW to CRITICAL depending on context
        assert score.score >= 4.0  # At minimum, a moderate issue

    def test_calculate_command_injection_score(self):
        """Test CVSS score calculation for command injection."""
        scorer = CVSSScorer()

        finding = Mock(spec=APITestResult)
        finding.vulnerability_type = VulnerabilityType.COMMAND_INJECTION
        finding.endpoint = Mock()
        finding.endpoint.url = "https://example.com/api/exec"

        score = scorer.calculate_score(finding)

        assert score is not None
        assert isinstance(score, CVSSScore)
        assert score.score > 8.0  # Command injection should be CRITICAL

    def test_calculate_unknown_vulnerability_type(self):
        """Test CVSS scoring with unknown vulnerability type."""
        scorer = CVSSScorer()

        finding = Mock(spec=APITestResult)
        finding.vulnerability_type = Mock()
        finding.vulnerability_type.value = "unknown_vulnerability"
        finding.endpoint = Mock()
        finding.endpoint.url = "https://example.com/api/test"

        # Should not raise exception, use safe defaults
        score = scorer.calculate_score(finding)

        assert score is not None
        assert isinstance(score, CVSSScore)
        assert 0.0 <= score.score <= 10.0


class TestPipelineInitialization:
    """Test BountyPipeline initialization."""

    def test_pipeline_init_creates_workspace(self):
        """Test that pipeline initialization creates workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir) / "test_workspace"
            pipeline = BountyPipeline(workspace_dir=str(workspace))

            assert workspace.exists()
            assert pipeline.workspace == workspace

    def test_pipeline_init_initializes_components(self):
        """Test that all pipeline components are initialized."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            assert pipeline.recon_engine is not None
            assert isinstance(pipeline.recon_engine, ReconEngine)
            assert pipeline.api_scanner is not None
            assert isinstance(pipeline.api_scanner, APIVulnerabilityScanner)
            assert pipeline.evidence_storage is not None
            assert isinstance(pipeline.evidence_storage, EvidenceStorage)
            assert pipeline.report_gen is not None
            assert isinstance(pipeline.report_gen, ReportGenerator)
            assert pipeline.cvss_scorer is not None
            assert isinstance(pipeline.cvss_scorer, CVSSScorer)

    def test_pipeline_init_custom_created_by(self):
        """Test pipeline initialization with custom created_by."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir, created_by="test_user")

            assert pipeline.created_by == "test_user"

    def test_pipeline_init_default_created_by(self):
        """Test pipeline initialization with default created_by."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            assert pipeline.created_by == "lucius_bot"


class TestMapSeverity:
    """Test severity mapping helper."""

    def test_map_critical_severity(self):
        """Test mapping CRITICAL severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("CRITICAL")

            assert severity == ReportSeverity.CRITICAL

    def test_map_high_severity(self):
        """Test mapping HIGH severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("HIGH")

            assert severity == ReportSeverity.HIGH

    def test_map_medium_severity(self):
        """Test mapping MEDIUM severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("MEDIUM")

            assert severity == ReportSeverity.MEDIUM

    def test_map_low_severity(self):
        """Test mapping LOW severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("LOW")

            assert severity == ReportSeverity.LOW

    def test_map_none_severity(self):
        """Test mapping NONE severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("NONE")

            assert severity == ReportSeverity.INFO

    def test_map_unknown_severity_defaults_to_info(self):
        """Test mapping unknown severity defaults to INFO."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)
            severity = pipeline._map_severity("UNKNOWN")

            assert severity == ReportSeverity.INFO


class TestStoreFindingEvidence:
    """Test _store_finding_evidence helper method."""

    def test_store_evidence_without_pii(self):
        """Test storing evidence without PII."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            mock_finding = Mock(spec=APITestResult)
            mock_finding.vulnerability_type = VulnerabilityType.SQL_INJECTION
            mock_finding.endpoint = Mock(url="https://example.com/api/users")
            mock_finding.parameter_tested = "id"
            mock_finding.evidence = "SQL error: syntax error"
            mock_finding.http_request = "GET /api/users?id=1' OR '1'='1"
            mock_finding.http_response = "Error: syntax error near line 1"

            # Mock evidence storage without PII
            mock_evidence = Mock(spec=Evidence)
            mock_evidence.metadata = Mock(spec=EvidenceMetadata)
            mock_evidence.metadata.contains_pii = False
            mock_evidence.metadata.evidence_id = "ev-123"

            pipeline.evidence_storage.store_evidence = Mock(return_value=mock_evidence)
            pipeline.evidence_storage.redact_evidence_pii = Mock()

            evidence_id = pipeline._store_finding_evidence(mock_finding)

            assert evidence_id == "ev-123"
            pipeline.evidence_storage.store_evidence.assert_called_once()
            pipeline.evidence_storage.redact_evidence_pii.assert_not_called()

    def test_store_evidence_with_pii_triggers_redaction(self):
        """Test that storing evidence with PII triggers redaction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            mock_finding = Mock(spec=APITestResult)
            mock_finding.vulnerability_type = VulnerabilityType.IDOR
            mock_finding.endpoint = Mock(url="https://example.com/api/profile")
            mock_finding.parameter_tested = "user_id"
            mock_finding.evidence = "User data exposed: john.doe@example.com"
            mock_finding.http_request = "GET /api/profile/123"
            mock_finding.http_response = json.dumps(
                {"email": "john.doe@example.com", "phone": "555-1234"}
            )

            # Mock evidence storage with PII
            mock_evidence = Mock(spec=Evidence)
            mock_evidence.metadata = Mock(spec=EvidenceMetadata)
            mock_evidence.metadata.contains_pii = True
            mock_evidence.metadata.pii_types = [PIIType.EMAIL, PIIType.PHONE]
            mock_evidence.metadata.evidence_id = "ev-123"

            # Mock redacted evidence
            mock_redacted = Mock(spec=Evidence)
            mock_redacted.metadata = Mock(spec=EvidenceMetadata)
            mock_redacted.metadata.evidence_id = "ev-123-redacted"

            pipeline.evidence_storage.store_evidence = Mock(return_value=mock_evidence)
            pipeline.evidence_storage.redact_evidence_pii = Mock(return_value=mock_redacted)

            evidence_id = pipeline._store_finding_evidence(mock_finding)

            assert evidence_id == "ev-123-redacted"
            pipeline.evidence_storage.store_evidence.assert_called_once()
            pipeline.evidence_storage.redact_evidence_pii.assert_called_once()

    def test_store_evidence_payload_structure(self):
        """Test that evidence payload has correct structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            mock_finding = Mock(spec=APITestResult)
            mock_finding.vulnerability_type = VulnerabilityType.XSS
            mock_finding.endpoint = Mock(url="https://example.com/search")
            mock_finding.parameter_tested = "q"
            mock_finding.evidence = "<script>alert('xss')</script>"
            mock_finding.http_request = "GET /search?q=<script>"
            mock_finding.http_response = "<script>alert('xss')</script>"

            # Mock evidence storage
            stored_evidence = None

            def capture_store_evidence(content, evidence_type, created_by, tags, description):
                nonlocal stored_evidence
                stored_evidence = json.loads(content.decode("utf-8"))
                mock_evidence = Mock(spec=Evidence)
                mock_evidence.metadata = Mock(spec=EvidenceMetadata)
                mock_evidence.metadata.contains_pii = False
                mock_evidence.metadata.evidence_id = "ev-123"
                return mock_evidence

            pipeline.evidence_storage.store_evidence = Mock(side_effect=capture_store_evidence)

            pipeline._store_finding_evidence(mock_finding)

            # Verify payload structure
            assert stored_evidence is not None
            assert "http_request" in stored_evidence
            assert "http_response" in stored_evidence
            assert "evidence" in stored_evidence
            assert "endpoint" in stored_evidence
            assert "parameter" in stored_evidence
            assert stored_evidence["endpoint"] == "https://example.com/search"
            assert stored_evidence["parameter"] == "q"


class TestPipelineRunTarget:
    """Test BountyPipeline.run_target() with mocked external components."""

    @pytest.mark.asyncio
    async def test_run_target_exports_reports(self):
        """Test that run_target exports both HTML and JSON reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = BountyPipeline(workspace_dir=tmpdir)

            with patch.object(pipeline.recon_engine, "create_scan") as mock_create_scan:
                with patch.object(
                    pipeline.recon_engine, "run_scan", new_callable=AsyncMock
                ) as mock_run_scan:
                    with patch.object(pipeline.api_scanner, "discover_endpoints") as mock_discover:
                        with patch.object(pipeline.api_scanner, "scan_endpoint") as mock_scan_ep:
                            with patch.object(
                                pipeline.evidence_storage, "store_evidence"
                            ) as mock_store:
                                with patch.object(
                                    pipeline.report_gen, "export_report"
                                ) as mock_export:
                                    # Setup
                                    mock_scan_result = Mock(spec=ReconScan)
                                    mock_scan_result.get_assets_by_type.return_value = []
                                    mock_scan_result.get_summary.return_value = "Found assets"
                                    mock_scan_result.export_json.return_value = "{}"

                                    mock_create_scan.return_value = Mock()
                                    mock_run_scan.return_value = mock_scan_result
                                    mock_discover.return_value = []
                                    mock_scan_ep.return_value = []
                                    mock_store.return_value = Mock(
                                        metadata=Mock(contains_pii=False, evidence_id="ev-123")
                                    )
                                    mock_export.side_effect = [
                                        "<html>Report</html>",
                                        json.dumps({"findings": []}),
                                    ]

                                    # Execute
                                    result = await pipeline.run_target("example.com")

                                    # Verify reports were created
                                    assert result.report_html.exists()
                                    assert result.report_json.exists()
                                    assert mock_export.call_count == 2
