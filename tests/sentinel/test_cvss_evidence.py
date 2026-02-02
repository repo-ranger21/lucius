"""Tests for CVSS scoring and evidence collection."""

import json
from datetime import datetime

import pytest

from sentinel.cvss_scorer import (
    CVSSScore,
    CVSSv31Scorer,
    CVSSv40Scorer,
    CVSSVersion,
    VulnerabilityAssessment,
    VulnerabilityScorerFactory,
)
from sentinel.evidence_collector import (
    Evidence,
    EvidenceCollection,
    EvidenceSensitivity,
    EvidenceType,
)


class TestCVSSv31Scorer:
    """Tests for CVSS v3.1 scoring."""

    def test_calculate_high_cvss_score(self):
        """Test calculating a high CVSS score."""
        score = CVSSv31Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        assert score.version == CVSSVersion.V3_1
        assert score.score >= 9.0
        assert score.severity == "CRITICAL"
        assert "CVSS:3.1" in score.vector

    def test_calculate_medium_cvss_score(self):
        """Test calculating a medium CVSS score."""
        score = CVSSv31Scorer.calculate(
            attack_vector="A",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="L",
        )

        assert score.version == CVSSVersion.V3_1
        assert 5.0 <= score.score <= 7.0
        assert score.severity in ["MEDIUM", "HIGH"]

    def test_calculate_low_cvss_score(self):
        """Test calculating a low CVSS score."""
        score = CVSSv31Scorer.calculate(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="L",
        )

        assert score.version == CVSSVersion.V3_1
        assert score.score < 4.0
        assert score.severity == "LOW"

    def test_calculate_zero_score(self):
        """Test calculating zero impact (no impact)."""
        score = CVSSv31Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )

        assert score.score == 0.0
        assert score.severity == "NONE"

    def test_score_to_severity_mapping(self):
        """Test severity mapping."""
        assert CVSSv31Scorer.score_to_severity(0.0) == "NONE"
        assert CVSSv31Scorer.score_to_severity(2.0) == "LOW"
        assert CVSSv31Scorer.score_to_severity(5.5) == "MEDIUM"
        assert CVSSv31Scorer.score_to_severity(8.0) == "HIGH"
        assert CVSSv31Scorer.score_to_severity(9.5) == "CRITICAL"

    def test_cvss_vector_format(self):
        """Test CVSS vector string format."""
        score = CVSSv31Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        assert score.vector.startswith("CVSS:3.1/")
        assert "AV:N" in score.vector
        assert "AC:L" in score.vector
        assert "PR:N" in score.vector
        assert "UI:N" in score.vector


class TestCVSSv40Scorer:
    """Tests for CVSS v4.0 scoring."""

    def test_calculate_v40_score(self):
        """Test CVSS v4.0 scoring."""
        score = CVSSv40Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        assert score.version == CVSSVersion.V4_0
        assert score.score >= 0
        assert "CVSS:4.0" in score.vector

    def test_v40_vector_format(self):
        """Test CVSS v4.0 vector format."""
        score = CVSSv40Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        assert score.vector.startswith("CVSS:4.0/")


class TestCVSSScoreToDictConversion:
    """Tests for CVSSScore to dict conversion."""

    def test_cvss_score_to_dict(self):
        """Test converting CVSSScore to dictionary."""
        score = CVSSv31Scorer.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        score_dict = score.to_dict()

        assert score_dict["version"] == "3.1"
        assert "score" in score_dict
        assert "vector" in score_dict
        assert "severity" in score_dict
        assert "metrics" in score_dict

        # Check metrics
        metrics = score_dict["metrics"]
        assert metrics["attack_vector"] == "N"
        assert metrics["attack_complexity"] == "L"


class TestVulnerabilityScorerFactory:
    """Tests for scorer factory."""

    def test_create_v31_scorer(self):
        """Test creating v3.1 scorer."""
        scorer = VulnerabilityScorerFactory.create_scorer(CVSSVersion.V3_1)
        assert scorer == CVSSv31Scorer

    def test_create_v40_scorer(self):
        """Test creating v4.0 scorer."""
        scorer = VulnerabilityScorerFactory.create_scorer(CVSSVersion.V4_0)
        assert scorer == CVSSv40Scorer


class TestEvidence:
    """Tests for Evidence class."""

    def test_create_evidence(self):
        """Test creating evidence."""
        evidence = Evidence(
            evidence_type=EvidenceType.SCREENSHOT,
            content="Screenshot data",
            description="XSS payload execution",
            tags=["xss"],
        )

        assert evidence.evidence_type == EvidenceType.SCREENSHOT
        assert evidence.description == "XSS payload execution"
        assert "xss" in evidence.tags

    def test_evidence_hash_computation(self):
        """Test evidence hash computation."""
        evidence1 = Evidence(
            evidence_type=EvidenceType.LOG_FILE,
            content="Same content",
        )
        evidence2 = Evidence(
            evidence_type=EvidenceType.LOG_FILE,
            content="Same content",
        )

        assert evidence1.hash == evidence2.hash

    def test_evidence_to_dict(self):
        """Test evidence to dict conversion."""
        evidence = Evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            content="Response body",
            description="API response",
        )

        evidence_dict = evidence.to_dict(include_content=True)

        assert evidence_dict["type"] == "api_response"
        assert evidence_dict["description"] == "API response"
        assert "content" in evidence_dict
        assert "hash" in evidence_dict

    def test_evidence_redact_pii(self):
        """Test PII redaction."""
        content = "User email: test@example.com and SSN: 123-45-6789"
        evidence = Evidence(
            evidence_type=EvidenceType.LOG_FILE,
            content=content,
        )

        redacted = evidence.redact_pii()

        assert "test@example.com" not in redacted.content.decode()
        assert "123-45-6789" not in redacted.content.decode()
        assert "[REDACTED]" in redacted.content.decode()

    def test_evidence_redact_api_key(self):
        """Test redacting API keys."""
        content = 'api_key = "sk_live_12345abcde"'
        evidence = Evidence(
            evidence_type=EvidenceType.CONFIGURATION,
            content=content,
        )

        redacted = evidence.redact_pii()

        assert "sk_live_12345abcde" not in redacted.content.decode()
        assert "[REDACTED]" in redacted.content.decode()


class TestEvidenceCollection:
    """Tests for EvidenceCollection."""

    def test_create_collection(self):
        """Test creating evidence collection."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
            description="SQL Injection vulnerability",
        )

        assert collection.finding_id == "FIND-001"
        assert collection.cve_id == "CVE-2021-12345"
        assert len(collection.evidence_list) == 0

    def test_add_screenshot(self):
        """Test adding screenshot."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_screenshot(b"image data", description="SQLi payload")

        assert len(collection.evidence_list) == 1
        assert collection.evidence_list[0].evidence_type == EvidenceType.SCREENSHOT

    def test_add_log_file(self):
        """Test adding log file."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_log_file("Error log content", source="/var/log/app.log")

        assert len(collection.evidence_list) == 1
        assert collection.evidence_list[0].evidence_type == EvidenceType.LOG_FILE

    def test_add_api_response(self):
        """Test adding API response."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        response_data = {"error": "SQL syntax error", "query": "SELECT * FROM users"}
        collection.add_api_response(response_data, url="https://api.example.com/users")

        assert len(collection.evidence_list) == 1
        assert collection.evidence_list[0].evidence_type == EvidenceType.API_RESPONSE

    def test_add_error_message(self):
        """Test adding error message."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_error_message("MySQL error: syntax error near WHERE")

        assert len(collection.evidence_list) == 1
        assert "error-disclosure" in collection.evidence_list[0].tags

    def test_get_evidence_by_type(self):
        """Test filtering evidence by type."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_screenshot(b"img", description="Screenshot 1")
        collection.add_log_file("Log content", description="Log 1")
        collection.add_screenshot(b"img2", description="Screenshot 2")

        screenshots = collection.get_evidence_by_type(EvidenceType.SCREENSHOT)

        assert len(screenshots) == 2
        assert all(e.evidence_type == EvidenceType.SCREENSHOT for e in screenshots)

    def test_get_evidence_by_tag(self):
        """Test filtering evidence by tag."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_screenshot(b"img", tags=["xss", "reflected"])
        collection.add_screenshot(b"img2", tags=["xss"])
        collection.add_log_file("Log content", tags=["error"])

        xss_evidence = collection.get_evidence_by_tag("xss")

        assert len(xss_evidence) == 2

    def test_has_sensitive_evidence(self):
        """Test checking for sensitive evidence."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        evidence = Evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            content="Response data",
            sensitivity=EvidenceSensitivity.RESTRICTED,
        )
        collection.add_evidence(evidence)

        assert collection.has_sensitive_evidence()

    def test_redact_all_pii(self):
        """Test redacting all PII in collection."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
        )

        collection.add_api_response({"email": "user@example.com"})
        collection.add_error_message("Error: password = secret123")

        redacted = collection.redact_all_pii()

        # All evidence should be marked as public
        assert all(e.sensitivity == EvidenceSensitivity.PUBLIC for e in redacted.evidence_list)

    def test_export_for_report(self):
        """Test exporting evidence for bug bounty report."""
        collection = EvidenceCollection(
            finding_id="FIND-001",
            cve_id="CVE-2021-12345",
            description="SQL Injection",
        )

        collection.add_screenshot(b"img", description="SQLi proof")
        collection.add_api_response({"error": "SQL error"})

        report = collection.export_for_report(include_sensitive=True)

        assert report["finding_id"] == "FIND-001"
        assert report["cve_id"] == "CVE-2021-12345"
        assert report["evidence_count"] == 2


class TestVulnerabilityAssessment:
    """Tests for comprehensive vulnerability assessment."""

    def test_assess_critical_vulnerability(self):
        """Test assessing a critical vulnerability."""
        assessment = VulnerabilityAssessment(cvss_version=CVSSVersion.V3_1)

        vuln = {
            "cve_id": "CVE-2021-12345",
            "package_name": "lib-example",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
            "description": "Remote code execution",
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        }

        result = assessment.assess(vuln)

        assert result["cve_id"] == "CVE-2021-12345"
        assert result["cvss"]["severity"] == "CRITICAL"
        assert result["impact"]["data_exposed"]
        assert result["remediation"]["priority"] == "IMMEDIATE"

    def test_assessment_includes_all_fields(self):
        """Test that assessment includes all required fields."""
        assessment = VulnerabilityAssessment()

        vuln = {
            "cve_id": "CVE-2021-12345",
            "package_name": "lib",
            "installed_version": "1.0",
            "fixed_version": "1.1",
            "description": "Vulnerability",
        }

        result = assessment.assess(vuln)

        assert "cvss" in result
        assert "impact" in result
        assert "exploitability" in result
        assert "remediation" in result
        assert "business_impact" in result
