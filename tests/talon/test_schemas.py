"""
Tests for Pydantic validation schemas.

Tests cover:
- Input validation
- Data normalization
- Error messages
- Edge cases
"""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from talon.schemas import (
    APIResponse,
    ErrorResponse,
    PaginatedResponse,
    ScanResultCreate,
    ScanResultResponse,
    ScanStatus,
    ScanVulnerabilityItem,
    SeverityLevel,
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilitySearchQuery,
    VulnerabilityUpdate,
)


class TestVulnerabilitySchemas:
    """Test vulnerability validation schemas."""

    def test_vulnerability_create_valid(self):
        """Create with valid data."""
        data = VulnerabilityCreate(
            cve_id="CVE-2021-44228",
            description="Test vulnerability",
            severity=SeverityLevel.CRITICAL,
            cvss_score=10.0,
        )

        assert data.cve_id == "CVE-2021-44228"
        assert data.severity == SeverityLevel.CRITICAL

    def test_vulnerability_create_normalizes_cve_id(self):
        """CVE ID is normalized to uppercase."""
        data = VulnerabilityCreate(
            cve_id="cve-2021-44228",
            severity=SeverityLevel.HIGH,
        )

        assert data.cve_id == "CVE-2021-44228"

    def test_vulnerability_create_strips_whitespace(self):
        """Whitespace is stripped from CVE ID."""
        data = VulnerabilityCreate(
            cve_id="  CVE-2021-44228  ",
            severity=SeverityLevel.HIGH,
        )

        assert data.cve_id == "CVE-2021-44228"

    def test_vulnerability_create_invalid_cve_format(self):
        """Invalid CVE format raises error."""
        with pytest.raises(ValidationError) as exc_info:
            VulnerabilityCreate(
                cve_id="INVALID",
                severity=SeverityLevel.HIGH,
            )

        assert "cve_id" in str(exc_info.value)

    def test_vulnerability_create_cve_too_short(self):
        """Too short CVE ID raises error."""
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                cve_id="CVE-1",
                severity=SeverityLevel.HIGH,
            )

    def test_vulnerability_create_cvss_bounds(self):
        """CVSS score must be between 0 and 10."""
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                cve_id="CVE-2021-44228",
                severity=SeverityLevel.HIGH,
                cvss_score=15.0,
            )

        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                cve_id="CVE-2021-44228",
                severity=SeverityLevel.HIGH,
                cvss_score=-1.0,
            )

    def test_vulnerability_update_partial(self):
        """Update can have partial data."""
        data = VulnerabilityUpdate(
            description="Updated description",
        )

        assert data.description == "Updated description"
        assert data.severity == SeverityLevel.UNKNOWN

    def test_vulnerability_update_threat_score_bounds(self):
        """Threat score must be between 0 and 100."""
        with pytest.raises(ValidationError):
            VulnerabilityUpdate(
                threat_score=150.0,
            )

    def test_vulnerability_response_from_orm(self):
        """Response schema can be created from ORM-like object."""
        # Create a mock object with attributes
        class MockVuln:
            id = uuid4()
            cve_id = "CVE-2021-44228"
            description = "Test"
            severity = "CRITICAL"
            cvss_score = 10.0
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            affected_packages = []
            references = []
            published_date = datetime.utcnow()
            modified_date = datetime.utcnow()
            threat_score = 95.0
            created_at = datetime.utcnow()
            updated_at = datetime.utcnow()

        data = VulnerabilityResponse.model_validate(MockVuln())

        assert data.cve_id == "CVE-2021-44228"

    def test_vulnerability_search_query_defaults(self):
        """Search query has sensible defaults."""
        query = VulnerabilitySearchQuery()

        assert query.limit == 50
        assert query.offset == 0
        assert query.query is None

    def test_vulnerability_search_query_limit_bounds(self):
        """Search limit has bounds."""
        with pytest.raises(ValidationError):
            VulnerabilitySearchQuery(limit=0)

        with pytest.raises(ValidationError):
            VulnerabilitySearchQuery(limit=5000)


class TestScanSchemas:
    """Test scan result validation schemas."""

    def test_scan_create_valid(self):
        """Create with valid data."""
        data = ScanResultCreate(
            project_name="my-project",
            package_manager="npm",
            total_dependencies=100,
        )

        assert data.project_name == "my-project"
        assert data.package_manager == "npm"

    def test_scan_create_normalizes_package_manager(self):
        """Package manager is normalized to lowercase."""
        data = ScanResultCreate(
            project_name="my-project",
            package_manager="NPM",
        )

        assert data.package_manager == "npm"

    def test_scan_create_requires_project_name(self):
        """Project name is required."""
        with pytest.raises(ValidationError):
            ScanResultCreate(
                project_name="",
                package_manager="npm",
            )

    def test_scan_create_with_vulnerabilities(self):
        """Create with vulnerability list."""
        data = ScanResultCreate(
            project_name="my-project",
            package_manager="npm",
            vulnerabilities=[
                ScanVulnerabilityItem(
                    cve_id="CVE-2021-44228",
                    package_name="log4j",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=10.0,
                ),
            ],
        )

        assert len(data.vulnerabilities) == 1

    def test_scan_vulnerability_item_valid(self):
        """Vulnerability item with valid data."""
        item = ScanVulnerabilityItem(
            cve_id="CVE-2021-44228",
            package_name="log4j",
            installed_version="2.14.0",
            fixed_version="2.17.0",
            severity=SeverityLevel.CRITICAL,
            cvss_score=10.0,
        )

        assert item.package_name == "log4j"

    def test_scan_result_response(self):
        """Scan result response schema."""
        data = ScanResultResponse(
            id=uuid4(),
            project_name="my-project",
            scan_type="dependency",
            package_manager="npm",
            total_dependencies=100,
            vulnerable_count=5,
            critical_count=1,
            high_count=2,
            medium_count=1,
            low_count=1,
            status=ScanStatus.COMPLETED,
            created_at=datetime.utcnow(),
        )

        assert data.vulnerable_count == 5


class TestCommonSchemas:
    """Test common response schemas."""

    def test_api_response_success(self):
        """Successful API response."""
        response = APIResponse(
            success=True,
            data={"id": "123"},
            message="Created successfully",
        )

        assert response.success is True

    def test_api_response_failure(self):
        """Failed API response."""
        response = APIResponse(
            success=False,
            error="Validation failed",
        )

        assert response.success is False
        assert response.error == "Validation failed"

    def test_error_response(self):
        """Error response schema."""
        response = ErrorResponse(
            error="Not found",
            error_code="RESOURCE_NOT_FOUND",
            details={"resource_id": "123"},
        )

        assert response.success is False
        assert response.error_code == "RESOURCE_NOT_FOUND"

    def test_paginated_response(self):
        """Paginated response schema."""
        response = PaginatedResponse(
            items=[{"id": "1"}, {"id": "2"}],
            total=100,
            page=1,
            page_size=50,
            has_next=True,
            has_prev=False,
        )

        assert len(response.items) == 2
        assert response.has_next is True


class TestSeverityEnum:
    """Test severity level enum."""

    def test_severity_values(self):
        """Severity has expected values."""
        assert SeverityLevel.CRITICAL.value == "CRITICAL"
        assert SeverityLevel.HIGH.value == "HIGH"
        assert SeverityLevel.MEDIUM.value == "MEDIUM"
        assert SeverityLevel.LOW.value == "LOW"
        assert SeverityLevel.UNKNOWN.value == "UNKNOWN"

    def test_severity_from_string(self):
        """Severity can be created from string."""
        assert SeverityLevel("CRITICAL") == SeverityLevel.CRITICAL


class TestScanStatusEnum:
    """Test scan status enum."""

    def test_status_values(self):
        """Status has expected values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
