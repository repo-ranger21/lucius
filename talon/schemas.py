"""
Pydantic schemas for API request/response validation.

This module provides type-safe validation for all Talon API endpoints
with proper input sanitization and output serialization.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Vulnerability Schemas
# =============================================================================


class VulnerabilityBase(BaseModel):
    """Base vulnerability schema with common fields."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_max_length=50000,
    )

    description: str | None = Field(
        default=None,
        max_length=10000,
        description="Vulnerability description",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.UNKNOWN,
        description="Severity level",
    )
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS v3.x base score",
    )
    cvss_vector: str | None = Field(
        default=None,
        max_length=200,
        description="CVSS vector string",
    )
    affected_packages: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of affected packages",
    )
    references: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Reference URLs and sources",
    )
    published_date: datetime | None = Field(
        default=None,
        description="CVE publication date",
    )
    modified_date: datetime | None = Field(
        default=None,
        description="Last modification date",
    )


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a new vulnerability."""

    cve_id: str = Field(
        ...,
        min_length=9,
        max_length=20,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="CVE identifier (e.g., CVE-2021-44228)",
    )

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, v: str) -> str:
        """Normalize CVE ID to uppercase."""
        return v.upper().strip()


class VulnerabilityUpdate(VulnerabilityBase):
    """Schema for updating an existing vulnerability."""

    threat_score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="ML-based threat score",
    )


class VulnerabilityResponse(VulnerabilityBase):
    """Schema for vulnerability API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(description="Unique identifier")
    cve_id: str = Field(description="CVE identifier")
    threat_score: float | None = Field(
        default=None,
        description="ML-based threat score",
    )
    created_at: datetime | None = Field(
        default=None,
        description="Record creation timestamp",
    )
    updated_at: datetime | None = Field(
        default=None,
        description="Record update timestamp",
    )


class VulnerabilitySearchQuery(BaseModel):
    """Schema for vulnerability search parameters."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str | None = Field(
        default=None,
        max_length=200,
        description="Search in CVE ID or description",
    )
    severity: SeverityLevel | None = Field(
        default=None,
        description="Filter by severity level",
    )
    min_cvss: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Minimum CVSS score",
    )
    package_name: str | None = Field(
        default=None,
        max_length=200,
        description="Filter by affected package",
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum results",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Results offset",
    )


# =============================================================================
# Scan Schemas
# =============================================================================


class ScanVulnerabilityItem(BaseModel):
    """Schema for vulnerability item in scan results."""

    cve_id: str = Field(description="CVE identifier")
    package_name: str = Field(description="Affected package name")
    installed_version: str | None = Field(
        default=None,
        description="Currently installed version",
    )
    fixed_version: str | None = Field(
        default=None,
        description="Version that fixes the vulnerability",
    )
    severity: SeverityLevel | None = Field(
        default=None,
        description="Severity level",
    )
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS score",
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Short description",
    )


class ScanResultCreate(BaseModel):
    """Schema for submitting scan results."""

    model_config = ConfigDict(str_strip_whitespace=True)

    project_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Project name",
    )
    package_manager: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Package manager (npm, pip, composer, etc.)",
    )
    scan_type: str = Field(
        default="dependency",
        max_length=50,
        description="Type of scan performed",
    )
    total_dependencies: int = Field(
        default=0,
        ge=0,
        description="Total number of dependencies scanned",
    )
    vulnerabilities: list[ScanVulnerabilityItem] = Field(
        default_factory=list,
        description="List of discovered vulnerabilities",
    )
    sbom_path: str | None = Field(
        default=None,
        max_length=500,
        description="Path to generated SBOM file",
    )
    scan_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan metadata",
    )

    @field_validator("package_manager")
    @classmethod
    def normalize_package_manager(cls, v: str) -> str:
        """Normalize package manager name."""
        return v.lower().strip()


class ScanResultResponse(BaseModel):
    """Schema for scan result API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(description="Unique identifier")
    project_name: str = Field(description="Project name")
    scan_type: str = Field(description="Type of scan")
    package_manager: str = Field(description="Package manager")
    total_dependencies: int = Field(description="Total dependencies")
    vulnerable_count: int = Field(description="Vulnerable package count")
    critical_count: int = Field(description="Critical severity count")
    high_count: int = Field(description="High severity count")
    medium_count: int = Field(description="Medium severity count")
    low_count: int = Field(description="Low severity count")
    sbom_path: str | None = Field(default=None, description="SBOM file path")
    scan_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    status: ScanStatus = Field(description="Scan status")
    created_at: datetime | None = Field(description="Creation timestamp")
    completed_at: datetime | None = Field(
        default=None,
        description="Completion timestamp",
    )
    vulnerabilities: list[ScanVulnerabilityItem | None] = Field(
        default=None,
        description="Vulnerability details (when requested)",
    )


# =============================================================================
# Statistics Schemas
# =============================================================================


class VulnerabilityStatistics(BaseModel):
    """Schema for vulnerability statistics response."""

    total: int = Field(description="Total vulnerabilities")
    severity_counts: dict[str, int] = Field(
        description="Counts by severity level",
    )
    average_cvss: float = Field(description="Average CVSS score")
    scored_count: int = Field(description="Vulnerabilities with threat scores")
    last_30_days: int = Field(description="New in last 30 days")
    last_7_days: int = Field(description="New in last 7 days")
    critical_count: int = Field(description="Critical severity count")
    high_count: int = Field(description="High severity count")


class ScanStatistics(BaseModel):
    """Schema for scan statistics response."""

    total_scans: int = Field(description="Total scans")
    status_breakdown: dict[str, int] = Field(description="Counts by status")
    scans_last_7_days: int = Field(description="Scans in last 7 days")
    scans_with_critical: int = Field(description="Scans with critical vulns")
    vulnerabilities_last_7_days: int = Field(
        description="Total vulns in last 7 days",
    )
    critical_vulnerabilities_last_7_days: int = Field(
        description="Critical vulns in last 7 days",
    )


# =============================================================================
# Common Response Schemas
# =============================================================================


class PaginatedResponse(BaseModel):
    """Schema for paginated API responses."""

    items: list[Any] = Field(description="Result items")
    total: int = Field(description="Total count")
    page: int = Field(description="Current page")
    page_size: int = Field(description="Items per page")
    has_next: bool = Field(description="Has next page")
    has_prev: bool = Field(description="Has previous page")


class APIResponse(BaseModel):
    """Schema for standard API responses."""

    success: bool = Field(default=True, description="Operation success")
    data: Any | None = Field(default=None, description="Response data")
    error: str | None = Field(default=None, description="Error message")
    message: str | None = Field(default=None, description="Status message")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )


class ErrorResponse(BaseModel):
    """Schema for error responses."""

    success: bool = Field(default=False)
    error: str = Field(description="Error message")
    error_code: str | None = Field(
        default=None,
        description="Machine-readable error code",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Additional error details",
    )
