"""Database models for Talon."""

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from talon.extensions import db


class Tenant(db.Model):
    """Tenant model for multi-tenant isolation."""

    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "name": self.name,
            "is_active": self.is_active,
            "settings": self.settings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Vulnerability(db.Model):
    """Vulnerability model representing CVE entries."""

    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Numeric(3, 1))
    cvss_vector = Column(String(100))
    affected_packages = Column(JSON, default=list)
    references = Column(JSON, default=list)
    published_date = Column(DateTime(timezone=True))
    modified_date = Column(DateTime(timezone=True))
    threat_score = Column(Numeric(5, 2))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan_vulnerabilities = relationship("ScanVulnerability", back_populates="vulnerability")

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": float(self.cvss_score) if self.cvss_score else None,
            "cvss_vector": self.cvss_vector,
            "affected_packages": self.affected_packages,
            "references": self.references,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "threat_score": float(self.threat_score) if self.threat_score else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ScanResult(db.Model):
    """Scan result model representing vulnerability scan outputs."""

    __tablename__ = "scan_results"
    __table_args__ = (
        Index("ix_scan_results_tenant_project", "tenant_id", "project_name"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(100), nullable=False, index=True)
    project_name = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)
    package_manager = Column(String(50), nullable=False)
    total_dependencies = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    sbom_path = Column(String(500))
    scan_metadata = Column(JSON, default=dict)
    status = Column(String(20), default="pending", index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True))

    # Relationships
    vulnerabilities = relationship(
        "ScanVulnerability", back_populates="scan", cascade="all, delete-orphan"
    )

    def to_dict(self, include_vulnerabilities: bool = False) -> dict:
        """Convert to dictionary."""
        result = {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "project_name": self.project_name,
            "scan_type": self.scan_type,
            "package_manager": self.package_manager,
            "total_dependencies": self.total_dependencies,
            "vulnerable_count": self.vulnerable_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "sbom_path": self.sbom_path,
            "scan_metadata": self.scan_metadata,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

        if include_vulnerabilities:
            result["vulnerabilities"] = [sv.to_dict() for sv in self.vulnerabilities]

        return result


class ScanVulnerability(db.Model):
    """Junction table linking scans to vulnerabilities."""

    __tablename__ = "scan_vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"))
    vulnerability_id = Column(
        UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    package_name = Column(String(255), nullable=False)
    installed_version = Column(String(100))
    fixed_version = Column(String(100))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    scan = relationship("ScanResult", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="scan_vulnerabilities")

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "vulnerability_id": str(self.vulnerability_id),
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "vulnerability": self.vulnerability.to_dict() if self.vulnerability else None,
        }


class Notification(db.Model):
    """Notification model for tracking sent notifications."""

    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(100), nullable=False, index=True)
    notification_type = Column(String(50), nullable=False)
    channel = Column(String(50), nullable=False)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500))
    body = Column(Text, nullable=False)
    notification_metadata = Column(JSON, default=dict)
    status = Column(String(20), default="pending", index=True)
    sent_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "notification_type": self.notification_type,
            "channel": self.channel,
            "recipient": self.recipient,
            "subject": self.subject,
            "body": self.body,
            "metadata": self.notification_metadata,
            "status": self.status,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
