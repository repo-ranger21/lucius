"""Database models for Operations."""

import uuid
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class Grant(Base):
    """Grant model for tracking funding opportunities."""

    __tablename__ = "grants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    grant_name = Column(String(500), nullable=False)
    funder = Column(String(255), nullable=False)
    amount = Column(Numeric(15, 2))
    currency = Column(String(3), default="USD")
    status = Column(String(50), default="prospecting", index=True)
    priority = Column(String(20), default="medium")
    submission_deadline = Column(DateTime(timezone=True), index=True)
    decision_date = Column(DateTime(timezone=True))
    project_start_date = Column(Date)
    project_end_date = Column(Date)
    description = Column(Text)
    requirements = Column(JSON, default=dict)
    contacts = Column(JSON, default=list)
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    milestones = relationship(
        "GrantMilestone", back_populates="grant", cascade="all, delete-orphan"
    )

    # Status values
    STATUSES = [
        "prospecting",
        "researching",
        "drafting",
        "internal_review",
        "submitted",
        "under_review",
        "awarded",
        "rejected",
        "closed",
    ]

    PRIORITIES = ["low", "medium", "high", "critical"]

    def to_dict(self, include_milestones: bool = False) -> dict:
        """Convert to dictionary."""
        result = {
            "id": str(self.id),
            "grant_name": self.grant_name,
            "funder": self.funder,
            "amount": float(self.amount) if self.amount else None,
            "currency": self.currency,
            "status": self.status,
            "priority": self.priority,
            "submission_deadline": (
                self.submission_deadline.isoformat() if self.submission_deadline else None
            ),
            "decision_date": self.decision_date.isoformat() if self.decision_date else None,
            "project_start_date": (
                self.project_start_date.isoformat() if self.project_start_date else None
            ),
            "project_end_date": (
                self.project_end_date.isoformat() if self.project_end_date else None
            ),
            "description": self.description,
            "requirements": self.requirements,
            "contacts": self.contacts,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_milestones:
            result["milestones"] = [m.to_dict() for m in self.milestones]

        return result

    @property
    def days_until_deadline(self) -> int | None:
        """Calculate days until submission deadline."""
        if not self.submission_deadline:
            return None

        now = datetime.utcnow()
        if self.submission_deadline.tzinfo:
            now = now.replace(tzinfo=UTC)

        delta = cast(datetime, self.submission_deadline) - now
        return int(delta.days)


class GrantMilestone(Base):
    """Milestone model for tracking grant progress."""

    __tablename__ = "grant_milestones"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    grant_id = Column(UUID(as_uuid=True), ForeignKey("grants.id", ondelete="CASCADE"))
    milestone_name = Column(String(255), nullable=False)
    description = Column(Text)
    due_date = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(50), default="pending")
    reminder_sent = Column(Boolean, default=False)
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    grant = relationship("Grant", back_populates="milestones")

    STATUSES = ["pending", "in_progress", "completed", "overdue"]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "grant_id": str(self.grant_id),
            "milestone_name": self.milestone_name,
            "description": self.description,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "status": self.status,
            "reminder_sent": self.reminder_sent,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NonprofitData(Base):
    """Nonprofit data model for data cleaning operations."""

    __tablename__ = "nonprofit_data"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ein = Column(String(20), unique=True, index=True)
    organization_name = Column(String(500), nullable=False)
    dba_name = Column(String(500))
    address = Column(JSON, default=dict)
    phone = Column(String(50))
    email = Column(String(255))
    website = Column(String(500))
    mission_statement = Column(Text)
    ntee_code = Column(String(10))
    subsection_code = Column(String(10))
    foundation_type = Column(String(100))
    ruling_date = Column(Date)
    asset_amount = Column(Numeric(15, 2))
    income_amount = Column(Numeric(15, 2))
    revenue_amount = Column(Numeric(15, 2))
    form_990_year = Column(Integer)
    is_verified = Column(Boolean, default=False)
    data_quality_score = Column(Numeric(5, 2))
    raw_data = Column(JSON, default=dict)
    cleaned_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "ein": self.ein,
            "organization_name": self.organization_name,
            "dba_name": self.dba_name,
            "address": self.address,
            "phone": self.phone,
            "email": self.email,
            "website": self.website,
            "mission_statement": self.mission_statement,
            "ntee_code": self.ntee_code,
            "subsection_code": self.subsection_code,
            "foundation_type": self.foundation_type,
            "ruling_date": self.ruling_date.isoformat() if self.ruling_date else None,
            "asset_amount": float(self.asset_amount) if self.asset_amount else None,
            "income_amount": float(self.income_amount) if self.income_amount else None,
            "revenue_amount": float(self.revenue_amount) if self.revenue_amount else None,
            "form_990_year": self.form_990_year,
            "is_verified": self.is_verified,
            "data_quality_score": (
                float(self.data_quality_score) if self.data_quality_score else None
            ),
            "cleaned_at": self.cleaned_at.isoformat() if self.cleaned_at else None,
        }
