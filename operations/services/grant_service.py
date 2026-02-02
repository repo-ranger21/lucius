"""Grant service using Repository pattern."""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

from sqlalchemy.orm import Session

try:
    from operations.database import get_session as get_db
except Exception:  # pragma: no cover - optional dependency for tests

    def get_db():  # type: ignore[return-type]
        raise ImportError("Database session is not available")


from operations.models import Grant, GrantMilestone
from shared.logging import get_logger

logger = get_logger(__name__)


class GrantRepository:
    """Repository for Grant data access."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, grant_id: str | UUID) -> Grant | None:
        """Get grant by ID."""
        if isinstance(grant_id, str):
            grant_id = UUID(grant_id)
        return cast(Grant | None, self.session.query(Grant).filter(Grant.id == grant_id).first())

    def get_all(
        self,
        status: str | None = None,
        priority: str | None = None,
        limit: int = 100,
    ) -> list[Grant]:
        """Get all grants with optional filtering."""
        query = self.session.query(Grant)

        if status:
            query = query.filter(Grant.status == status)
        if priority:
            query = query.filter(Grant.priority == priority)

        return cast(
            list[Grant],
            query.order_by(Grant.submission_deadline.asc().nullslast()).limit(limit).all(),
        )

    def get_by_deadline_range(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> list[Grant]:
        """Get grants within deadline range."""
        return cast(
            list[Grant],
            (
                self.session.query(Grant)
                .filter(
                    Grant.submission_deadline >= start_date,
                    Grant.submission_deadline <= end_date,
                    Grant.status.notin_(["awarded", "rejected", "closed"]),
                )
                .order_by(Grant.submission_deadline.asc())
                .all()
            ),
        )

    def create(self, grant: Grant) -> Grant:
        """Create a new grant."""
        self.session.add(grant)
        self.session.flush()
        return cast(Grant, grant)

    def update(self, grant: Grant) -> Grant:
        """Update a grant."""
        self.session.flush()
        return cast(Grant, grant)

    def delete(self, grant: Grant) -> None:
        """Delete a grant."""
        self.session.delete(grant)


class MilestoneRepository:
    """Repository for GrantMilestone data access."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, milestone_id: str | UUID) -> GrantMilestone | None:
        """Get milestone by ID."""
        if isinstance(milestone_id, str):
            milestone_id = UUID(milestone_id)
        return cast(
            GrantMilestone | None,
            self.session.query(GrantMilestone).filter(GrantMilestone.id == milestone_id).first(),
        )

    def get_by_grant(self, grant_id: str | UUID) -> list[GrantMilestone]:
        """Get milestones for a grant."""
        if isinstance(grant_id, str):
            grant_id = UUID(grant_id)
        return cast(
            list[GrantMilestone],
            (
                self.session.query(GrantMilestone)
                .filter(GrantMilestone.grant_id == grant_id)
                .order_by(GrantMilestone.due_date.asc())
                .all()
            ),
        )

    def get_upcoming(self, days: int = 7) -> list[GrantMilestone]:
        """Get upcoming milestones."""
        now = datetime.utcnow()
        end_date = now + timedelta(days=days)

        return cast(
            list[GrantMilestone],
            (
                self.session.query(GrantMilestone)
                .filter(
                    GrantMilestone.due_date >= now,
                    GrantMilestone.due_date <= end_date,
                    GrantMilestone.status != "completed",
                )
                .order_by(GrantMilestone.due_date.asc())
                .all()
            ),
        )

    def create(self, milestone: GrantMilestone) -> GrantMilestone:
        """Create a new milestone."""
        self.session.add(milestone)
        self.session.flush()
        return cast(GrantMilestone, milestone)

    def update(self, milestone: GrantMilestone) -> GrantMilestone:
        """Update a milestone."""
        self.session.flush()
        return cast(GrantMilestone, milestone)


class GrantService:
    """Service layer for grant management."""

    def __init__(self, session: Session | None = None) -> None:
        if session is None:
            self._session_ctx = get_db()
            self.session = self._session_ctx.__enter__()
        else:
            self._session_ctx = None
            self.session = session
        self.grant_repo = GrantRepository(self.session)
        self.milestone_repo = MilestoneRepository(self.session)

    def create_grant(
        self,
        grant_name: str,
        funder: str,
        amount: float | None = None,
        submission_deadline: datetime | None = None,
        priority: str = "medium",
        description: str | None = None,
        requirements: dict | None = None,
    ) -> Grant:
        """Create a new grant."""
        grant = Grant(
            grant_name=grant_name,
            funder=funder,
            amount=Decimal(str(amount)) if amount else None,
            submission_deadline=submission_deadline,
            priority=priority,
            description=description,
            requirements=requirements or {},
            status="prospecting",
        )

        grant = self.grant_repo.create(grant)
        logger.info(f"Created grant: {grant.grant_name} (ID: {grant.id})")

        return grant

    def update_grant(
        self,
        grant_id: str,
        status: str | None = None,
        priority: str | None = None,
        **kwargs,
    ) -> Grant | None:
        """Update a grant."""
        grant = self.grant_repo.get_by_id(grant_id)
        if not grant:
            return None

        if status and status in Grant.STATUSES:
            grant.status = status
        if priority and priority in Grant.PRIORITIES:
            grant.priority = priority

        for key, value in kwargs.items():
            if hasattr(grant, key) and value is not None:
                setattr(grant, key, value)

        grant = self.grant_repo.update(grant)
        logger.info(f"Updated grant: {grant.grant_name}")

        return grant

    def get_grant(self, grant_id: str) -> Grant | None:
        """Get a grant by ID."""
        return self.grant_repo.get_by_id(grant_id)

    def list_grants(
        self,
        status: str | None = None,
        priority: str | None = None,
    ) -> list[Grant]:
        """List grants with optional filtering."""
        return self.grant_repo.get_all(status=status, priority=priority)

    def get_upcoming_deadlines(self, days: int = 30) -> list[Grant]:
        """Get grants with upcoming deadlines."""
        now = datetime.utcnow()
        end_date = now + timedelta(days=days)
        return self.grant_repo.get_by_deadline_range(now, end_date)

    def add_milestone(
        self,
        grant_id: str,
        milestone_name: str,
        due_date: datetime,
        description: str | None = None,
    ) -> GrantMilestone | None:
        """Add a milestone to a grant."""
        grant = self.grant_repo.get_by_id(grant_id)
        if not grant:
            return None

        milestone = GrantMilestone(
            grant_id=grant.id,
            milestone_name=milestone_name,
            due_date=due_date,
            description=description,
            status="pending",
        )

        milestone = self.milestone_repo.create(milestone)
        logger.info(f"Added milestone to grant {grant_id}: {milestone_name}")

        return milestone

    def complete_milestone(self, milestone_id: str) -> GrantMilestone | None:
        """Mark a milestone as completed."""
        milestone = self.milestone_repo.get_by_id(milestone_id)
        if not milestone:
            return None

        milestone.status = "completed"
        milestone.completed_at = datetime.utcnow()

        milestone = self.milestone_repo.update(milestone)
        logger.info(f"Completed milestone: {milestone.milestone_name}")

        return milestone

    def get_pipeline_summary(self) -> dict[str, Any]:
        """Get grant pipeline summary."""
        all_grants = self.grant_repo.get_all(limit=1000)

        by_status: dict[str, int] = {}
        total_amount = Decimal("0")
        awarded_amount = Decimal("0")

        for grant in all_grants:
            status = grant.status
            by_status[status] = by_status.get(status, 0) + 1

            if grant.amount:
                total_amount += grant.amount
                if grant.status == "awarded":
                    awarded_amount += grant.amount

        return {
            "total_grants": len(all_grants),
            "by_status": by_status,
            "total_pipeline_value": float(total_amount),
            "awarded_value": float(awarded_amount),
            "upcoming_deadlines": len(self.get_upcoming_deadlines(days=30)),
        }
