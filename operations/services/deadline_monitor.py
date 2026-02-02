"""Deadline monitoring service with Twilio SMS integration."""

import time
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

try:
    from twilio.rest import Client
except ModuleNotFoundError:  # pragma: no cover - optional dependency for tests
    Client = None

try:
    from operations.database import get_session as get_db
except Exception:  # pragma: no cover - optional dependency for tests

    def get_db():  # type: ignore[return-type]
        raise ImportError("Database session is not available")


from operations.config import config
from operations.models import Grant, GrantMilestone
from operations.services.grant_service import GrantRepository, MilestoneRepository
from shared.logging import get_logger

logger = get_logger(__name__)


class SMSNotifier:
    """SMS notification via Twilio."""

    def __init__(self) -> None:
        self.config = config.twilio

    def is_configured(self) -> bool:
        """Check if Twilio is configured."""
        return self.config.is_configured

    def send_sms(self, to: str, message: str) -> bool:
        """Send an SMS message."""
        if not self.is_configured():
            logger.warning("Twilio not configured, skipping SMS")
            return False

        try:
            if Client is None:
                raise RuntimeError("Twilio client is not available")

            client = Client(self.config.account_sid, self.config.auth_token)

            result = client.messages.create(
                body=message,
                from_=self.config.from_number,
                to=to,
            )

            logger.info(f"SMS sent: {result.sid}")
            return True

        except Exception as e:
            logger.error(f"SMS send failed: {e}")
            return False


class DeadlineMonitor:
    """Service for monitoring grant deadlines and sending reminders."""

    def __init__(self, session: Session | None = None) -> None:
        if session is None:
            self._session_ctx = get_db()
            self.session = self._session_ctx.__enter__()
        else:
            self._session_ctx = None
            self.session = session
        self.grant_repo = GrantRepository(self.session)
        self.milestone_repo = MilestoneRepository(self.session)
        self.sms_notifier = SMSNotifier()
        self.reminder_days = config.scheduler.reminder_days_before

    def get_upcoming_deadlines(self, days: int = 7) -> list[tuple[Grant, int]]:
        """
        Get grants with upcoming deadlines.

        Returns:
            List of (Grant, days_until_deadline) tuples
        """
        now = datetime.utcnow()
        end_date = now + timedelta(days=days)

        grants = self.grant_repo.get_by_deadline_range(now, end_date)

        result = []
        for grant in grants:
            days_left = grant.days_until_deadline
            if days_left is not None and days_left >= 0:
                result.append((grant, days_left))

        return sorted(result, key=lambda x: x[1])

    def get_overdue_grants(self) -> list[Grant]:
        """Get grants with passed deadlines that aren't closed."""
        now = datetime.utcnow()

        return (
            self.session.query(Grant)
            .filter(
                Grant.submission_deadline < now,
                Grant.status.notin_(["submitted", "under_review", "awarded", "rejected", "closed"]),
            )
            .all()
        )

    def get_upcoming_milestones(self, days: int = 7) -> list[tuple[GrantMilestone, int]]:
        """Get upcoming milestones."""
        now = datetime.utcnow()
        milestones = self.milestone_repo.get_upcoming(days=days)

        result = []
        for milestone in milestones:
            if milestone.due_date.tzinfo:
                now_aware = now.replace(tzinfo=UTC)
            else:
                now_aware = now

            days_left = (milestone.due_date - now_aware).days
            result.append((milestone, days_left))

        return sorted(result, key=lambda x: x[1])

    def should_send_reminder(self, days_until: int) -> bool:
        """Check if a reminder should be sent based on days remaining."""
        return days_until in self.reminder_days

    def send_deadline_reminders(
        self,
        phone_numbers: list[str] | None = None,
    ) -> int:
        """
        Send SMS reminders for upcoming deadlines.

        Args:
            phone_numbers: List of phone numbers to notify

        Returns:
            Number of reminders sent
        """
        if not phone_numbers:
            logger.info("No phone numbers configured for reminders")
            return 0

        # Get deadlines that need reminders
        upcoming = self.get_upcoming_deadlines(days=max(self.reminder_days))

        sent_count = 0
        for grant, days_left in upcoming:
            if not self.should_send_reminder(days_left):
                continue

            message = self._format_deadline_message(grant, days_left)

            for phone in phone_numbers:
                if self.sms_notifier.send_sms(phone, message):
                    sent_count += 1

        logger.info(f"Sent {sent_count} deadline reminders")
        return sent_count

    def send_milestone_reminders(
        self,
        phone_numbers: list[str] | None = None,
    ) -> int:
        """Send SMS reminders for upcoming milestones."""
        if not phone_numbers:
            return 0

        upcoming = self.get_upcoming_milestones(days=max(self.reminder_days))

        sent_count = 0
        for milestone, days_left in upcoming:
            if not self.should_send_reminder(days_left) or milestone.reminder_sent:
                continue

            message = self._format_milestone_message(milestone, days_left)

            for phone in phone_numbers:
                if self.sms_notifier.send_sms(phone, message):
                    sent_count += 1

            # Mark reminder as sent
            milestone.reminder_sent = True

        self.session.flush()
        logger.info(f"Sent {sent_count} milestone reminders")
        return sent_count

    def _format_deadline_message(self, grant: Grant, days_left: int) -> str:
        """Format deadline reminder message."""
        urgency = "⚠️ URGENT: " if days_left <= 3 else ""
        day_word = "day" if days_left == 1 else "days"

        return (
            f"{urgency}Grant Deadline Reminder\n\n"
            f"'{grant.grant_name}' ({grant.funder})\n"
            f"Due in {days_left} {day_word}\n"
            f"Status: {grant.status}"
        )

    def _format_milestone_message(self, milestone: GrantMilestone, days_left: int) -> str:
        """Format milestone reminder message."""
        day_word = "day" if days_left == 1 else "days"
        grant = milestone.grant

        return (
            f"Milestone Reminder\n\n"
            f"'{milestone.milestone_name}'\n"
            f"Grant: {grant.grant_name if grant else 'Unknown'}\n"
            f"Due in {days_left} {day_word}"
        )

    def start_monitoring(self, interval: int = 3600) -> None:
        """
        Start deadline monitoring loop.

        Args:
            interval: Check interval in seconds
        """
        logger.info(f"Starting deadline monitor (interval: {interval}s)")

        while True:
            try:
                self._run_check()
            except Exception as e:
                logger.error(f"Error during deadline check: {e}")

            time.sleep(interval)

    def _run_check(self) -> None:
        """Run a single deadline check."""
        logger.debug("Running deadline check")

        # Check for upcoming deadlines
        upcoming = self.get_upcoming_deadlines(days=7)
        if upcoming:
            logger.info(f"Found {len(upcoming)} upcoming deadlines")

        # Check for overdue grants
        overdue = self.get_overdue_grants()
        if overdue:
            logger.warning(f"Found {len(overdue)} overdue grants")
            for grant in overdue:
                logger.warning(f"  - {grant.grant_name}: deadline was {grant.submission_deadline}")

    def check_and_alert(self, phone_numbers: list[str]) -> dict[str, int]:
        """
        Run check and send alerts.

        Returns:
            Summary of alerts sent
        """
        deadline_alerts = self.send_deadline_reminders(phone_numbers)
        milestone_alerts = self.send_milestone_reminders(phone_numbers)

        return {
            "deadline_reminders": deadline_alerts,
            "milestone_reminders": milestone_alerts,
        }
