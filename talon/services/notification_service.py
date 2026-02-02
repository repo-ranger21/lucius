"""Notification service using Strategy pattern."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from shared.logging import get_logger
from talon.config import config
from talon.extensions import db
from talon.models import Notification

logger = get_logger(__name__)


class NotificationStrategy(ABC):
    """Abstract base class for notification strategies."""

    @abstractmethod
    def send(self, notification: Notification) -> bool:
        """Send the notification."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the strategy is properly configured."""
        pass


class SMSStrategy(NotificationStrategy):
    """SMS notification via Twilio."""

    def __init__(self) -> None:
        self.config = config.twilio

    def is_configured(self) -> bool:
        return self.config.is_configured

    def send(self, notification: Notification) -> bool:
        if not self.is_configured():
            logger.warning("Twilio not configured, skipping SMS")
            return False

        try:
            from twilio.rest import Client

            client = Client(self.config.account_sid, self.config.auth_token)

            message = client.messages.create(
                body=notification.body,
                from_=self.config.from_number,
                to=notification.recipient,
            )

            logger.info(f"SMS sent: {message.sid}")
            return True

        except Exception as e:
            logger.error(f"SMS send failed: {e}")
            raise


class EmailStrategy(NotificationStrategy):
    """Email notification via SendGrid."""

    def __init__(self) -> None:
        self.config = config.sendgrid

    def is_configured(self) -> bool:
        return self.config.is_configured

    def send(self, notification: Notification) -> bool:
        if not self.is_configured():
            logger.warning("SendGrid not configured, skipping email")
            return False

        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            message = Mail(
                from_email=self.config.from_email,
                to_emails=notification.recipient,
                subject=notification.subject or "Lucius Alert",
                html_content=notification.body,
            )

            sg = SendGridAPIClient(self.config.api_key)
            response = sg.send(message)

            logger.info(f"Email sent: {response.status_code}")
            return response.status_code in (200, 202)

        except Exception as e:
            logger.error(f"Email send failed: {e}")
            raise


class SlackStrategy(NotificationStrategy):
    """Slack notification via webhook."""

    def __init__(self) -> None:
        self.config = config.slack

    def is_configured(self) -> bool:
        return self.config.is_configured

    def send(self, notification: Notification) -> bool:
        if not self.is_configured():
            logger.warning("Slack not configured, skipping")
            return False

        try:
            import httpx

            # Build Slack message blocks
            blocks = self._build_slack_blocks(notification)

            response = httpx.post(
                self.config.webhook_url,
                json={"blocks": blocks, "text": notification.subject or notification.body[:100]},
                timeout=10,
            )
            response.raise_for_status()

            logger.info("Slack message sent")
            return True

        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            raise

    def _build_slack_blocks(self, notification: Notification) -> list[dict[str, Any]]:
        """Build Slack block kit message."""
        blocks: list[dict[str, Any]] = []

        if notification.subject:
            blocks.append(
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": notification.subject,
                    },
                }
            )

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": notification.body,
                },
            }
        )

        # Add metadata if present
        metadata = notification.metadata or {}
        if metadata.get("severity"):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
            }.get(metadata["severity"].lower(), "⚪")

            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"{severity_emoji} Severity: *{metadata['severity'].upper()}*",
                        }
                    ],
                }
            )

        return blocks


class NotificationService:
    """Service for managing notifications using Strategy pattern."""

    def __init__(self) -> None:
        self.strategies: dict[str, NotificationStrategy] = {
            "sms": SMSStrategy(),
            "email": EmailStrategy(),
            "slack": SlackStrategy(),
        }

    def create_notification(
        self,
        notification_type: str,
        channel: str,
        recipient: str,
        body: str,
        subject: str | None = None,
        metadata: dict | None = None,
    ) -> Notification:
        """Create a notification record."""
        notification = Notification(
            tenant_id="default",
            notification_type=notification_type,
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            metadata=metadata or {},
            status="pending",
        )

        db.session.add(notification)
        db.session.commit()

        return notification

    def send_notification(self, notification: Notification) -> bool:
        """Send a notification using the appropriate strategy."""
        strategy = self.strategies.get(notification.channel)

        if not strategy:
            notification.status = "failed"
            notification.error_message = f"Unknown channel: {notification.channel}"
            db.session.commit()
            return False

        if not strategy.is_configured():
            notification.status = "failed"
            notification.error_message = f"Channel not configured: {notification.channel}"
            db.session.commit()
            return False

        try:
            success = strategy.send(notification)

            if success:
                notification.status = "sent"
                notification.sent_at = datetime.utcnow()
            else:
                notification.status = "failed"
                notification.error_message = "Send returned false"

            db.session.commit()
            return success

        except Exception as e:
            notification.status = "failed"
            notification.error_message = str(e)[:500]
            notification.retry_count += 1
            db.session.commit()

            logger.error(f"Notification {notification.id} failed: {e}")
            return False

    def queue_notification(self, notification: Notification) -> None:
        """Queue a notification for async sending."""
        from talon.tasks.notifications import send_notification_task

        send_notification_task.delay(str(notification.id))

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "high",
        channels: list[str] | None = None,
        recipients: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """Send an alert to multiple channels."""
        channels = channels or ["slack"]
        recipients = recipients or {}

        results = {}

        for channel in channels:
            channel_recipients = recipients.get(channel, [])

            # Default recipients
            if not channel_recipients:
                if channel == "slack":
                    channel_recipients = ["default"]  # Uses webhook URL
                else:
                    continue

            for recipient in channel_recipients:
                notification = self.create_notification(
                    notification_type="alert",
                    channel=channel,
                    recipient=recipient,
                    subject=title,
                    body=message,
                    metadata={"severity": severity},
                )

                success = self.send_notification(notification)
                results[f"{channel}:{recipient}"] = success

        return results
