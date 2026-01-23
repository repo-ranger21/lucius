"""Talon API client for Operations service."""

from typing import Any, cast

import httpx

from operations.config import config
from shared.logging import get_logger

logger = get_logger(__name__)


class TalonClient:
    """Client for communicating with the Talon API."""

    def __init__(self) -> None:
        self.config = config.talon

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Operations-Service/1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def send_notification(
        self,
        notification_type: str,
        channel: str,
        recipient: str,
        body: str,
        subject: str | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any] | None:
        """
        Send a notification via Talon.

        Args:
            notification_type: Type of notification
            channel: Delivery channel (sms, email, slack)
            recipient: Recipient address/number
            body: Notification body
            subject: Optional subject
            metadata: Optional metadata

        Returns:
            API response or None on failure
        """
        try:
            with httpx.Client(
                base_url=self.config.api_url,
                timeout=self.config.timeout,
                headers=self._get_headers(),
            ) as client:
                response = client.post(
                    "/api/v1/notifications",
                    json={
                        "notification_type": notification_type,
                        "channel": channel,
                        "recipient": recipient,
                        "subject": subject,
                        "body": body,
                        "metadata": metadata or {},
                    },
                )
                response.raise_for_status()
                return cast(dict[str, Any], response.json())

        except Exception as e:
            logger.error(f"Failed to send notification via Talon: {e}")
            return None

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        channels: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Send an alert via Talon.

        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            channels: Channels to send to

        Returns:
            API response or None on failure
        """
        try:
            with httpx.Client(
                base_url=self.config.api_url,
                timeout=self.config.timeout,
                headers=self._get_headers(),
            ) as client:
                response = client.post(
                    "/api/v1/notifications/send-alert",
                    json={
                        "title": title,
                        "message": message,
                        "severity": severity,
                        "channels": channels or ["slack"],
                    },
                )
                response.raise_for_status()
                return cast(dict[str, Any], response.json())

        except Exception as e:
            logger.error(f"Failed to send alert via Talon: {e}")
            return None

    def report_deadline(
        self,
        grant_name: str,
        days_remaining: int,
        funder: str,
    ) -> None:
        """Report upcoming deadline to Talon for alerting."""
        severity = (
            "critical" if days_remaining <= 3 else "high" if days_remaining <= 7 else "medium"
        )

        self.send_alert(
            title=f"Grant Deadline: {grant_name}",
            message=(f"*{grant_name}* deadline in {days_remaining} days\n" f"Funder: {funder}"),
            severity=severity,
            channels=["slack"],
        )

    def health_check(self) -> bool:
        """Check if Talon API is healthy."""
        try:
            with httpx.Client(
                base_url=self.config.api_url,
                timeout=5,
            ) as client:
                response = client.get("/health")
                return bool(response.status_code == 200)
        except Exception:
            return False

    def get_vulnerability_stats(self) -> dict[str, Any] | None:
        """Get vulnerability statistics from Talon."""
        try:
            with httpx.Client(
                base_url=self.config.api_url,
                timeout=self.config.timeout,
                headers=self._get_headers(),
            ) as client:
                response = client.get("/api/v1/vulnerabilities/stats")
                response.raise_for_status()
                return cast(dict[str, Any], response.json())
        except Exception as e:
            logger.error(f"Failed to get vulnerability stats: {e}")
            return None

    def get_scan_stats(self) -> dict[str, Any] | None:
        """Get scan statistics from Talon."""
        try:
            with httpx.Client(
                base_url=self.config.api_url,
                timeout=self.config.timeout,
                headers=self._get_headers(),
            ) as client:
                response = client.get("/api/v1/scans/stats")
                response.raise_for_status()
                return cast(dict[str, Any], response.json())
        except Exception as e:
            logger.error(f"Failed to get scan stats: {e}")
            return None
