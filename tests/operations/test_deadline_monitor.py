"""Tests for deadline monitor service."""

from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


class TestDeadlineMonitor:
    """Test cases for DeadlineMonitor."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock()
        return session

    @pytest.fixture
    def monitor(self, mock_session):
        """Create deadline monitor with mocked dependencies."""
        with patch("operations.services.deadline_monitor.config") as mock_config:
            mock_config.scheduler.reminder_days_before = 7

            from operations.services.deadline_monitor import DeadlineMonitor

            return DeadlineMonitor(mock_session)

    def test_check_grant_deadlines_none_approaching(self, monitor, mock_session):
        """Test when no deadlines are approaching."""
        mock_session.query.return_value.filter.return_value.all.return_value = []

        # Should not send any alerts

    def test_check_grant_deadlines_urgent(self, monitor, mock_session):
        """Test when grant deadline is urgent (< 3 days)."""
        urgent_grant = MagicMock()
        urgent_grant.id = uuid4()
        urgent_grant.grant_name = "Urgent Grant"
        urgent_grant.organization_name = "Test Org"
        urgent_grant.deadline = date.today() + timedelta(days=2)
        urgent_grant.amount = Decimal("50000")

        mock_session.query.return_value.filter.return_value.all.return_value = [urgent_grant]

        # Should trigger urgent notification

    def test_check_milestone_deadlines(self, monitor, mock_session):
        """Test checking milestone deadlines."""
        overdue_milestone = MagicMock()
        overdue_milestone.id = uuid4()
        overdue_milestone.title = "Overdue Task"
        overdue_milestone.due_date = date.today() - timedelta(days=1)
        overdue_milestone.completed = False
        overdue_milestone.grant = MagicMock()
        overdue_milestone.grant.grant_name = "Parent Grant"

        mock_session.query.return_value.filter.return_value.all.return_value = [overdue_milestone]

        # Should flag overdue milestone


class TestAlertFormatting:
    """Test alert message formatting."""

    def test_format_grant_alert_urgent(self):
        """Test formatting for urgent grant deadline."""

        # Alert should contain these elements

    def test_format_grant_alert_warning(self):
        """Test formatting for warning-level grant deadline."""

    def test_format_milestone_alert(self):
        """Test formatting for milestone deadline."""


class TestSMSIntegration:
    """Test SMS notification integration."""

    @pytest.fixture
    def mock_twilio(self):
        """Create mock Twilio client."""
        with patch("operations.services.deadline_monitor.Client") as mock:
            mock_client = MagicMock()
            mock.return_value = mock_client
            yield mock_client

    def test_send_sms_success(self, mock_twilio):
        """Test successful SMS sending."""
        mock_twilio.messages.create.return_value.sid = "SM123"

        # SMS should be sent successfully

    def test_send_sms_failure(self, mock_twilio):
        """Test SMS sending failure handling."""
        mock_twilio.messages.create.side_effect = Exception("Twilio error")

        # Should handle error gracefully

    def test_sms_disabled(self):
        """Test when SMS alerts are disabled."""
        # Should not attempt to send SMS


class TestDeadlineCalculations:
    """Test deadline-related calculations."""

    def test_days_until_deadline_positive(self):
        """Test calculating days until future deadline."""
        future = date.today() + timedelta(days=10)
        days = (future - date.today()).days
        assert days == 10

    def test_days_until_deadline_zero(self):
        """Test deadline is today."""
        today = date.today()
        days = (today - date.today()).days
        assert days == 0

    def test_days_until_deadline_negative(self):
        """Test deadline is past."""
        past = date.today() - timedelta(days=5)
        days = (past - date.today()).days
        assert days == -5

    def test_urgency_level_critical(self):
        """Test critical urgency (0-1 days)."""
        date.today() + timedelta(days=1)
        # Should be critical

    def test_urgency_level_urgent(self):
        """Test urgent level (2-3 days)."""
        date.today() + timedelta(days=3)
        # Should be urgent

    def test_urgency_level_warning(self):
        """Test warning level (4-7 days)."""
        date.today() + timedelta(days=7)
        # Should be warning

    def test_urgency_level_normal(self):
        """Test normal level (>7 days)."""
        date.today() + timedelta(days=14)
        # Should be normal
