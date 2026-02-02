"""Notifications API endpoints."""

from uuid import UUID

from flask import current_app, request
from flask_restx import Namespace, Resource, fields

from shared.logging import get_logger
from talon.extensions import db
from talon.models import Notification
from talon.services.notification_service import NotificationService

logger = get_logger(__name__)

notifications_ns = Namespace("notifications", description="Notification management")

# API Models
notification_input = notifications_ns.model(
    "NotificationInput",
    {
        "notification_type": fields.String(
            required=True, description="Type (alert, report, reminder)"
        ),
        "channel": fields.String(required=True, description="Channel (sms, email, slack)"),
        "recipient": fields.String(required=True, description="Recipient address/number"),
        "subject": fields.String(description="Notification subject"),
        "body": fields.String(required=True, description="Notification body"),
        "metadata": fields.Raw(description="Additional metadata"),
    },
)

notification_output = notifications_ns.model(
    "NotificationOutput",
    {
        "id": fields.String(description="Notification ID"),
        "notification_type": fields.String(description="Notification type"),
        "channel": fields.String(description="Delivery channel"),
        "recipient": fields.String(description="Recipient"),
        "subject": fields.String(description="Subject"),
        "body": fields.String(description="Body"),
        "status": fields.String(description="Status (pending, sent, failed)"),
        "sent_at": fields.DateTime(description="Sent timestamp"),
        "error_message": fields.String(description="Error message if failed"),
        "created_at": fields.DateTime(description="Creation timestamp"),
    },
)


@notifications_ns.route("/")
class NotificationList(Resource):
    """Notification collection resource."""

    @notifications_ns.doc("list_notifications")
    @notifications_ns.param("status", "Filter by status (pending, sent, failed)")
    @notifications_ns.param("channel", "Filter by channel")
    @notifications_ns.param("limit", "Maximum results", type=int, default=50)
    @notifications_ns.marshal_list_with(notification_output)
    def get(self):
        """List notifications with filtering."""
        status = request.args.get("status")
        channel = request.args.get("channel")
        limit = request.args.get("limit", 50, type=int)

        query = Notification.query

        if status:
            query = query.filter(Notification.status == status)
        if channel:
            query = query.filter(Notification.channel == channel)

        query = query.order_by(Notification.created_at.desc())
        notifications = query.limit(limit).all()

        return [n.to_dict() for n in notifications]

    @notifications_ns.doc("create_notification")
    @notifications_ns.expect(notification_input)
    @notifications_ns.marshal_with(notification_output, code=201)
    def post(self):
        """Create and send a notification."""
        data = request.json

        notification_type = data.get("notification_type") or data.get("type") or "alert"
        channel = data.get("channel") or data.get("type") or "email"
        body = data.get("body") or data.get("message") or ""

        notification_service = NotificationService()
        notification = notification_service.create_notification(
            notification_type=notification_type,
            channel=channel,
            recipient=data["recipient"],
            subject=data.get("subject"),
            body=body,
            metadata=data.get("metadata", {}),
        )

        # Queue for async sending (skip during tests)
        if not current_app.testing:
            notification_service.queue_notification(notification)

        logger.info(f"Created notification: {notification.id}")
        return notification.to_dict(), 201


@notifications_ns.route("/<string:notification_id>")
@notifications_ns.param("notification_id", "Notification identifier")
class NotificationResource(Resource):
    """Single notification resource."""

    @notifications_ns.doc("get_notification")
    @notifications_ns.marshal_with(notification_output)
    def get(self, notification_id: str):
        """Get notification details."""
        try:
            uuid_id = UUID(notification_id)
        except ValueError:
            notifications_ns.abort(400, "Invalid notification ID format")

        notification = Notification.query.get(uuid_id)
        if not notification:
            notifications_ns.abort(404, "Notification not found")

        return notification.to_dict()


@notifications_ns.route("/<string:notification_id>/resend")
@notifications_ns.param("notification_id", "Notification identifier")
class NotificationResend(Resource):
    """Resend notification resource."""

    @notifications_ns.doc("resend_notification")
    def post(self, notification_id: str):
        """Resend a failed notification."""
        try:
            uuid_id = UUID(notification_id)
        except ValueError:
            notifications_ns.abort(400, "Invalid notification ID format")

        notification = Notification.query.get(uuid_id)
        if not notification:
            notifications_ns.abort(404, "Notification not found")

        notification_service = NotificationService()
        notification_service.queue_notification(notification)

        logger.info(f"Queued notification for resend: {notification_id}")
        return {"message": "Notification queued for resend"}


@notifications_ns.route("/send-alert")
class SendAlert(Resource):
    """Send alert notification."""

    @notifications_ns.doc("send_alert")
    @notifications_ns.expect(
        notifications_ns.model(
            "AlertInput",
            {
                "title": fields.String(required=True, description="Alert title"),
                "message": fields.String(required=True, description="Alert message"),
                "severity": fields.String(description="Alert severity", default="high"),
                "channels": fields.List(fields.String, description="Channels to send to"),
                "recipients": fields.Raw(description="Recipients by channel"),
            },
        )
    )
    def post(self):
        """Send an alert to multiple channels."""
        data = request.json

        notification_service = NotificationService()
        results = notification_service.send_alert(
            title=data["title"],
            message=data["message"],
            severity=data.get("severity", "high"),
            channels=data.get("channels", ["slack"]),
            recipients=data.get("recipients", {}),
        )

        return {
            "message": "Alert sent",
            "results": results,
        }


@notifications_ns.route("/stats")
class NotificationStats(Resource):
    """Notification statistics resource."""

    @notifications_ns.doc("get_notification_stats")
    def get(self):
        """Get notification statistics."""
        from sqlalchemy import func

        total = Notification.query.count()

        by_status = (
            db.session.query(Notification.status, func.count(Notification.id).label("count"))
            .group_by(Notification.status)
            .all()
        )

        by_channel = (
            db.session.query(Notification.channel, func.count(Notification.id).label("count"))
            .group_by(Notification.channel)
            .all()
        )

        return {
            "total_notifications": total,
            "by_status": dict(by_status),
            "by_channel": dict(by_channel),
        }
