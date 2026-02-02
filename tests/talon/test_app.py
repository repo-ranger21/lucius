"""Tests for Talon Flask application."""

import pytest
from flask import Flask

from talon.app import create_app
from talon.extensions import db


@pytest.fixture
def app():
    """Create test application."""
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        }
    )

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestAppFactory:
    """Tests for app factory."""

    def test_create_app(self):
        """Test app creation."""
        app = create_app()
        assert isinstance(app, Flask)

    def test_app_config(self, app):
        """Test app configuration."""
        assert app.config["TESTING"] is True


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self, client):
        """Test health check returns OK."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"


class TestScansAPI:
    """Tests for scans API endpoints."""

    def test_list_scans_empty(self, client):
        """Test listing scans when empty."""
        response = client.get("/api/v1/scans/")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_create_scan(self, client):
        """Test creating a new scan."""
        response = client.post(
            "/api/v1/scans/",
            json={
                "project_name": "test-project",
                "dependencies": [{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}],
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        assert "id" in data
        assert data["project_name"] == "test-project"

    def test_get_scan(self, client):
        """Test getting a specific scan."""
        # Create scan first
        create_response = client.post(
            "/api/v1/scans/", json={"project_name": "test", "dependencies": []}
        )
        scan_id = create_response.get_json()["id"]

        # Get scan
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200

    def test_get_scan_not_found(self, client):
        """Test getting non-existent scan."""
        response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404


class TestVulnerabilitiesAPI:
    """Tests for vulnerabilities API endpoints."""

    def test_list_vulnerabilities_empty(self, client):
        """Test listing vulnerabilities when empty."""
        response = client.get("/api/v1/vulnerabilities/")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_search_vulnerabilities(self, client):
        """Test searching vulnerabilities."""
        response = client.get("/api/v1/vulnerabilities/search?keyword=test")
        assert response.status_code == 200


class TestNotificationsAPI:
    """Tests for notifications API endpoints."""

    def test_list_notifications_empty(self, client):
        """Test listing notifications when empty."""
        response = client.get("/api/v1/notifications/")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_create_notification(self, client):
        """Test creating a notification."""
        response = client.post(
            "/api/v1/notifications/",
            json={
                "type": "email",
                "recipient": "test@example.com",
                "subject": "Test",
                "message": "Test message",
            },
        )
        assert response.status_code == 201
