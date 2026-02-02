"""Flask application factory."""

from typing import Any

from flask import Flask, request
from flask_cors import CORS

from shared.logging import get_logger
from talon.api import api_blueprint
from talon.config import config
from talon.extensions import db, migrate
from talon.middleware import BOLAMiddleware

logger = get_logger(__name__)


def create_app(config_override: dict[str, Any] | None = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_override: Optional configuration overrides

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Load configuration
    app.config["SECRET_KEY"] = config.secret_key
    app.config["DEBUG"] = config.debug
    app.config["SQLALCHEMY_DATABASE_URI"] = config.database.url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Apply overrides
    if config_override:
        app.config.update(config_override)

    # Configure SQLAlchemy engine options
    engine_options = app.config.get(
        "SQLALCHEMY_ENGINE_OPTIONS",
        {
            "pool_size": config.database.pool_size,
            "pool_recycle": config.database.pool_recycle,
            "echo": config.database.echo,
        },
    )
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if isinstance(db_uri, str) and db_uri.startswith("sqlite"):
        engine_options.pop("pool_size", None)
        engine_options.pop("pool_recycle", None)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options

    # Initialize extensions
    CORS(app)
    db.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")

    register_bola_middleware(app)

    # Register health check endpoint
    @app.route("/health")
    def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "talon"}

    # Register error handlers
    register_error_handlers(app)

    logger.info("Talon application initialized")

    return app


def register_bola_middleware(app: Flask) -> None:
    """Register BOLA middleware if dependencies are configured."""
    ledger = app.config.get("BOLA_LEDGER")
    ownership_store = app.config.get("BOLA_OWNERSHIP_STORE")
    audit = app.config.get("BOLA_AUDIT")

    if not (ledger and ownership_store and audit):
        logger.warning("BOLA middleware not configured; skipping registration")
        return

    bola_gate = BOLAMiddleware(ledger, ownership_store, audit)

    @app.before_request
    def _bola_gate() -> None:
        object_id = None
        if request.view_args:
            object_id = request.view_args.get("object_id")
        if not object_id:
            object_id = request.args.get("object_id")

        if not object_id:
            return

        if not hasattr(request, "context"):
            request.context = {
                "legacy_nn_ip_user_id": request.headers.get("X-Legacy-User-Id"),
                "gs_global_tenant_id": request.headers.get("X-Global-Tenant-Id"),
            }

        bola_gate(request, object_id)


def register_error_handlers(app: Flask) -> None:
    """Register error handlers for the application."""

    @app.errorhandler(400)
    def bad_request(error):
        return {"error": "Bad Request", "message": str(error)}, 400

    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not Found", "message": str(error)}, 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return {"error": "Internal Server Error", "message": "An unexpected error occurred"}, 500
