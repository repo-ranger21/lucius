"""Centralized logging configuration using structlog."""

import logging
import os
import sys

import structlog


def setup_logging(level: str | None = None) -> None:
    """
    Set up structured logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
    """
    log_level: str = level if level is not None else (os.getenv("LOG_LEVEL") or "INFO")

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            (
                structlog.dev.ConsoleRenderer()
                if _is_development()
                else structlog.processors.JSONRenderer()
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, log_level.upper())),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _is_development() -> bool:
    """Check if running in development mode."""
    return os.getenv("FLASK_ENV") == "development" or os.getenv("DEBUG", "").lower() == "true"


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a logger instance for the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


# Initialize logging on import
setup_logging()
