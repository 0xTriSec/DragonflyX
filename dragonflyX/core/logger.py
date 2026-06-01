"""Logging configuration using loguru."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

__all__ = ["logger", "setup_logger"]


def setup_logger(debug: bool = False) -> None:
    """
    Configure loguru logger with console and file sinks.

    Args:
        debug: If True, set log level to DEBUG. Otherwise INFO.
    """
    logger.remove()  # Remove default handler

    # Console sink with colorized output
    logger.add(
        sys.stderr,
        level="DEBUG" if debug else "INFO",
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
        colorize=True,
    )

    # Create log directory
    log_dir = Path.home() / ".dragonflyX" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Rotating file sink for plain text logs
    logger.add(
        log_dir / "dragonflyx_{time:YYYY-MM-DD}.log",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        enqueue=True,
    )

    # JSON audit sink for structured logs
    logger.add(
        log_dir / "dragonflyx_{time:YYYY-MM-DD}.json",
        level="DEBUG",
        serialize=True,
        rotation="1 day",
        retention="30 days",
        enqueue=True,
    )
