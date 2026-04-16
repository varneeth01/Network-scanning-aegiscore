"""
AegisCore main entry point.

SAFETY NOTICE: AegisCore is a defensive-only cybersecurity AI project.
It is authorized for use on owner-provided, offline, or allowlisted data only.
It does not generate exploits, attack payloads, malware, or assist in
unauthorized offensive operations.
"""

from .training.train_all import train_all
from .common.logger import get_logger

logger = get_logger(__name__)


def main():
    logger.info("AegisCore — Defensive Cybersecurity AI Suite")
    logger.info("Run 'python -m src.cli --help' for available commands.")


if __name__ == "__main__":
    main()
