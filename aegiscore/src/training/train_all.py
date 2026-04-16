"""
Train all AegisCore models in sequence.

SAFETY NOTICE: Trains defensive ML models only. No offensive capabilities
are introduced by this pipeline.
"""

from ..common.logger import get_logger
from ..common.utils import ensure_dirs
from .train_honeypot import train_honeypot
from .train_malware import train_malware
from .train_network import train_network
from .train_posture import train_posture

logger = get_logger(__name__)


def train_all() -> dict:
    """Run the full AegisCore training pipeline."""
    ensure_dirs()
    results = {}

    logger.info("=" * 60)
    logger.info("AegisCore — Full Training Pipeline")
    logger.info("DEFENSIVE-ONLY | Authorized data only")
    logger.info("=" * 60)

    logger.info("\n[1/4] Training Honeypot Attack Classifier...")
    try:
        results["honeypot"] = train_honeypot()
        logger.info("Honeypot classifier training complete.")
    except Exception as e:
        logger.error(f"Honeypot training failed: {e}")
        results["honeypot"] = {"error": str(e)}

    logger.info("\n[2/4] Training Malware Triage Classifier...")
    try:
        results["malware"] = train_malware()
        logger.info("Malware triage training complete.")
    except Exception as e:
        logger.error(f"Malware training failed: {e}")
        results["malware"] = {"error": str(e)}

    logger.info("\n[3/4] Training Network Anomaly Detector...")
    try:
        results["network"] = train_network()
        logger.info("Network anomaly detection training complete.")
    except Exception as e:
        logger.error(f"Network training failed: {e}")
        results["network"] = {"error": str(e)}

    logger.info("\n[4/4] Training Security Posture Risk Model...")
    try:
        results["posture"] = train_posture()
        logger.info("Posture risk model training complete.")
    except Exception as e:
        logger.error(f"Posture training failed: {e}")
        results["posture"] = {"error": str(e)}

    logger.info("\n" + "=" * 60)
    logger.info("AegisCore training pipeline complete.")
    logger.info("=" * 60)

    return results


if __name__ == "__main__":
    train_all()
