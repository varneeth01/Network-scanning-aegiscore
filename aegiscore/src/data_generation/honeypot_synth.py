"""
Synthetic data generator for the Honeypot Attack Classifier.

SAFETY NOTICE: This module generates labeled synthetic training data
for defensive honeypot analysis only. It does not generate real attack
payloads or scanning tools.
"""

import numpy as np
import pandas as pd
from typing import Optional

from ..common.logger import get_logger
from ..common.io import save_dataframe

logger = get_logger(__name__)

LABELS = [
    "benign",
    "recon_scanner",
    "brute_force",
    "bot_activity",
    "suspicious_manual",
    "exploit_like_pattern",
]

LABEL_WEIGHTS = [0.35, 0.20, 0.18, 0.12, 0.10, 0.05]

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "TELNET"]
METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "CONNECT"]
PORTS = [22, 80, 443, 21, 23, 3389, 8080, 8443, 3306, 5432, 27017, 6379]


def _generate_class_samples(label: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = []
    for _ in range(n):
        if label == "benign":
            row = dict(
                source_ip_reputation_score=rng.uniform(0.0, 0.2),
                request_rate=rng.uniform(0.1, 2.0),
                burstiness=rng.uniform(0.0, 0.15),
                path_depth=rng.integers(1, 4),
                path_entropy=rng.uniform(1.0, 2.5),
                user_agent_risk_score=rng.uniform(0.0, 0.15),
                failed_login_count=rng.integers(0, 2),
                unique_username_count=rng.integers(0, 2),
                protocol=rng.choice(["HTTP", "HTTPS", "TCP"]),
                port=rng.choice([80, 443, 8080]),
                method=rng.choice(["GET", "POST"]),
                header_count=rng.integers(5, 15),
                unusual_header_ratio=rng.uniform(0.0, 0.1),
                request_size=rng.integers(200, 2000),
                time_between_requests=rng.uniform(1.0, 10.0),
                number_of_touched_endpoints=rng.integers(1, 5),
                decoy_asset_triggered=0,
                invalid_method_used=0,
                suspicious_path_keywords_count=rng.integers(0, 1),
            )
        elif label == "recon_scanner":
            row = dict(
                source_ip_reputation_score=rng.uniform(0.3, 0.7),
                request_rate=rng.uniform(5.0, 50.0),
                burstiness=rng.uniform(0.2, 0.6),
                path_depth=rng.integers(1, 8),
                path_entropy=rng.uniform(2.5, 4.5),
                user_agent_risk_score=rng.uniform(0.3, 0.7),
                failed_login_count=rng.integers(0, 5),
                unique_username_count=rng.integers(0, 3),
                protocol=rng.choice(PROTOCOLS),
                port=rng.choice(PORTS),
                method=rng.choice(METHODS),
                header_count=rng.integers(2, 10),
                unusual_header_ratio=rng.uniform(0.1, 0.4),
                request_size=rng.integers(50, 500),
                time_between_requests=rng.uniform(0.01, 0.5),
                number_of_touched_endpoints=rng.integers(10, 80),
                decoy_asset_triggered=int(rng.random() < 0.3),
                invalid_method_used=int(rng.random() < 0.2),
                suspicious_path_keywords_count=rng.integers(1, 5),
            )
        elif label == "brute_force":
            row = dict(
                source_ip_reputation_score=rng.uniform(0.4, 0.9),
                request_rate=rng.uniform(10.0, 100.0),
                burstiness=rng.uniform(0.5, 0.9),
                path_depth=rng.integers(1, 3),
                path_entropy=rng.uniform(0.5, 2.0),
                user_agent_risk_score=rng.uniform(0.2, 0.6),
                failed_login_count=rng.integers(20, 500),
                unique_username_count=rng.integers(5, 200),
                protocol=rng.choice(["SSH", "HTTP", "FTP", "TELNET"]),
                port=rng.choice([22, 21, 80, 443, 3389]),
                method=rng.choice(["POST", "GET"]),
                header_count=rng.integers(2, 8),
                unusual_header_ratio=rng.uniform(0.0, 0.2),
                request_size=rng.integers(50, 300),
                time_between_requests=rng.uniform(0.001, 0.2),
                number_of_touched_endpoints=rng.integers(1, 3),
                decoy_asset_triggered=int(rng.random() < 0.1),
                invalid_method_used=int(rng.random() < 0.05),
                suspicious_path_keywords_count=rng.integers(0, 2),
            )
        elif label == "bot_activity":
            row = dict(
                source_ip_reputation_score=rng.uniform(0.3, 0.6),
                request_rate=rng.uniform(2.0, 20.0),
                burstiness=rng.uniform(0.05, 0.3),
                path_depth=rng.integers(1, 5),
                path_entropy=rng.uniform(1.5, 3.5),
                user_agent_risk_score=rng.uniform(0.4, 0.8),
                failed_login_count=rng.integers(0, 5),
                unique_username_count=rng.integers(0, 3),
                protocol=rng.choice(["HTTP", "HTTPS"]),
                port=rng.choice([80, 443, 8080, 8443]),
                method=rng.choice(["GET", "POST", "HEAD"]),
                header_count=rng.integers(3, 12),
                unusual_header_ratio=rng.uniform(0.0, 0.25),
                request_size=rng.integers(100, 1000),
                time_between_requests=rng.uniform(0.5, 3.0),
                number_of_touched_endpoints=rng.integers(3, 20),
                decoy_asset_triggered=int(rng.random() < 0.2),
                invalid_method_used=int(rng.random() < 0.1),
                suspicious_path_keywords_count=rng.integers(0, 3),
            )
        elif label == "suspicious_manual":
            row = dict(
                source_ip_reputation_score=rng.uniform(0.5, 0.85),
                request_rate=rng.uniform(0.1, 5.0),
                burstiness=rng.uniform(0.1, 0.5),
                path_depth=rng.integers(2, 10),
                path_entropy=rng.uniform(2.0, 5.0),
                user_agent_risk_score=rng.uniform(0.3, 0.7),
                failed_login_count=rng.integers(1, 15),
                unique_username_count=rng.integers(1, 10),
                protocol=rng.choice(PROTOCOLS),
                port=rng.choice(PORTS),
                method=rng.choice(METHODS),
                header_count=rng.integers(1, 20),
                unusual_header_ratio=rng.uniform(0.2, 0.6),
                request_size=rng.integers(50, 5000),
                time_between_requests=rng.uniform(2.0, 60.0),
                number_of_touched_endpoints=rng.integers(2, 25),
                decoy_asset_triggered=int(rng.random() < 0.4),
                invalid_method_used=int(rng.random() < 0.3),
                suspicious_path_keywords_count=rng.integers(1, 8),
            )
        else:  # exploit_like_pattern
            row = dict(
                source_ip_reputation_score=rng.uniform(0.6, 1.0),
                request_rate=rng.uniform(0.5, 30.0),
                burstiness=rng.uniform(0.3, 0.9),
                path_depth=rng.integers(3, 12),
                path_entropy=rng.uniform(3.5, 6.0),
                user_agent_risk_score=rng.uniform(0.5, 1.0),
                failed_login_count=rng.integers(5, 50),
                unique_username_count=rng.integers(0, 5),
                protocol=rng.choice(["HTTP", "HTTPS", "TCP"]),
                port=rng.choice(PORTS),
                method=rng.choice(METHODS),
                header_count=rng.integers(1, 30),
                unusual_header_ratio=rng.uniform(0.4, 1.0),
                request_size=rng.integers(200, 65535),
                time_between_requests=rng.uniform(0.01, 5.0),
                number_of_touched_endpoints=rng.integers(1, 15),
                decoy_asset_triggered=int(rng.random() < 0.6),
                invalid_method_used=int(rng.random() < 0.5),
                suspicious_path_keywords_count=rng.integers(3, 15),
            )
        row["label"] = label
        rows.append(row)
    return pd.DataFrame(rows)


def generate_honeypot_data(
    n_samples: int = 8000,
    seed: int = 42,
    save: bool = True,
) -> pd.DataFrame:
    """Generate synthetic honeypot interaction data for model training."""
    rng = np.random.default_rng(seed)
    counts = (np.array(LABEL_WEIGHTS) * n_samples).astype(int)
    counts[-1] = n_samples - counts[:-1].sum()

    frames = []
    for label, count in zip(LABELS, counts):
        frames.append(_generate_class_samples(label, count, rng))

    df = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)

    df["port"] = df["port"].astype(str)

    logger.info(f"Generated {len(df)} honeypot samples")
    logger.info(f"Label distribution:\n{df['label'].value_counts()}")

    if save:
        save_dataframe(df, "honeypot_synthetic")

    return df
