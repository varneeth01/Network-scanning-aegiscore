"""
Synthetic data generator for the Network Anomaly Detection model.

SAFETY NOTICE: This module generates synthetic authorized telemetry data
for defensive anomaly detection. It does not generate real network attack
traffic or assist with unauthorized scanning.
"""

import numpy as np
import pandas as pd
from typing import Optional

from ..common.logger import get_logger
from ..common.io import save_dataframe

logger = get_logger(__name__)

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS"]
DIRECTIONS = ["internal_to_internal", "internal_to_external", "external_to_internal"]


def _gen_normal(n: int, rng: np.random.Generator) -> pd.DataFrame:
    return pd.DataFrame({
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([80, 443, 8080, 22, 53, 25, 587, 3306], n),
        "protocol": rng.choice(["TCP", "UDP", "HTTP", "HTTPS", "TLS"], n),
        "bytes_sent": rng.integers(64, 50_000, n),
        "bytes_received": rng.integers(64, 200_000, n),
        "packets": rng.integers(1, 500, n),
        "duration": rng.uniform(0.01, 30.0, n),
        "direction": rng.choice(DIRECTIONS, n, p=[0.4, 0.5, 0.1]),
        "failed_connections": rng.integers(0, 3, n),
        "distinct_destinations": rng.integers(1, 10, n),
        "connection_frequency": rng.uniform(0.1, 10.0, n),
        "dns_query_volume": rng.integers(0, 20, n),
        "tls_version_score": rng.uniform(0.7, 1.0, n),
        "uncommon_port_flag": (rng.random(n) < 0.05).astype(int),
        "internal_to_internal_flag": (rng.random(n) < 0.4).astype(int),
        "external_to_internal_flag": (rng.random(n) < 0.1).astype(int),
        "beaconing_score": rng.uniform(0.0, 0.1, n),
        "hour_of_day": rng.integers(8, 19, n),
        "weekend_flag": (rng.random(n) < 0.15).astype(int),
        "label": "normal",
    })


def _gen_anomalous(n: int, rng: np.random.Generator) -> pd.DataFrame:
    anomaly_types = ["beaconing", "data_exfil", "lateral_move", "port_scan", "dns_tunnel"]
    atype = rng.choice(anomaly_types, n)
    rows = []
    for t in atype:
        if t == "beaconing":
            r = dict(
                src_port=rng.integers(1024, 65535),
                dst_port=rng.integers(1, 65535),
                protocol=rng.choice(["TCP", "UDP"]),
                bytes_sent=rng.integers(50, 500),
                bytes_received=rng.integers(50, 300),
                packets=rng.integers(1, 20),
                duration=rng.uniform(0.001, 0.5),
                direction="internal_to_external",
                failed_connections=rng.integers(0, 2),
                distinct_destinations=rng.integers(1, 3),
                connection_frequency=rng.uniform(50.0, 300.0),
                dns_query_volume=rng.integers(0, 5),
                tls_version_score=rng.uniform(0.3, 0.7),
                uncommon_port_flag=int(rng.random() < 0.7),
                internal_to_internal_flag=0,
                external_to_internal_flag=0,
                beaconing_score=rng.uniform(0.7, 1.0),
                hour_of_day=rng.integers(0, 24),
                weekend_flag=int(rng.random() < 0.5),
            )
        elif t == "data_exfil":
            r = dict(
                src_port=rng.integers(1024, 65535),
                dst_port=rng.integers(1, 65535),
                protocol=rng.choice(["TCP", "HTTPS"]),
                bytes_sent=rng.integers(5_000_000, 500_000_000),
                bytes_received=rng.integers(50, 1000),
                packets=rng.integers(500, 10000),
                duration=rng.uniform(60.0, 3600.0),
                direction="internal_to_external",
                failed_connections=rng.integers(0, 5),
                distinct_destinations=rng.integers(1, 5),
                connection_frequency=rng.uniform(0.01, 2.0),
                dns_query_volume=rng.integers(0, 30),
                tls_version_score=rng.uniform(0.4, 0.9),
                uncommon_port_flag=int(rng.random() < 0.5),
                internal_to_internal_flag=0,
                external_to_internal_flag=0,
                beaconing_score=rng.uniform(0.0, 0.4),
                hour_of_day=rng.integers(0, 7),
                weekend_flag=int(rng.random() < 0.5),
            )
        elif t == "lateral_move":
            r = dict(
                src_port=rng.integers(1024, 65535),
                dst_port=rng.choice([22, 3389, 445, 135, 5985, 5986]),
                protocol=rng.choice(["TCP"]),
                bytes_sent=rng.integers(1000, 100_000),
                bytes_received=rng.integers(1000, 100_000),
                packets=rng.integers(20, 500),
                duration=rng.uniform(1.0, 300.0),
                direction="internal_to_internal",
                failed_connections=rng.integers(5, 50),
                distinct_destinations=rng.integers(5, 50),
                connection_frequency=rng.uniform(5.0, 50.0),
                dns_query_volume=rng.integers(5, 50),
                tls_version_score=rng.uniform(0.4, 0.8),
                uncommon_port_flag=int(rng.random() < 0.4),
                internal_to_internal_flag=1,
                external_to_internal_flag=0,
                beaconing_score=rng.uniform(0.1, 0.5),
                hour_of_day=rng.integers(0, 24),
                weekend_flag=int(rng.random() < 0.5),
            )
        elif t == "port_scan":
            r = dict(
                src_port=rng.integers(1024, 65535),
                dst_port=rng.integers(1, 65535),
                protocol=rng.choice(["TCP", "UDP", "ICMP"]),
                bytes_sent=rng.integers(40, 200),
                bytes_received=rng.integers(0, 100),
                packets=rng.integers(1, 5),
                duration=rng.uniform(0.0001, 0.1),
                direction=rng.choice(["internal_to_internal", "external_to_internal"]),
                failed_connections=rng.integers(20, 500),
                distinct_destinations=rng.integers(50, 500),
                connection_frequency=rng.uniform(100.0, 1000.0),
                dns_query_volume=rng.integers(0, 5),
                tls_version_score=rng.uniform(0.0, 0.5),
                uncommon_port_flag=1,
                internal_to_internal_flag=0,
                external_to_internal_flag=1,
                beaconing_score=rng.uniform(0.0, 0.3),
                hour_of_day=rng.integers(0, 24),
                weekend_flag=int(rng.random() < 0.5),
            )
        else:  # dns_tunnel
            r = dict(
                src_port=rng.integers(1024, 65535),
                dst_port=53,
                protocol="DNS",
                bytes_sent=rng.integers(500, 50_000),
                bytes_received=rng.integers(200, 30_000),
                packets=rng.integers(20, 500),
                duration=rng.uniform(1.0, 120.0),
                direction=rng.choice(["internal_to_external", "internal_to_internal"]),
                failed_connections=rng.integers(0, 3),
                distinct_destinations=rng.integers(1, 5),
                connection_frequency=rng.uniform(10.0, 100.0),
                dns_query_volume=rng.integers(200, 5000),
                tls_version_score=rng.uniform(0.0, 0.3),
                uncommon_port_flag=0,
                internal_to_internal_flag=0,
                external_to_internal_flag=0,
                beaconing_score=rng.uniform(0.4, 0.9),
                hour_of_day=rng.integers(0, 24),
                weekend_flag=int(rng.random() < 0.5),
            )
        r["label"] = "anomalous"
        rows.append(r)
    return pd.DataFrame(rows)


def generate_network_data(
    n_samples: int = 8000,
    contamination: float = 0.08,
    seed: int = 42,
    save: bool = True,
) -> pd.DataFrame:
    """Generate synthetic network telemetry for anomaly detection."""
    rng = np.random.default_rng(seed)
    n_anomalous = max(1, int(n_samples * contamination))
    n_normal = n_samples - n_anomalous

    df = pd.concat([
        _gen_normal(n_normal, rng),
        _gen_anomalous(n_anomalous, rng),
    ], ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)

    logger.info(f"Generated {len(df)} network samples ({n_anomalous} anomalous, {n_normal} normal)")
    logger.info(f"Label distribution:\n{df['label'].value_counts()}")

    if save:
        save_dataframe(df, "network_synthetic")

    return df
