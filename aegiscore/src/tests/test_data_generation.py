"""Tests for AegisCore synthetic data generators."""

import pytest
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.data_generation.honeypot_synth import generate_honeypot_data, LABELS as HONEYPOT_LABELS
from src.data_generation.malware_synth import generate_malware_data, LABELS as MALWARE_LABELS
from src.data_generation.network_synth import generate_network_data
from src.data_generation.posture_synth import generate_posture_data


class TestHoneypotDataGeneration:
    def test_shape(self):
        df = generate_honeypot_data(n_samples=500, seed=0, save=False)
        assert len(df) == 500

    def test_columns_exist(self):
        df = generate_honeypot_data(n_samples=100, seed=0, save=False)
        assert "label" in df.columns
        assert "request_rate" in df.columns
        assert "failed_login_count" in df.columns

    def test_label_distribution(self):
        df = generate_honeypot_data(n_samples=1000, seed=0, save=False)
        labels = df["label"].unique().tolist()
        for lbl in HONEYPOT_LABELS:
            assert lbl in labels, f"Label '{lbl}' missing from generated data"

    def test_reproducibility(self):
        df1 = generate_honeypot_data(n_samples=200, seed=99, save=False)
        df2 = generate_honeypot_data(n_samples=200, seed=99, save=False)
        assert df1["request_rate"].sum() == pytest.approx(df2["request_rate"].sum())

    def test_no_nulls(self):
        df = generate_honeypot_data(n_samples=200, seed=0, save=False)
        assert df.isnull().sum().sum() == 0


class TestMalwareDataGeneration:
    def test_shape(self):
        df = generate_malware_data(n_samples=300, seed=0, save=False)
        assert len(df) == 300

    def test_columns_exist(self):
        df = generate_malware_data(n_samples=100, seed=0, save=False)
        assert "label" in df.columns
        assert "entropy" in df.columns
        assert "packer_indicator" in df.columns

    def test_label_distribution(self):
        df = generate_malware_data(n_samples=600, seed=0, save=False)
        for lbl in MALWARE_LABELS:
            assert lbl in df["label"].unique(), f"Label '{lbl}' missing"

    def test_entropy_range(self):
        df = generate_malware_data(n_samples=200, seed=0, save=False)
        assert df["entropy"].between(0, 8.0).all()

    def test_binary_fields(self):
        df = generate_malware_data(n_samples=200, seed=0, save=False)
        for col in ["has_macro", "packer_indicator", "signer_present"]:
            assert df[col].isin([0, 1]).all(), f"Column {col} has non-binary values"


class TestNetworkDataGeneration:
    def test_shape(self):
        df = generate_network_data(n_samples=400, seed=0, save=False)
        assert len(df) == 400

    def test_labels(self):
        df = generate_network_data(n_samples=400, seed=0, save=False)
        assert set(df["label"].unique()).issubset({"normal", "anomalous"})

    def test_contamination_rate(self):
        df = generate_network_data(n_samples=1000, contamination=0.1, seed=0, save=False)
        anomaly_rate = (df["label"] == "anomalous").mean()
        assert 0.05 <= anomaly_rate <= 0.15

    def test_columns(self):
        df = generate_network_data(n_samples=100, seed=0, save=False)
        for col in ["bytes_sent", "beaconing_score", "tls_version_score"]:
            assert col in df.columns


class TestPostureDataGeneration:
    def test_shape(self):
        df = generate_posture_data(n_samples=300, seed=0, save=False)
        assert len(df) == 300

    def test_labels(self):
        df = generate_posture_data(n_samples=500, seed=0, save=False)
        assert set(df["label"].unique()).issubset({"low", "medium", "high", "critical"})

    def test_binary_columns(self):
        df = generate_posture_data(n_samples=200, seed=0, save=False)
        for col in ["missing_hsts", "weak_tls", "admin_interface_exposed", "secrets_detected"]:
            assert df[col].isin([0, 1]).all()

    def test_segmentation_risk_range(self):
        df = generate_posture_data(n_samples=200, seed=0, save=False)
        assert df["segmentation_risk_score"].between(0.0, 1.0).all()
