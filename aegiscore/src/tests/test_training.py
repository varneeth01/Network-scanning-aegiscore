"""Tests for AegisCore model training pipelines."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.data_generation.honeypot_synth import generate_honeypot_data
from src.data_generation.malware_synth import generate_malware_data
from src.data_generation.network_synth import generate_network_data
from src.data_generation.posture_synth import generate_posture_data
from src.training.train_honeypot import train_honeypot
from src.training.train_malware import train_malware
from src.training.train_network import train_network
from src.training.train_posture import train_posture


@pytest.fixture(scope="module")
def honeypot_df():
    return generate_honeypot_data(n_samples=400, seed=42, save=False)


@pytest.fixture(scope="module")
def malware_df():
    return generate_malware_data(n_samples=400, seed=42, save=False)


@pytest.fixture(scope="module")
def network_df():
    return generate_network_data(n_samples=400, seed=42, save=False)


@pytest.fixture(scope="module")
def posture_df():
    return generate_posture_data(n_samples=400, seed=42, save=False)


class TestHoneypotTraining:
    def test_training_runs(self, honeypot_df):
        metrics = train_honeypot(df=honeypot_df, save=False)
        assert metrics is not None

    def test_f1_returned(self, honeypot_df):
        metrics = train_honeypot(df=honeypot_df, save=False)
        assert "f1_macro" in metrics
        assert isinstance(metrics["f1_macro"], float)

    def test_f1_nontrivial(self, honeypot_df):
        metrics = train_honeypot(df=honeypot_df, save=False)
        assert metrics["f1_macro"] > 0.3


class TestMalwareTraining:
    def test_training_runs(self, malware_df):
        metrics = train_malware(df=malware_df, save=False)
        assert metrics is not None

    def test_f1_returned(self, malware_df):
        metrics = train_malware(df=malware_df, save=False)
        assert "f1_macro" in metrics

    def test_f1_nontrivial(self, malware_df):
        metrics = train_malware(df=malware_df, save=False)
        assert metrics["f1_macro"] > 0.4


class TestNetworkTraining:
    def test_training_runs(self, network_df):
        metrics = train_network(df=network_df, save=False)
        assert metrics is not None

    def test_f1_returned(self, network_df):
        metrics = train_network(df=network_df, save=False)
        assert "f1_macro" in metrics


class TestPostureTraining:
    def test_training_runs(self, posture_df):
        metrics = train_posture(df=posture_df, save=False)
        assert metrics is not None

    def test_f1_returned(self, posture_df):
        metrics = train_posture(df=posture_df, save=False)
        assert "f1_macro" in metrics

    def test_f1_nontrivial(self, posture_df):
        metrics = train_posture(df=posture_df, save=False)
        assert metrics["f1_macro"] > 0.3
