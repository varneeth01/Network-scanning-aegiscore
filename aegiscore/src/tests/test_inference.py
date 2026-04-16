"""Tests for AegisCore inference output structure."""

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
from src.common.utils import ensure_dirs


@pytest.fixture(scope="module", autouse=True)
def train_all_models():
    """Train all models in a temp directory for inference tests."""
    ensure_dirs()
    train_honeypot(df=generate_honeypot_data(n_samples=500, seed=42, save=False), save=True)
    train_malware(df=generate_malware_data(n_samples=500, seed=42, save=False), save=True)
    train_network(df=generate_network_data(n_samples=500, seed=42, save=False), save=True)
    train_posture(df=generate_posture_data(n_samples=500, seed=42, save=False), save=True)


SAMPLE_HONEYPOT = {
    "source_ip_reputation_score": 0.85,
    "request_rate": 80.0,
    "burstiness": 0.75,
    "path_depth": 3,
    "path_entropy": 4.2,
    "user_agent_risk_score": 0.6,
    "failed_login_count": 200,
    "unique_username_count": 80,
    "protocol": "SSH",
    "port": 22,
    "method": "POST",
    "header_count": 4,
    "unusual_header_ratio": 0.1,
    "request_size": 120,
    "time_between_requests": 0.05,
    "number_of_touched_endpoints": 2,
    "decoy_asset_triggered": 0,
    "invalid_method_used": 0,
    "suspicious_path_keywords_count": 1,
}

SAMPLE_MALWARE = {
    "file_size": 524288,
    "entropy": 7.8,
    "extension": ".exe",
    "mime_type": "application/x-dosexec",
    "has_macro": 0,
    "suspicious_string_count": 42,
    "obfuscation_score": 0.88,
    "import_count": 150,
    "suspicious_import_count": 45,
    "packer_indicator": 1,
    "yara_match_count": 4,
    "signer_present": 0,
    "signer_trust_score": 0.1,
    "hash_seen_frequency": 0.01,
    "network_indicator_count": 8,
    "sandbox_behavior_score": 0.92,
    "persistence_indicator_count": 5,
    "script_indicator_score": 0.7,
}

SAMPLE_NETWORK = {
    "src_port": 54321,
    "dst_port": 4444,
    "protocol": "TCP",
    "bytes_sent": 2500000,
    "bytes_received": 512,
    "packets": 3000,
    "duration": 7200.0,
    "direction": "internal_to_external",
    "failed_connections": 0,
    "distinct_destinations": 1,
    "connection_frequency": 0.5,
    "dns_query_volume": 2,
    "tls_version_score": 0.4,
    "uncommon_port_flag": 1,
    "internal_to_internal_flag": 0,
    "external_to_internal_flag": 0,
    "beaconing_score": 0.85,
    "hour_of_day": 3,
    "weekend_flag": 1,
}

SAMPLE_POSTURE = {
    "missing_hsts": 1,
    "missing_csp": 1,
    "missing_x_content_type_options": 1,
    "insecure_cookie_flags": 1,
    "weak_tls": 1,
    "deprecated_protocol_present": 1,
    "admin_interface_exposed": 1,
    "risky_management_port_exposed": 1,
    "open_port_count": 45,
    "legacy_service_count": 6,
    "dependency_vuln_count": 22,
    "secrets_detected": 1,
    "public_bucket_like_flag": 1,
    "authz_gap_indicator": 1,
    "excessive_cors_flag": 1,
    "debug_banner_present": 1,
    "default_credentials_risk": 1,
    "segmentation_risk_score": 0.9,
}


REQUIRED_OUTPUT_KEYS = {"model", "prediction", "confidence", "risk_score", "severity", "reason_codes", "explanation"}


class TestHoneypotInference:
    def test_output_structure(self):
        from src.inference.predict_honeypot import predict_honeypot
        result = predict_honeypot(SAMPLE_HONEYPOT)
        assert REQUIRED_OUTPUT_KEYS.issubset(result.keys())

    def test_confidence_range(self):
        from src.inference.predict_honeypot import predict_honeypot
        result = predict_honeypot(SAMPLE_HONEYPOT)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_risk_score_range(self):
        from src.inference.predict_honeypot import predict_honeypot
        result = predict_honeypot(SAMPLE_HONEYPOT)
        assert 0 <= result["risk_score"] <= 100

    def test_prediction_is_string(self):
        from src.inference.predict_honeypot import predict_honeypot
        result = predict_honeypot(SAMPLE_HONEYPOT)
        assert isinstance(result["prediction"], str)
        assert len(result["prediction"]) > 0

    def test_model_field(self):
        from src.inference.predict_honeypot import predict_honeypot
        result = predict_honeypot(SAMPLE_HONEYPOT)
        assert "honeypot" in result["model"]


class TestMalwareInference:
    def test_output_structure(self):
        from src.inference.predict_malware import predict_malware
        result = predict_malware(SAMPLE_MALWARE)
        assert REQUIRED_OUTPUT_KEYS.issubset(result.keys())

    def test_confidence_range(self):
        from src.inference.predict_malware import predict_malware
        result = predict_malware(SAMPLE_MALWARE)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_model_field(self):
        from src.inference.predict_malware import predict_malware
        result = predict_malware(SAMPLE_MALWARE)
        assert "malware" in result["model"]

    def test_reason_codes_list(self):
        from src.inference.predict_malware import predict_malware
        result = predict_malware(SAMPLE_MALWARE)
        assert isinstance(result["reason_codes"], list)


class TestNetworkInference:
    def test_output_structure(self):
        from src.inference.predict_network import predict_network
        result = predict_network(SAMPLE_NETWORK)
        assert REQUIRED_OUTPUT_KEYS.issubset(result.keys())

    def test_confidence_range(self):
        from src.inference.predict_network import predict_network
        result = predict_network(SAMPLE_NETWORK)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_model_field(self):
        from src.inference.predict_network import predict_network
        result = predict_network(SAMPLE_NETWORK)
        assert "network" in result["model"]


class TestPostureInference:
    def test_output_structure(self):
        from src.inference.predict_posture import predict_posture
        result = predict_posture(SAMPLE_POSTURE)
        assert REQUIRED_OUTPUT_KEYS.issubset(result.keys())

    def test_confidence_range(self):
        from src.inference.predict_posture import predict_posture
        result = predict_posture(SAMPLE_POSTURE)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_model_field(self):
        from src.inference.predict_posture import predict_posture
        result = predict_posture(SAMPLE_POSTURE)
        assert "posture" in result["model"]

    def test_remediation_present(self):
        from src.inference.predict_posture import predict_posture
        result = predict_posture(SAMPLE_POSTURE)
        adj = result.get("rule_adjustments", [])
        assert isinstance(adj, list)
        assert len(adj) > 0
