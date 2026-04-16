"""Tests for AegisCore deterministic rule engines."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.rules.honeypot_rules import apply_honeypot_rules
from src.rules.malware_rules import apply_malware_rules
from src.rules.posture_rules import apply_posture_rules, generate_remediation_priorities


class TestHoneypotRules:
    def test_brute_force_rule(self):
        record = {
            "failed_login_count": 100,
            "unique_username_count": 50,
            "burstiness": 0.8,
            "decoy_asset_triggered": 0,
            "suspicious_path_keywords_count": 0,
            "invalid_method_used": 0,
            "source_ip_reputation_score": 0.5,
            "request_rate": 5.0,
        }
        adjustments, severity = apply_honeypot_rules(record)
        assert len(adjustments) > 0
        assert severity in ("high", "critical")

    def test_benign_no_override(self):
        record = {
            "failed_login_count": 1,
            "unique_username_count": 1,
            "burstiness": 0.05,
            "decoy_asset_triggered": 0,
            "suspicious_path_keywords_count": 0,
            "invalid_method_used": 0,
            "source_ip_reputation_score": 0.1,
            "request_rate": 1.0,
        }
        adjustments, severity = apply_honeypot_rules(record)
        assert severity is None

    def test_decoy_critical_rule(self):
        record = {
            "failed_login_count": 0,
            "unique_username_count": 0,
            "burstiness": 0.1,
            "decoy_asset_triggered": 1,
            "suspicious_path_keywords_count": 5,
            "invalid_method_used": 0,
            "source_ip_reputation_score": 0.3,
            "request_rate": 2.0,
        }
        adjustments, severity = apply_honeypot_rules(record)
        assert severity == "critical"


class TestMalwareRules:
    def test_high_entropy_packer_rule(self):
        record = {
            "entropy": 7.5,
            "suspicious_import_count": 10,
            "packer_indicator": 1,
            "obfuscation_score": 0.5,
            "yara_match_count": 0,
            "sandbox_behavior_score": 0.3,
            "has_macro": 0,
            "signer_trust_score": 0.5,
            "persistence_indicator_count": 0,
        }
        adjustments, severity = apply_malware_rules(record)
        assert len(adjustments) > 0
        assert severity in ("high", "critical")

    def test_yara_sandbox_critical(self):
        record = {
            "entropy": 6.0,
            "suspicious_import_count": 3,
            "packer_indicator": 0,
            "obfuscation_score": 0.3,
            "yara_match_count": 5,
            "sandbox_behavior_score": 0.85,
            "has_macro": 0,
            "signer_trust_score": 0.5,
            "persistence_indicator_count": 0,
        }
        adjustments, severity = apply_malware_rules(record)
        assert severity == "critical"

    def test_benign_no_override(self):
        record = {
            "entropy": 4.0,
            "suspicious_import_count": 1,
            "packer_indicator": 0,
            "obfuscation_score": 0.05,
            "yara_match_count": 0,
            "sandbox_behavior_score": 0.1,
            "has_macro": 0,
            "signer_trust_score": 0.9,
            "persistence_indicator_count": 0,
        }
        adjustments, severity = apply_malware_rules(record)
        assert severity is None


class TestPostureRules:
    def test_critical_triple_rule(self):
        record = {
            "missing_hsts": 1,
            "weak_tls": 1,
            "admin_interface_exposed": 1,
            "secrets_detected": 0,
            "default_credentials_risk": 0,
            "risky_management_port_exposed": 0,
            "deprecated_protocol_present": 0,
            "public_bucket_like_flag": 0,
            "authz_gap_indicator": 0,
            "dependency_vuln_count": 0,
        }
        adjustments, severity = apply_posture_rules(record)
        assert severity == "critical"

    def test_secrets_admin_critical(self):
        record = {
            "missing_hsts": 0,
            "weak_tls": 0,
            "admin_interface_exposed": 1,
            "secrets_detected": 1,
            "default_credentials_risk": 0,
            "risky_management_port_exposed": 0,
            "deprecated_protocol_present": 0,
            "public_bucket_like_flag": 0,
            "authz_gap_indicator": 0,
            "dependency_vuln_count": 0,
        }
        adjustments, severity = apply_posture_rules(record)
        assert severity == "critical"

    def test_no_issues_no_override(self):
        record = {k: 0 for k in [
            "missing_hsts", "weak_tls", "admin_interface_exposed", "secrets_detected",
            "default_credentials_risk", "risky_management_port_exposed", "deprecated_protocol_present",
            "public_bucket_like_flag", "authz_gap_indicator", "dependency_vuln_count",
        ]}
        adjustments, severity = apply_posture_rules(record)
        assert severity is None

    def test_remediation_list_non_empty(self):
        record = {
            "missing_hsts": 1, "weak_tls": 1, "admin_interface_exposed": 1,
            "secrets_detected": 1, "default_credentials_risk": 1, "dependency_vuln_count": 15,
            "risky_management_port_exposed": 1, "deprecated_protocol_present": 1,
            "public_bucket_like_flag": 1, "authz_gap_indicator": 1, "excessive_cors_flag": 1,
            "debug_banner_present": 1, "missing_csp": 1, "missing_x_content_type_options": 1,
            "insecure_cookie_flags": 1,
        }
        remediations = generate_remediation_priorities(record)
        assert isinstance(remediations, list)
        assert len(remediations) > 3

    def test_remediation_empty_no_issues(self):
        record = {k: 0 for k in [
            "missing_hsts", "weak_tls", "admin_interface_exposed", "secrets_detected",
            "default_credentials_risk", "risky_management_port_exposed", "deprecated_protocol_present",
            "public_bucket_like_flag", "authz_gap_indicator", "excessive_cors_flag",
            "debug_banner_present", "missing_csp", "missing_x_content_type_options",
            "insecure_cookie_flags", "dependency_vuln_count",
        ]}
        remediations = generate_remediation_priorities(record)
        assert "[INFO]" in remediations[0]
