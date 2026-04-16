"""
Human-readable explanation engine for AegisCore model predictions.

Maps feature names and values to defensive reason codes and natural language explanations.
"""

from typing import Any, Dict, List, Optional, Tuple

from ..common.logger import get_logger

logger = get_logger(__name__)

HONEYPOT_REASON_CODES = {
    "burstiness": ("HIGH_REQUEST_BURST", "Very high request burst rate detected"),
    "failed_login_count": ("HIGH_FAILED_LOGINS", "Unusually high number of failed login attempts"),
    "unique_username_count": ("HIGH_USERNAME_DIVERSITY", "Many distinct usernames attempted (brute-force indicator)"),
    "suspicious_path_keywords_count": ("SUSPICIOUS_PATH_KEYWORDS", "Request paths contain known suspicious keywords"),
    "decoy_asset_triggered": ("DECOY_ASSET_TRIGGERED", "Honeypot decoy asset was accessed"),
    "invalid_method_used": ("INVALID_HTTP_METHOD", "Unusual or invalid HTTP method used"),
    "path_entropy": ("HIGH_PATH_ENTROPY", "Unusually high entropy in request paths"),
    "source_ip_reputation_score": ("POOR_IP_REPUTATION", "Source IP has a high threat reputation score"),
    "user_agent_risk_score": ("RISKY_USER_AGENT", "User agent string matches known malicious patterns"),
    "unusual_header_ratio": ("UNUSUAL_HEADERS", "High proportion of non-standard HTTP headers detected"),
    "number_of_touched_endpoints": ("BROAD_ENDPOINT_SWEEP", "Large number of distinct endpoints probed"),
    "request_rate": ("HIGH_REQUEST_RATE", "Request rate far exceeds normal behavior"),
}

MALWARE_REASON_CODES = {
    "entropy": ("HIGH_FILE_ENTROPY", "Very high file entropy suggests encryption or packing"),
    "suspicious_import_count": ("SUSPICIOUS_IMPORTS", "Multiple suspicious API imports detected"),
    "packer_indicator": ("PACKER_INDICATOR", "Packing or compression artifact detected"),
    "obfuscation_score": ("HIGH_OBFUSCATION", "File contains obfuscation markers"),
    "has_macro": ("MACRO_PRESENT", "Document contains embedded macros"),
    "yara_match_count": ("YARA_RULE_MATCH", "One or more YARA rules matched"),
    "sandbox_behavior_score": ("SUSPICIOUS_SANDBOX_BEHAVIOR", "Anomalous behavior observed in sandbox analysis"),
    "persistence_indicator_count": ("PERSISTENCE_INDICATORS", "Persistence mechanism indicators found"),
    "network_indicator_count": ("NETWORK_INDICATORS", "Network communication indicators detected"),
    "script_indicator_score": ("SCRIPT_INDICATORS", "Script-based execution indicators present"),
    "signer_trust_score": ("LOW_SIGNER_TRUST", "File has no trusted digital signature"),
    "hash_seen_frequency": ("RARE_FILE_HASH", "File hash has very low frequency in known-good corpus"),
}

NETWORK_REASON_CODES = {
    "beaconing_score": ("BEACONING_PATTERN", "Traffic shows periodic beaconing pattern (C2 indicator)"),
    "connection_frequency": ("HIGH_CONNECTION_FREQUENCY", "Abnormally high connection frequency"),
    "bytes_sent": ("LARGE_DATA_TRANSFER", "Unusually large outbound data volume (possible exfiltration)"),
    "dns_query_volume": ("HIGH_DNS_VOLUME", "Abnormal DNS query volume (possible DNS tunneling)"),
    "failed_connections": ("HIGH_FAILED_CONNECTIONS", "Many failed connections (possible scanning)"),
    "distinct_destinations": ("BROAD_DESTINATION_SWEEP", "Traffic to many distinct destinations"),
    "uncommon_port_flag": ("UNCOMMON_PORT", "Traffic on non-standard or uncommon port"),
    "tls_version_score": ("WEAK_TLS_VERSION", "TLS version is outdated or weak"),
    "duration": ("UNUSUAL_DURATION", "Connection duration is highly anomalous"),
}

POSTURE_REASON_CODES = {
    "missing_hsts": ("MISSING_SECURITY_HEADERS", "HSTS header is absent — HTTPS downgrade risk"),
    "missing_csp": ("MISSING_CSP", "Content Security Policy not configured"),
    "weak_tls": ("WEAK_TLS", "Weak TLS version or cipher suites in use"),
    "admin_interface_exposed": ("ADMIN_SURFACE_EXPOSED", "Administrative interface is publicly accessible"),
    "secrets_detected": ("SECRETS_DETECTED", "Possible secrets or credentials found in configuration"),
    "default_credentials_risk": ("DEFAULT_CREDENTIALS", "Default credentials may be in use"),
    "deprecated_protocol_present": ("DEPRECATED_PROTOCOL", "Deprecated or insecure protocol is active"),
    "risky_management_port_exposed": ("MANAGEMENT_PORT_EXPOSED", "Risky management port is exposed externally"),
    "public_bucket_like_flag": ("PUBLIC_STORAGE_EXPOSURE", "Storage bucket or similar resource appears public"),
    "authz_gap_indicator": ("AUTHZ_GAP", "Authorization gap or missing access controls detected"),
    "excessive_cors_flag": ("EXCESSIVE_CORS", "CORS policy is overly permissive"),
    "debug_banner_present": ("DEBUG_BANNER", "Debug or version banner is publicly visible"),
    "dependency_vuln_count": ("VULNERABLE_DEPENDENCIES", "Known vulnerable dependencies detected"),
    "segmentation_risk_score": ("POOR_SEGMENTATION", "Network segmentation risk is elevated"),
}

ALL_REASON_CODES = {
    **HONEYPOT_REASON_CODES,
    **MALWARE_REASON_CODES,
    **NETWORK_REASON_CODES,
    **POSTURE_REASON_CODES,
}

EXPLANATION_TEMPLATES = {
    "benign": "The sample exhibits normal behavior with no significant threat indicators.",
    "recon_scanner": "The activity pattern matches automated reconnaissance or scanning behavior.",
    "brute_force": "The event shows repeated authentication attempts consistent with brute-force activity.",
    "bot_activity": "The traffic pattern is consistent with automated bot-like behavior.",
    "suspicious_manual": "The activity appears to be manual and targeted, with multiple suspicious indicators.",
    "exploit_like_pattern": "The request pattern closely resembles known exploit delivery signatures.",
    "likely_benign": "File metadata does not indicate malicious intent.",
    "suspicious": "Several metadata indicators suggest elevated risk; further review is recommended.",
    "likely_malicious": "Multiple strong indicators of malicious intent detected in file metadata.",
    "normal": "Network flow is within expected parameters.",
    "anomalous": "Network flow deviates significantly from baseline; anomaly detected.",
    "low": "Security posture shows minor gaps with limited exposure risk.",
    "medium": "Several security misconfigurations detected; remediation is recommended.",
    "high": "Significant security weaknesses present; prompt remediation required.",
    "critical": "Critical security exposure detected; immediate remediation is required.",
}


def get_reason_codes_for_model(model_name: str) -> Dict[str, Tuple[str, str]]:
    mapping = {
        "honeypot": HONEYPOT_REASON_CODES,
        "malware": MALWARE_REASON_CODES,
        "network": NETWORK_REASON_CODES,
        "posture": POSTURE_REASON_CODES,
    }
    return mapping.get(model_name, {})


def build_reason_codes(
    top_features: List[Tuple[str, float]],
    model_name: str,
    record: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Map top features to human-readable reason codes."""
    reason_map = get_reason_codes_for_model(model_name)
    codes = []

    for feat_name, importance in top_features:
        clean_name = feat_name.split("__")[-1] if "__" in feat_name else feat_name

        for key, (code, _) in reason_map.items():
            if key in clean_name:
                if record is not None:
                    val = record.get(key, None)
                    if val is not None and val == 0:
                        continue
                if code not in codes:
                    codes.append(code)
                break

    return codes[:3] if len(codes) >= 3 else codes


def build_explanation(
    prediction: str,
    reason_codes: List[str],
    model_name: str,
) -> str:
    """Generate a human-readable explanation string."""
    base = EXPLANATION_TEMPLATES.get(prediction, "The model flagged this sample based on learned patterns.")
    reason_map = get_reason_codes_for_model(model_name)
    code_to_desc = {v[0]: v[1] for v in reason_map.values()}

    details = []
    for code in reason_codes:
        desc = code_to_desc.get(code)
        if desc:
            details.append(desc)

    if details:
        return base + " Key indicators: " + "; ".join(details) + "."
    return base


from typing import Dict, Any
