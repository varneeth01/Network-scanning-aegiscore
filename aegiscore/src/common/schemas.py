"""Pydantic schemas for AegisCore inference inputs and outputs."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class HoneypotInput(BaseModel):
    source_ip_reputation_score: float = Field(ge=0.0, le=1.0)
    request_rate: float = Field(ge=0.0)
    burstiness: float = Field(ge=0.0)
    path_depth: int = Field(ge=0)
    path_entropy: float = Field(ge=0.0)
    user_agent_risk_score: float = Field(ge=0.0, le=1.0)
    failed_login_count: int = Field(ge=0)
    unique_username_count: int = Field(ge=0)
    protocol: str
    port: int = Field(ge=1, le=65535)
    method: str
    header_count: int = Field(ge=0)
    unusual_header_ratio: float = Field(ge=0.0, le=1.0)
    request_size: int = Field(ge=0)
    time_between_requests: float = Field(ge=0.0)
    number_of_touched_endpoints: int = Field(ge=0)
    decoy_asset_triggered: int = Field(ge=0, le=1)
    invalid_method_used: int = Field(ge=0, le=1)
    suspicious_path_keywords_count: int = Field(ge=0)


class MalwareInput(BaseModel):
    file_size: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)
    extension: str
    mime_type: str
    has_macro: int = Field(ge=0, le=1)
    suspicious_string_count: int = Field(ge=0)
    obfuscation_score: float = Field(ge=0.0, le=1.0)
    import_count: int = Field(ge=0)
    suspicious_import_count: int = Field(ge=0)
    packer_indicator: int = Field(ge=0, le=1)
    yara_match_count: int = Field(ge=0)
    signer_present: int = Field(ge=0, le=1)
    signer_trust_score: float = Field(ge=0.0, le=1.0)
    hash_seen_frequency: float = Field(ge=0.0, le=1.0)
    network_indicator_count: int = Field(ge=0)
    sandbox_behavior_score: float = Field(ge=0.0, le=1.0)
    persistence_indicator_count: int = Field(ge=0)
    script_indicator_score: float = Field(ge=0.0, le=1.0)


class NetworkInput(BaseModel):
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    packets: int = Field(ge=0)
    duration: float = Field(ge=0.0)
    direction: str
    failed_connections: int = Field(ge=0)
    distinct_destinations: int = Field(ge=0)
    connection_frequency: float = Field(ge=0.0)
    dns_query_volume: int = Field(ge=0)
    tls_version_score: float = Field(ge=0.0, le=1.0)
    uncommon_port_flag: int = Field(ge=0, le=1)
    internal_to_internal_flag: int = Field(ge=0, le=1)
    external_to_internal_flag: int = Field(ge=0, le=1)
    beaconing_score: float = Field(ge=0.0, le=1.0)
    hour_of_day: int = Field(ge=0, le=23)
    weekend_flag: int = Field(ge=0, le=1)


class PostureInput(BaseModel):
    missing_hsts: int = Field(ge=0, le=1)
    missing_csp: int = Field(ge=0, le=1)
    missing_x_content_type_options: int = Field(ge=0, le=1)
    insecure_cookie_flags: int = Field(ge=0, le=1)
    weak_tls: int = Field(ge=0, le=1)
    deprecated_protocol_present: int = Field(ge=0, le=1)
    admin_interface_exposed: int = Field(ge=0, le=1)
    risky_management_port_exposed: int = Field(ge=0, le=1)
    open_port_count: int = Field(ge=0)
    legacy_service_count: int = Field(ge=0)
    dependency_vuln_count: int = Field(ge=0)
    secrets_detected: int = Field(ge=0, le=1)
    public_bucket_like_flag: int = Field(ge=0, le=1)
    authz_gap_indicator: int = Field(ge=0, le=1)
    excessive_cors_flag: int = Field(ge=0, le=1)
    debug_banner_present: int = Field(ge=0, le=1)
    default_credentials_risk: int = Field(ge=0, le=1)
    segmentation_risk_score: float = Field(ge=0.0, le=1.0)


class PredictionOutput(BaseModel):
    model: str
    prediction: str
    confidence: float
    risk_score: int
    severity: str
    reason_codes: List[str]
    explanation: str
    rule_adjustments: Optional[List[str]] = None


SEVERITY_MAP = {
    "benign": "info",
    "likely_benign": "info",
    "normal": "info",
    "low": "low",
    "recon_scanner": "low",
    "bot_activity": "medium",
    "suspicious": "medium",
    "suspicious_manual": "medium",
    "medium": "medium",
    "brute_force": "high",
    "likely_malicious": "high",
    "anomalous": "high",
    "high": "high",
    "exploit_like_pattern": "critical",
    "critical": "critical",
}
