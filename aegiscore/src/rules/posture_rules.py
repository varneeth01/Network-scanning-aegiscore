"""
Rule-based engine for the Security Misconfiguration / Exposure Risk model.

SAFETY NOTICE: Rules are defensive-only, targeting known security misconfigurations
as defined by public best practices (OWASP, CIS, NIST). They do not generate
attack automation or exploits.
"""

from typing import Any, Dict, List, Tuple


def apply_posture_rules(record: Dict[str, Any]) -> Tuple[List[str], str]:
    """
    Apply deterministic posture rules to a record.

    Returns:
        (adjustments: list of str, severity_override or None)
    """
    adjustments = []
    severity_override = None

    missing_hsts = record.get("missing_hsts", 0)
    weak_tls = record.get("weak_tls", 0)
    admin_exposed = record.get("admin_interface_exposed", 0)
    secrets = record.get("secrets_detected", 0)
    default_creds = record.get("default_credentials_risk", 0)
    risky_port = record.get("risky_management_port_exposed", 0)
    deprecated = record.get("deprecated_protocol_present", 0)
    public_bucket = record.get("public_bucket_like_flag", 0)
    authz_gap = record.get("authz_gap_indicator", 0)
    dep_vulns = record.get("dependency_vuln_count", 0)

    if missing_hsts and weak_tls and admin_exposed:
        adjustments.append("RULE: Missing HSTS + weak TLS + admin interface exposed → critical")
        severity_override = "critical"

    if secrets and (admin_exposed or default_creds):
        adjustments.append("RULE: Secrets detected + admin access exposure → critical")
        severity_override = "critical"

    if default_creds and risky_port:
        adjustments.append("RULE: Default credentials + risky port exposed → critical")
        severity_override = "critical"

    if public_bucket and authz_gap:
        adjustments.append("RULE: Public storage + authorization gap → high risk")
        if severity_override not in ("critical",):
            severity_override = "high"

    if deprecated and weak_tls:
        adjustments.append("RULE: Deprecated protocol + weak TLS → elevate to high")
        if severity_override not in ("critical", "high"):
            severity_override = "high"

    if dep_vulns >= 10:
        adjustments.append(f"RULE: {dep_vulns} vulnerable dependencies → elevated risk")
        if severity_override is None:
            severity_override = "high"

    return adjustments, severity_override


def generate_remediation_priorities(record: Dict[str, Any]) -> List[str]:
    """Return a prioritized list of remediation recommendations."""
    remediations = []

    if record.get("secrets_detected"):
        remediations.append("[CRITICAL] Rotate and vault any detected secrets immediately")
    if record.get("default_credentials_risk"):
        remediations.append("[CRITICAL] Change all default credentials before next deployment")
    if record.get("admin_interface_exposed"):
        remediations.append("[HIGH] Restrict admin interface access to VPN or allowlisted IPs")
    if record.get("weak_tls"):
        remediations.append("[HIGH] Upgrade TLS to 1.2+ and disable weak cipher suites")
    if record.get("missing_hsts"):
        remediations.append("[HIGH] Enable HTTP Strict Transport Security (HSTS)")
    if record.get("risky_management_port_exposed"):
        remediations.append("[HIGH] Close or firewall risky management ports (22, 3389, 5900, etc.)")
    if record.get("deprecated_protocol_present"):
        remediations.append("[MEDIUM] Disable deprecated protocols (SSLv3, TLS 1.0, Telnet, FTP)")
    if record.get("public_bucket_like_flag"):
        remediations.append("[HIGH] Audit and restrict public storage bucket access")
    if record.get("missing_csp"):
        remediations.append("[MEDIUM] Implement a Content Security Policy header")
    if record.get("authz_gap_indicator"):
        remediations.append("[HIGH] Review and enforce authorization controls for all endpoints")
    if record.get("excessive_cors_flag"):
        remediations.append("[MEDIUM] Restrict CORS policy to trusted origins only")
    if record.get("debug_banner_present"):
        remediations.append("[LOW] Remove version and debug banners from public-facing services")
    if record.get("missing_x_content_type_options"):
        remediations.append("[LOW] Add X-Content-Type-Options: nosniff header")
    if record.get("insecure_cookie_flags"):
        remediations.append("[MEDIUM] Set Secure, HttpOnly, and SameSite flags on all cookies")
    dep_vulns = record.get("dependency_vuln_count", 0)
    if dep_vulns > 0:
        remediations.append(f"[MEDIUM] Update {dep_vulns} vulnerable dependencies")

    return remediations if remediations else ["[INFO] No high-priority remediations identified"]
