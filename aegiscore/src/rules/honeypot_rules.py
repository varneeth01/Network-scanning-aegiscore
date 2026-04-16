"""
Rule-based fallback engine for Honeypot Attack Classifier.

SAFETY NOTICE: Rules are purely defensive — they flag suspicious activity,
they do not generate attack payloads or scanning instructions.
"""

from typing import Any, Dict, List, Tuple


def apply_honeypot_rules(record: Dict[str, Any]) -> Tuple[List[str], str]:
    """
    Apply deterministic honeypot rules to a record.

    Returns:
        (adjustments: list of str descriptions, severity_override or None)
    """
    adjustments = []
    severity_override = None

    failed_logins = record.get("failed_login_count", 0)
    unique_usernames = record.get("unique_username_count", 0)
    burstiness = record.get("burstiness", 0.0)
    decoy_triggered = record.get("decoy_asset_triggered", 0)
    suspicious_path_kw = record.get("suspicious_path_keywords_count", 0)
    invalid_method = record.get("invalid_method_used", 0)
    ip_rep = record.get("source_ip_reputation_score", 0.0)
    request_rate = record.get("request_rate", 0.0)

    if failed_logins >= 30 and unique_usernames >= 10 and burstiness >= 0.5:
        adjustments.append("RULE: High failed logins + username diversity + burstiness → brute_force_confirmed")
        severity_override = "high"

    if decoy_triggered and suspicious_path_kw >= 3:
        adjustments.append("RULE: Decoy asset triggered with suspicious path keywords → elevate to critical")
        severity_override = "critical"

    if ip_rep >= 0.8 and request_rate >= 20:
        adjustments.append("RULE: High IP reputation score with high request rate → suspicious elevated")
        if severity_override not in ("critical",):
            severity_override = "high"

    if invalid_method and suspicious_path_kw >= 5:
        adjustments.append("RULE: Invalid method + many suspicious keywords → exploit_like_pattern elevated")
        severity_override = "critical"

    return adjustments, severity_override
