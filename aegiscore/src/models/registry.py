"""Model registry for AegisCore — maps model names to artifact filenames."""

MODEL_REGISTRY = {
    "honeypot": "honeypot_model",
    "honeypot_baseline": "honeypot_baseline",
    "malware": "malware_model",
    "malware_baseline": "malware_baseline",
    "network_unsupervised": "network_unsupervised_model",
    "network_supervised": "network_supervised_model",
    "posture": "posture_model",
    "posture_baseline": "posture_baseline",
}

LABEL_REGISTRY = {
    "honeypot": "honeypot_label_encoder",
    "malware": "malware_label_encoder",
    "network_supervised": "network_supervised_label_encoder",
    "posture": "posture_label_encoder",
}
