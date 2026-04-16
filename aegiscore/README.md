# AegisCore

**Production-grade defensive cybersecurity AI suite — model-first Python project.**

---

## DEFENSIVE-ONLY SCOPE

> **AegisCore is strictly a defensive tool.**
>
> - It is authorized for use on **owner-provided, offline, uploaded, or allowlisted data only**.
> - It does **not** generate exploit code, attack payloads, malware, phishing kits, persistence logic, privilege escalation logic, or unauthorized scanning tools.
> - It does **not** automate offensive vulnerability discovery on public or third-party systems.
> - It does **not** claim 100% detection or prevention of zero-day attacks.
> - It focuses on **detection, risk scoring, anomaly identification, malware triage, honeypot telemetry analysis, and defensive posture analysis**.

---

## Project Overview

AegisCore is a modular Python ML project implementing and training a suite of defensive AI models for cybersecurity. It is CLI-first, notebook-friendly, and Replit-ready.

### Model Suite

| # | Model | Task | Algorithm |
|---|-------|------|-----------|
| 1 | **Honeypot Attack Classifier** | Classify honeypot events into threat categories | XGBoost / GradientBoosting |
| 2 | **Malware Triage Classifier** | Metadata-only file risk triage | XGBoost / GradientBoosting |
| 3 | **Network Anomaly Detector** | Detect anomalous network flows | IsolationForest + RandomForest |
| 4 | **Posture Risk Model** | Security misconfiguration risk scoring | XGBoost + Rule Engine |

---

## Project Structure

```
aegiscore/
  README.md
  requirements.txt
  pyproject.toml
  .env.example
  sample_honeypot.json
  sample_malware.json
  sample_network.json
  sample_posture.json
  data/
    raw/           # Owner-provided real data (never commit real data)
    processed/
    synthetic/     # Auto-generated synthetic training data
    models/        # Saved trained model artifacts (.joblib)
    reports/       # Training reports and evaluation metrics
  configs/
    model_config.yaml
    feature_schema.yaml
  notebooks/       # Jupyter exploration notebooks
  src/
    cli.py         # CLI entry point
    main.py
    common/        # Shared logger, utils, schemas, metrics, I/O
    data_generation/  # Synthetic data generators
    preprocessing/    # Encoders, feature builders, validators
    models/           # Model pipeline definitions
    training/         # Training scripts
    inference/        # Prediction scripts
    explainability/   # Feature importance + explanation engine
    rules/            # Deterministic rule engines
    evaluation/       # Metrics, reports, plots
    tests/            # pytest test suite
```

---

## Installation

```bash
cd aegiscore
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

---

## Generating Synthetic Data

AegisCore ships with realistic synthetic data generators for all 4 models. Real data can be placed in `data/raw/` and loaded directly.

```bash
# Generate data for all models (8000 samples each, seed=42)
python -m src.cli generate-data --model all

# Generate for a specific model with custom settings
python -m src.cli generate-data --model honeypot --samples 10000 --seed 123
python -m src.cli generate-data --model malware
python -m src.cli generate-data --model network
python -m src.cli generate-data --model posture
```

Or from Python:

```python
from src.data_generation.honeypot_synth import generate_honeypot_data
df = generate_honeypot_data(n_samples=8000, seed=42)
```

---

## Training Models

### Train All Models

```bash
python -m src.cli train-all
```

### Train Individual Models

```bash
python -m src.cli train-honeypot
python -m src.cli train-malware
python -m src.cli train-network
python -m src.cli train-posture
```

### From Python

```python
from src.training.train_all import train_all
results = train_all()
```

Trained model artifacts are saved to `data/models/`. Training reports are written to `data/reports/`.

---

## Running Inference

### CLI

```bash
python -m src.cli predict-honeypot --input sample_honeypot.json
python -m src.cli predict-malware --input sample_malware.json
python -m src.cli predict-network --input sample_network.json
python -m src.cli predict-posture --input sample_posture.json

# Save output to file
python -m src.cli predict-posture --input sample_posture.json --output result.json
```

### Python API

```python
import json
from src.inference.predict_malware import predict_malware

record = json.load(open("sample_malware.json"))
result = predict_malware(record)
print(result)
```

### Output Format

```json
{
  "model": "malware_triage",
  "prediction": "likely_malicious",
  "confidence": 0.91,
  "risk_score": 91,
  "severity": "critical",
  "reason_codes": ["HIGH_FILE_ENTROPY", "SUSPICIOUS_IMPORTS", "PACKER_INDICATOR"],
  "explanation": "Multiple strong indicators of malicious intent detected in file metadata. Key indicators: Very high file entropy suggests encryption or packing; Multiple suspicious API imports detected; Packing or compression artifact detected.",
  "rule_adjustments": ["RULE: High entropy + suspicious imports + packer → likely_malicious elevated"]
}
```

---

## Running Evaluation Reports

```bash
python -m src.cli report --model all
python -m src.cli report --model honeypot
```

---

## Running Tests

```bash
cd aegiscore
pytest src/tests/ -v
```

Coverage:
- Synthetic data generation shape and schema
- Model training pipeline execution
- Inference output structure
- Rule engine behavior
- Deterministic findings

---

## Notebook Exploration

Jupyter notebooks are available in `notebooks/`:
- `01_honeypot_exploration.ipynb`
- `02_malware_triage.ipynb`
- `03_network_anomaly.ipynb`
- `04_misconfig_risk.ipynb`

---

## Configuration

- `configs/model_config.yaml` — hyperparameters, label sets, sample counts
- `configs/feature_schema.yaml` — feature type definitions (numeric/binary/categorical)
- `.env.example` — environment variables

---

## Explainability

Every prediction includes:
- **Reason codes**: short, machine-readable identifiers (e.g., `HIGH_FILE_ENTROPY`)
- **Human-readable explanation**: natural language description of why the sample was flagged
- **Rule adjustments**: deterministic rule engine findings that override or supplement ML output
- **Top 3 contributing features**: from SHAP or permutation importance

---

## Limitations

- Models are trained on **synthetic data by default** — performance on real data will vary and require retraining on owner-provided datasets.
- AegisCore does **not** claim to detect all threats or zero-day attacks.
- Network anomaly detection in unsupervised mode may produce false positives; supervised mode requires labeled data.
- This tool must only be used on authorized, owner-provided systems and datasets.
- Malware triage is **metadata-only** — it does not detonate, execute, or inspect actual malware files.

---

## Future Work

- Real-data ingestion pipelines (CSV import with schema validation)
- MITRE ATT&CK tactic tagging for honeypot classifications
- Time-series beaconing detection model
- Threat Intelligence feed integration (read-only, defensive)
- REST API wrapper for SOC platform integration
- SHAP summary plot generation per model
- Active learning pipeline for analyst feedback loop
- Multi-model ensemble risk scoring

---

## Tech Stack

- Python 3.11+
- scikit-learn, XGBoost, pandas, numpy
- joblib (model persistence)
- Pydantic v2 (schema validation)
- SHAP (explainability, with permutation importance fallback)
- Typer + Rich (CLI)
- PyYAML (configuration)
- matplotlib (evaluation plots)
- pytest (testing)
