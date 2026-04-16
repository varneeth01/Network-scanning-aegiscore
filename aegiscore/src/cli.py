"""
AegisCore CLI — Defensive Cybersecurity AI Suite

SAFETY NOTICE: This CLI is for authorized defensive analysis only.
It does not generate exploits, attack payloads, or assist with
unauthorized scanning or offensive operations.

Usage:
    python -m src.cli train-all
    python -m src.cli predict-honeypot --input sample.json
    python -m src.cli predict-malware --input malware_sample.json
    python -m src.cli predict-network --input flow.json
    python -m src.cli predict-posture --input posture.json
    python -m src.cli generate-data [--model all|honeypot|malware|network|posture]
    python -m src.cli report [--model all|honeypot|malware|network|posture]
"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="aegiscore",
    help="AegisCore — Defensive Cybersecurity AI Suite (defensive-only)",
    rich_markup_mode="markdown",
)
console = Console()

SAFETY_BANNER = """
[bold yellow]AegisCore — Defensive-Only Tool[/bold yellow]
This system is authorized for use on owner-provided, offline, or allowlisted data only.
It does not generate exploits, attack payloads, or assist in unauthorized operations.
"""


def _print_banner():
    console.print(Panel(SAFETY_BANNER, expand=False))


def _load_input_file(path: Path) -> dict:
    """Load a JSON input file."""
    if not path.exists():
        console.print(f"[red]Error: Input file not found: {path}[/red]")
        raise typer.Exit(1)
    with open(path) as f:
        return json.load(f)


def _print_prediction(result: dict) -> None:
    """Pretty-print a prediction result."""
    table = Table(title=f"AegisCore Prediction: {result.get('model', 'unknown')}")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Prediction", result.get("prediction", "N/A"))
    table.add_row("Severity", result.get("severity", "N/A"))
    table.add_row("Confidence", f"{result.get('confidence', 0):.2%}")
    table.add_row("Risk Score", str(result.get("risk_score", 0)))
    table.add_row("Reason Codes", ", ".join(result.get("reason_codes", [])) or "N/A")
    table.add_row("Explanation", result.get("explanation", "N/A"))

    rule_adj = result.get("rule_adjustments")
    if rule_adj:
        table.add_row("Rule Adjustments / Remediation", "\n".join(rule_adj))

    console.print(table)
    rprint(f"\n[bold]JSON Output:[/bold]")
    rprint(json.dumps(result, indent=2))


@app.command("train-all")
def train_all_cmd():
    """Train all AegisCore models (honeypot, malware, network, posture)."""
    _print_banner()
    console.print("[bold green]Starting AegisCore full training pipeline...[/bold green]")
    from .training.train_all import train_all
    results = train_all()
    console.print("[bold green]All models trained successfully.[/bold green]")


@app.command("train-honeypot")
def train_honeypot_cmd():
    """Train the Honeypot Attack Classifier."""
    _print_banner()
    from .training.train_honeypot import train_honeypot
    train_honeypot()
    console.print("[green]Honeypot classifier training complete.[/green]")


@app.command("train-malware")
def train_malware_cmd():
    """Train the Malware Triage Classifier."""
    _print_banner()
    from .training.train_malware import train_malware
    train_malware()
    console.print("[green]Malware triage training complete.[/green]")


@app.command("train-network")
def train_network_cmd():
    """Train the Network Anomaly Detector."""
    _print_banner()
    from .training.train_network import train_network
    train_network()
    console.print("[green]Network anomaly detection training complete.[/green]")


@app.command("train-posture")
def train_posture_cmd():
    """Train the Security Posture Risk Model."""
    _print_banner()
    from .training.train_posture import train_posture
    train_posture()
    console.print("[green]Posture risk model training complete.[/green]")


@app.command("predict-honeypot")
def predict_honeypot_cmd(
    input: Path = typer.Option(..., "--input", "-i", help="Path to JSON input file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to JSON file"),
):
    """Run honeypot attack classification inference."""
    _print_banner()
    record = _load_input_file(input)
    from .inference.predict_honeypot import predict_honeypot
    result = predict_honeypot(record)
    _print_prediction(result)
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        console.print(f"[green]Result saved to {output}[/green]")


@app.command("predict-malware")
def predict_malware_cmd(
    input: Path = typer.Option(..., "--input", "-i", help="Path to JSON input file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to JSON file"),
):
    """Run malware triage inference on file metadata."""
    _print_banner()
    record = _load_input_file(input)
    from .inference.predict_malware import predict_malware
    result = predict_malware(record)
    _print_prediction(result)
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        console.print(f"[green]Result saved to {output}[/green]")


@app.command("predict-network")
def predict_network_cmd(
    input: Path = typer.Option(..., "--input", "-i", help="Path to JSON input file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to JSON file"),
):
    """Run network anomaly detection inference."""
    _print_banner()
    record = _load_input_file(input)
    from .inference.predict_network import predict_network
    result = predict_network(record)
    _print_prediction(result)
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        console.print(f"[green]Result saved to {output}[/green]")


@app.command("predict-posture")
def predict_posture_cmd(
    input: Path = typer.Option(..., "--input", "-i", help="Path to JSON input file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to JSON file"),
):
    """Run security posture risk assessment."""
    _print_banner()
    record = _load_input_file(input)
    from .inference.predict_posture import predict_posture
    result = predict_posture(record)
    _print_prediction(result)
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        console.print(f"[green]Result saved to {output}[/green]")


@app.command("generate-data")
def generate_data_cmd(
    model: str = typer.Option("all", "--model", "-m", help="Which model's data to generate: all|honeypot|malware|network|posture"),
    n_samples: int = typer.Option(8000, "--samples", "-n", help="Number of samples to generate"),
    seed: int = typer.Option(42, "--seed", "-s", help="Random seed"),
):
    """Generate synthetic training data for one or all models."""
    _print_banner()
    from .common.utils import ensure_dirs
    ensure_dirs()

    targets = [model] if model != "all" else ["honeypot", "malware", "network", "posture"]
    for target in targets:
        if target == "honeypot":
            from .data_generation.honeypot_synth import generate_honeypot_data
            generate_honeypot_data(n_samples=n_samples, seed=seed)
        elif target == "malware":
            from .data_generation.malware_synth import generate_malware_data
            generate_malware_data(n_samples=n_samples, seed=seed)
        elif target == "network":
            from .data_generation.network_synth import generate_network_data
            generate_network_data(n_samples=n_samples, seed=seed)
        elif target == "posture":
            from .data_generation.posture_synth import generate_posture_data
            generate_posture_data(n_samples=n_samples, seed=seed)
        else:
            console.print(f"[red]Unknown model: {target}[/red]")
    console.print("[green]Data generation complete.[/green]")


@app.command("report")
def report_cmd(
    model: str = typer.Option("all", "--model", "-m", help="Model to report on: all|honeypot|malware|network|posture"),
):
    """Print evaluation reports for trained models."""
    _print_banner()
    from .evaluation.reports import print_classification_report, summarize_all_reports
    if model == "all":
        summary = summarize_all_reports()
        for name, metrics in summary.items():
            console.print(f"\n[bold]{name}[/bold]")
            console.print(f"  F1 Macro: {metrics.get('f1_macro', 'N/A')}")
            console.print(f"  Train: {metrics.get('n_train', 'N/A')} | Test: {metrics.get('n_test', 'N/A')}")
    else:
        print_classification_report(f"{model}_training_report".replace("_training_report_training_report", "_training_report"))


if __name__ == "__main__":
    app()
