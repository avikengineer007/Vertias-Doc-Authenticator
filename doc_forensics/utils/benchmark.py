"""Precision, recall, and benchmark evaluation utilities for doc-forensics."""

from pathlib import Path
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table

from doc_forensics.scanner import ForensicScanner
from doc_forensics.report.schema import CheckStatus

console = Console()


def run_benchmark(dataset_dir: Path) -> Dict[str, Dict[str, float]]:
    """
    Run precision/recall benchmark evaluation against ground-truth dataset samples.
    
    Returns:
        Dictionary mapping each module name to its precision, recall, f1_score metrics.
    """
    dataset_dir = Path(dataset_dir)
    if not dataset_dir.exists() or not list(dataset_dir.glob("*.jpg")):
        try:
            from tests.generate_synthetic_samples import generate_all_dataset_samples
            console.print("[yellow]Dataset directory empty or missing. Generating synthetic samples...[/]")
            generate_all_dataset_samples(dataset_dir)
        except Exception as e:
            console.print(f"[red]Error loading dataset samples: {e}[/]")
            return {}

    scanner = ForensicScanner(save_heatmaps=False)

    # Expected ground-truth mapping: (filename, target_tampered_module)
    test_cases = [
        ("authentic_passport.jpg", None),
        ("tampered_metadata.jpg", "metadata"),
        ("tampered_ela.jpg", "ela"),
        ("tampered_copymove.jpg", "copy_move"),
        ("tampered_ocr.jpg", "ocr_consistency"),
        ("tampered_noise.jpg", "noise_analysis"),
    ]

    modules = ["metadata", "ela", "copy_move", "ocr_consistency", "noise_analysis"]
    stats: Dict[str, Dict[str, int]] = {
        mod: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for mod in modules
    }

    for fname, target_mod in test_cases:
        img_path = dataset_dir / fname
        if not img_path.exists():
            continue

        report = scanner.scan(img_path)

        for mod in modules:
            res = report.checks.get(mod)
            is_flagged = (res.status == CheckStatus.SUSPECTED_TAMPERING) if res else False

            if target_mod == mod:
                if is_flagged:
                    stats[mod]["tp"] += 1
                else:
                    stats[mod]["fn"] += 1
            else:
                if is_flagged:
                    stats[mod]["fp"] += 1
                else:
                    stats[mod]["tn"] += 1

    benchmark_metrics: Dict[str, Dict[str, float]] = {}

    table = Table(title="doc-forensics Benchmark Results (Ground Truth Test Set)", show_header=True, header_style="bold green")
    table.add_column("Module", style="cyan", width=18)
    table.add_column("Precision", justify="right", width=12)
    table.add_column("Recall", justify="right", width=12)
    table.add_column("F1-Score", justify="right", width=12)
    table.add_column("TP / FP / TN / FN", justify="center", width=22)

    for mod in modules:
        tp = stats[mod]["tp"]
        fp = stats[mod]["fp"]
        tn = stats[mod]["tn"]
        fn = stats[mod]["fn"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        benchmark_metrics[mod] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn
        }

        table.add_row(
            mod,
            f"{round(precision * 100, 1)}%",
            f"{round(recall * 100, 1)}%",
            f"{round(f1 * 100, 1)}%",
            f"{tp} / {fp} / {tn} / {fn}"
        )

    console.print()
    console.print(table)
    console.print()

    return benchmark_metrics
