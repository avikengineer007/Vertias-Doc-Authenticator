"""rich-based Command Line Interface (CLI) entrypoint for Veritas doc-forensics."""

import sys
import argparse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from doc_forensics import ForensicScanner, __version__
from doc_forensics.report.schema import CheckStatus
from doc_forensics.config import load_config


console = Console()


def _format_status_badge(status: CheckStatus) -> Text:
    """Format status badge with rich colors."""
    if status == CheckStatus.AUTHENTIC:
        return Text(" AUTHENTIC ", style="bold white on green")
    elif status == CheckStatus.SUSPECTED_TAMPERING:
        return Text(" SUSPECTED TAMPERING ", style="bold white on red")
    else:
        return Text(" INCONCLUSIVE ", style="bold black on yellow")


def print_report(report) -> None:
    """Render structured DocumentReport to rich terminal console."""
    console.print()
    
    # 1. Header panel
    badge = _format_status_badge(report.verdict)
    risk_color = "red" if report.overall_risk_score > 0.6 else "yellow" if report.overall_risk_score > 0.3 else "green"
    
    header_text = Text()
    header_text.append("Document: ", style="bold gray70")
    header_text.append(f"{report.image_path}\n", style="bold white")
    header_text.append("Aggregated Risk Score: ", style="bold gray70")
    header_text.append(f"{round(report.overall_risk_score * 100, 1)}%\n\n", style=f"bold {risk_color}")
    header_text.append(report.summary, style="italic dim")

    console.print(Panel(
        header_text,
        title=f"FORENSIC SCAN VERDICT  |  {badge.plain}",
        subtitle=f"veritas / doc-forensics v{__version__}",
        border_style="red" if report.verdict == CheckStatus.SUSPECTED_TAMPERING else "yellow" if report.verdict == CheckStatus.INCONCLUSIVE else "green",
        expand=True
    ))

    # 2. Check Breakdown Table
    table = Table(title="Module Detection Breakdown", show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Module", style="cyan", width=18)
    table.add_column("Status", justify="center", width=22)
    table.add_column("Risk Score", justify="right", width=12)
    table.add_column("Time", justify="right", width=10)
    table.add_column("Explanation & Evidence", style="white")

    for mod_name, check in report.checks.items():
        st_badge = _format_status_badge(check.status)
        score_str = f"{round(check.score * 100, 1)}%"
        time_str = f"{round(check.execution_time_ms, 1)} ms"
        table.add_row(
            mod_name,
            st_badge,
            score_str,
            time_str,
            check.explanation
        )

    console.print(table)
    console.print()


def cmd_scan(args) -> int:
    """Execute document forensic scan command with validation error handling."""
    image_path = Path(args.image_path)
    cfg = load_config(args.config)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description=f"Running forensic analysis on {image_path.name}...", total=None)
            
            scanner = ForensicScanner(
                config=cfg,
                save_heatmaps=args.save_heatmaps or bool(args.heatmap_dir),
                output_heatmap_dir=args.heatmap_dir or (image_path.parent / "forensic_heatmaps"),
                ela_quality=args.quality
            )
            report = scanner.scan(image_path)

        print_report(report)

        # Export JSON report if requested
        if args.output_json:
            out_json_path = Path(args.output_json)
            out_json_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_json_path, "w", encoding="utf-8") as f:
                f.write(report.to_json(indent=2))
            console.print(f"[bold green][+][/] Forensic JSON report saved to: [cyan]{out_json_path}[/]")

        return 0
    except (ValueError, FileNotFoundError) as err:
        console.print(f"[bold red]Error:[/] {str(err)}")
        return 1


def cmd_benchmark(args) -> int:
    """Execute benchmark evaluation across a labeled dataset directory."""
    from doc_forensics.utils.benchmark import run_benchmark
    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.exists():
        console.print(f"[bold red]Error:[/] Dataset directory not found: [yellow]{dataset_dir}[/]")
        return 1
    
    console.print(f"[bold cyan]Running forensic precision/recall benchmark against:[/] {dataset_dir}")
    run_benchmark(dataset_dir)
    return 0


def cmd_serve(args) -> int:
    """Launch local FastAPI web server endpoint."""
    try:
        import uvicorn
        from doc_forensics.api import create_app
        cfg = load_config(args.config)
        cfg.host = args.host or cfg.host
        cfg.port = args.port or cfg.port

        app = create_app(config=cfg)
        console.print(f"[bold green]Starting Veritas API web upload server on:[/] http://{cfg.host}:{cfg.port}")
        uvicorn.run(app, host=cfg.host, port=cfg.port)
        return 0
    except Exception as err:
        console.print(f"[bold red]Failed to start server:[/] {str(err)}")
        return 1


def main(argv=None) -> int:
    """Main CLI command handler for veritas / doc-forensics."""
    parser = argparse.ArgumentParser(
        prog="veritas",
        description="Veritas / doc-forensics DocumentID Tampering Detection CLI & Web Server"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", help="Path to veritas.toml configuration file")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Perform forensic tampering scan on an image")
    scan_parser.add_argument("image_path", help="Path to document image file")
    scan_parser.add_argument("--output-json", "-o", help="Path to save output JSON report")
    scan_parser.add_argument("--save-heatmaps", "-s", action="store_true", help="Save ELA and Noise visual heatmaps")
    scan_parser.add_argument("--heatmap-dir", help="Target directory for output heatmaps")
    scan_parser.add_argument("--quality", "-q", type=int, help="JPEG re-compression quality for ELA (default: from config)")

    # serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Launch local FastAPI upload web server")
    serve_parser.add_argument("--host", help="Bind host (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, help="Bind port (default: 8000)")

    # benchmark subcommand
    bench_parser = subparsers.add_parser("benchmark", help="Run precision/recall benchmark evaluation on dataset")
    bench_parser.add_argument("dataset_dir", nargs="?", default="tests/synthetic_dataset", help="Directory containing labeled test samples")

    args = parser.parse_args(argv)

    if args.subcommand == "scan":
        return cmd_scan(args)
    elif args.subcommand == "serve":
        return cmd_serve(args)
    elif args.subcommand == "benchmark":
        return cmd_benchmark(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
