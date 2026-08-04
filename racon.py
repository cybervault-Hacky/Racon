#!/usr/bin/env python3
"""RACON — Reconnaissance & Analysis Console.

A defensive cybersecurity reconnaissance and OSINT framework for authorized
security assessments, asset inventory and defensive reconnaissance.

Usage examples::

    python racon.py --target example.com
    python racon.py -t example.com -f html,json,pdf
    python racon.py -t 93.184.216.34 --threads 20 --verbose
    python racon.py -t example.com --modules basic_info,dns_intelligence
    python racon.py --target example.com --config my-config.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Ensure project root is importable when run as a plain script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.panel import Panel  # noqa: E402
from rich.progress import (BarColumn, Progress, SpinnerColumn,  # noqa: E402
                           TextColumn, TimeElapsedColumn, TimeRemainingColumn)
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

from core.config import load_config  # noqa: E402
from core.logger import setup_logging, get_console  # noqa: E402
from core.scanner import Scanner  # noqa: E402
from modules import MODULE_MAP, list_modules  # noqa: E402

console = get_console()

VERSION = "1.0.0"

#: Banner gradient colours (start -> end).
BANNER_COLORS = ["#00d2ff", "#3a7bd5", "#7c5cff", "#a855f7", "#ec4899"]


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def gradient_banner() -> Text:
    """Render the ASCII banner with a colour gradient."""
    banner_path = Path(__file__).resolve().parent / "banner.txt"
    lines = (banner_path.read_text(encoding="utf-8").splitlines()
             if banner_path.exists() else ["RACON"])
    result = Text()
    n = len(BANNER_COLORS)
    for i, line in enumerate(lines):
        color = BANNER_COLORS[min(i, n - 1)]
        result.append(line + "\n", style=color)
    return result


def welcome_panel() -> None:
    """Print the branded header panel."""
    console.print(gradient_banner())
    console.rule("[bold cyan]Reconnaissance & Analysis Console[/]")
    console.print(
        "[dim]Authorized security assessments • Asset inventory • "
        "Defensive reconnaissance[/]"
    )
    console.print()


def config_panel(cfg: Any) -> None:
    """Render the runtime configuration summary."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()
    table.add_row("Threads", str(cfg.threads))
    table.add_row("Timeout", f"{cfg.request_timeout}s")
    table.add_row("Retries", str(cfg.max_retries))
    table.add_row("Verify SSL", str(cfg.verify_ssl))
    table.add_row("Report format", cfg.report_format)
    table.add_row("Output dir", cfg.output_dir)
    table.add_row("Theme", cfg.theme)
    console.print(Panel(table, title="[bold]Runtime Configuration[/]",
                        border_style="cyan", expand=False))
    console.print()


def results_summary(scan_result: Any) -> None:
    """Render per-module results summary table."""
    table = Table(title="[bold]Module Results[/]", border_style="cyan")
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Time (s)", justify="right")

    for m in scan_result.module_results:
        status_style = {
            "success": "green", "skipped": "yellow", "error": "red",
            "not_applicable": "dim",
        }.get(m.status, "white")
        table.add_row(
            m.module, f"[{status_style}]{m.status}[/]",
            str(len(m.findings)), f"{m.elapsed:.2f}",
        )
    console.print(table)

    # Report output paths.
    if scan_result.report_paths:
        paths = Table(title="[bold]Reports Generated[/]", border_style="green")
        paths.add_column("File")
        for p in scan_result.report_paths:
            paths.add_row(f"[green]{p}[/]")
        console.print(paths)

    summary = scan_result.summary()
    console.print(Panel(
        f"Target: [bold]{summary['target']}[/]\n"
        f"Modules completed: [bold]{summary['modules_completed']}[/]/"
        f"{summary['modules_total']}\n"
        f"Elapsed: [bold]{summary['elapsed']}[/]s\n"
        f"Status: [bold green]{summary['status']}[/]",
        title="[bold]Scan Summary[/]", border_style="green", expand=False,
    ))


# ---------------------------------------------------------------------------
# Non-interactive scan
# ---------------------------------------------------------------------------

def scan_headless(cfg: Any, target: str, formats: str | None,
                  modules: list[str] | None) -> None:
    """Run a scan with a live progress dashboard (no command prompt)."""
    scanner = Scanner(cfg, target)
    total_modules = len(scanner.build_modules())
    if modules:
        total_modules = len([m for m in scanner.build_modules() if m.key in modules])

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )
    task = progress.add_task("Scanning", total=total_modules)

    def on_progress(done: int, total: int, module_name: str) -> None:
        progress.update(
            task, completed=done,
            description=f"Running: [bold]{module_name}[/] ({done}/{total})",
        )

    scanner.progress_callback = on_progress
    with progress:
        result = scanner.run(formats=formats, modules=modules)
    console.print()
    results_summary(result)
    console.print()
    console.print(Panel(
        "[bold]Created by[/]\nSarthak Bharambe\n\n"
        "[bold]YouTube[/]\nCyber Vault\n\n"
        "[bold]Instagram[/]\n@cyber_vault123",
        title="[bold]Credits[/]", border_style="cyan", expand=False,
        padding=(1, 4),
    ), justify="center")


# ---------------------------------------------------------------------------
# Interactive command mode
# ---------------------------------------------------------------------------

class CommandMode:
    """Interactive prompt with single-key shortcuts and typed commands."""

    HELP = {
        "status": "Show scan progress status",
        "modules": "List available modules",
        "results": "Show live module results",
        "reports": "Show generated report paths",
        "help": "Show this help message",
        "abort": "Abort the current scan",
        "exit": "Exit RACON",
    }

    def __init__(self, scanner: Scanner | None) -> None:
        self.scanner = scanner
        self.running = True

    def run(self) -> None:
        console.print(Panel(
            "[bold]Command Mode[/] — enter a command below. "
            "Type [bold]help[/] for options.",
            border_style="yellow",
        ))
        while self.running:
            try:
                raw = input("racon> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Exiting.[/]")
                break
            if not raw:
                continue
            cmd, _, arg = raw.partition(" ")
            handler = getattr(self, f"cmd_{cmd}", None)
            if handler:
                handler(arg)
            else:
                console.print(f"[red]Unknown command:[/] {cmd} "
                              f"(type [bold]help[/])")

    # -- command handlers ---------------------------------------------------
    def cmd_help(self, _: str) -> None:
        table = Table(title="[bold]Commands[/]", border_style="cyan")
        table.add_column("Command", style="bold cyan")
        table.add_column("Description")
        for cmd, desc in self.HELP.items():
            table.add_row(cmd, desc)
        console.print(table)

    def cmd_modules(self, _: str) -> None:
        table = Table(title="[bold]Available Modules[/]", border_style="cyan")
        table.add_column("Key", style="bold")
        table.add_column("Name")
        for key in list_modules():
            cls = MODULE_MAP[key]
            table.add_row(key, cls.name)
        console.print(table)

    def cmd_status(self, _: str) -> None:
        console.print("[yellow]Scan status:[/] run the scan in a separate "
                      "terminal or via [bold]--target[/] for live updates.")

    def cmd_results(self, _: str) -> None:
        console.print("[dim]Run a scan first to see results.[/]")

    def cmd_reports(self, _: str) -> None:
        console.print("[dim]No reports generated yet.[/]")

    def cmd_abort(self, _: str) -> None:
        console.print("[bold red]Aborting scan...[/]")
        if self.scanner is not None:
            self.scanner.abort()
        self.running = False

    def cmd_exit(self, _: str) -> None:
        console.print("[dim]Goodbye.[/]")
        self.running = False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="racon",
        description="RACON — Reconnaissance & Analysis Console "
                    "(defensive / authorized use only).",
        epilog="Example: python racon.py --target example.com -f html,json,pdf",
    )
    parser.add_argument("-t", "--target", required=False,
                        help="Target hostname or IP address")
    parser.add_argument("-c", "--config", default=None,
                        help="Path to a custom YAML configuration file")
    parser.add_argument("-f", "--format", default=None,
                        help="Report format(s): html, json, csv, pdf or all")
    parser.add_argument("--threads", type=int, default=None,
                        help="Override the number of worker threads")
    parser.add_argument("--timeout", type=int, default=None,
                        help="Override the HTTP request timeout (seconds)")
    parser.add_argument("--output", default=None,
                        help="Override the output directory")
    parser.add_argument("--modules", default=None,
                        help="Comma-separated module keys to run")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress banner and run headless")
    parser.add_argument("--version", action="store_true",
                        help="Show version and exit")
    parser.add_argument("--command", action="store_true",
                        help="Open interactive command mode")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.version:
        console.print(f"RACON v{VERSION} — Reconnaissance & Analysis Console")
        return 0

    cfg = load_config(args.config)

    # CLI overrides.
    if args.threads:
        cfg.set("scan.threads", args.threads)
    if args.timeout:
        cfg.set("scan.request_timeout", args.timeout)
    if args.output:
        cfg.set("output.directory", args.output)

    level = "DEBUG" if args.verbose else cfg.log_level
    setup_logging(level=level, to_file=cfg.log_to_file,
                  log_dir=str(Path(cfg.output_dir) / "logs"))

    modules_override: list[str] | None = None
    if args.modules:
        modules_override = [m.strip() for m in args.modules.split(",") if m.strip()]

    if args.command:
        welcome_panel()
        config_panel(cfg)
        console.print("[dim]Command mode (no scan target selected). "
                      "Use: python racon.py -t <target> for scanning.[/]")
        CommandMode(scanner=None).run()
        return 0

    # Interactive command mode with a target.
    if not args.target and not args.command:
        console.print("[red]No target provided.[/] "
                      "Use [bold]--target <host>[/] or [bold]--command[/].")
        console.print("Example: [cyan]python racon.py -t example.com[/]")
        return 1

    if not args.quiet:
        welcome_panel()

    try:
        scanner = Scanner(cfg, args.target)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Error:[/] {exc}")
        return 1

    config_panel(cfg)

    fmt = args.format or cfg.report_format
    try:
        scan_headless(cfg, args.target, fmt, modules_override)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/]")
        try:
            scanner.abort()
        except Exception:  # noqa: BLE001
            pass
        return 130
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Scan failed:[/] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
