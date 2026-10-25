"""
SIEM Alert Triage & Investigation Agent
────────────────────────────────────────
CLI entry point. Streams a NetFlow CSV file row by row, runs the
detection models, fires the investigation agent on every alert,
and prints investigation reports to the console.

Usage:
    python main.py                                  # uses Wednesday CSV
    python main.py --csv path/to/file.csv           # custom CSV
    python main.py --max-alerts 5                   # stop after 5 alerts
    python main.py --severity HIGH                  # only HIGH+ alerts
    python main.py --sample 100                     # test on 100 rows
    python main.py --no-report                      # alerts only, no full report
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

# ── Add siem_agent to path ────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from alert_layer         import AlertLayer
from investigation_agent import InvestigationAgent

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_CSV = BASE_DIR.parent / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="SIEM Alert Triage & Investigation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          Run on Wednesday CSV (default)
  python main.py --sample 500            Test on first 500 rows
  python main.py --max-alerts 3          Investigate first 3 alerts found
  python main.py --severity CRITICAL     Only CRITICAL alerts
  python main.py --no-report             Print alerts only, skip full report
  python main.py --csv ../Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
        """,
    )
    parser.add_argument(
        "--csv", type=Path, default=DEFAULT_CSV,
        help="Path to NetFlow CSV file",
    )
    parser.add_argument(
        "--sample", type=int, default=None,
        help="Process only first N rows (for testing)",
    )
    parser.add_argument(
        "--max-alerts", type=int, default=3,
        help="Stop after N alerts investigated (default: 3)",
    )
    parser.add_argument(
        "--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="MEDIUM",
        help="Minimum severity to investigate (default: MEDIUM)",
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Print alert summary only, skip full investigation report",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Disable LLM triage (use rule-based verdict only)",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=10_000,
        help="Rows per chunk when streaming CSV (default: 10000)",
    )
    return parser.parse_args()


# ── Banner ────────────────────────────────────────────────────────────────────
def print_banner():
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel(
            "[bold cyan]SIEM Alert Triage & Investigation Agent[/bold cyan]\n"
            "[dim]CSE-CIC-IDS2018 | XGBoost + Isolation Forest + AI Investigation[/dim]",
            border_style="cyan",
        ))
    except ImportError:
        print("=" * 60)
        print("  SIEM Alert Triage & Investigation Agent")
        print("=" * 60)


# ── Progress printer ──────────────────────────────────────────────────────────
def print_progress(rows_processed: int, alerts_found: int, start_time: float):
    elapsed = time.time() - start_time
    rate    = rows_processed / elapsed if elapsed > 0 else 0
    try:
        from rich.console import Console
        Console().print(
            f"  [dim]Processed {rows_processed:,} rows | "
            f"{alerts_found} alerts | "
            f"{rate:,.0f} rows/sec[/dim]",
            end="\r",
        )
    except ImportError:
        print(
            f"  Processed {rows_processed:,} rows | "
            f"{alerts_found} alerts | "
            f"{rate:,.0f} rows/sec",
            end="\r",
        )


# ── Alert summary printer ─────────────────────────────────────────────────────
def print_alert_summary(alert):
    sev_colors = {
        "CRITICAL": "\033[91m",  # red
        "HIGH"    : "\033[33m",  # yellow
        "MEDIUM"  : "\033[93m",  # bright yellow
        "LOW"     : "\033[92m",  # green
    }
    reset = "\033[0m"
    color = sev_colors.get(alert.severity, "")

    try:
        from rich.console import Console
        from rich.panel import Panel
        Console().print(
            f"\n{color}🚨 ALERT FIRED{reset}\n"
            f"  ID       : {alert.alert_id}\n"
            f"  Type     : {alert.attack_type}\n"
            f"  Decision : {alert.decision}\n"
            f"  Severity : {color}{alert.severity}{reset}\n"
            f"  Conf     : {alert.confidence:.1%}\n"
            f"  Port     : {alert.dst_port} ({alert.service})\n"
            f"  MITRE    : {alert.mitre_technique_id}\n"
            f"  IOCs     : {', '.join(alert.iocs)}\n"
            f"  Desc     : {alert.description[:120]}..."
        )
    except ImportError:
        print(f"\n{'─'*60}")
        print(f"  ALERT: {alert.alert_id}")
        print(f"  Type : {alert.attack_type} | Severity: {alert.severity}")
        print(f"  Conf : {alert.confidence:.1%} | Port: {alert.dst_port}")
        print(f"  Desc : {alert.description[:100]}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    print_banner()

    # ── Validate CSV ──────────────────────────────────────────────────────────
    if not args.csv.exists():
        print(f"\n  ERROR: CSV not found: {args.csv}")
        sys.exit(1)

    print(f"\n  CSV         : {args.csv.name}")
    print(f"  Sample rows : {args.sample or 'all'}")
    print(f"  Max alerts  : {args.max_alerts}")
    print(f"  Min severity: {args.severity}")
    print(f"  Full report : {'no' if args.no_report else 'yes'}")

    # ── Init models ───────────────────────────────────────────────────────────
    print("\n  Loading models...")
    alert_layer = AlertLayer()

    if not args.no_report:
        print("  Starting investigation agent...")
        agent = InvestigationAgent(verbose=False, use_llm=not args.no_llm)
        if agent.llm_triage and agent.llm_triage.backend.name == "none:rule-based":
            from llm_triage import print_setup_instructions
            print_setup_instructions()

    # ── Stream CSV ────────────────────────────────────────────────────────────
    print(f"\n  Streaming {args.csv.name} ...\n")

    min_severity_rank = SEVERITY_ORDER[args.severity]
    alerts_found      = 0
    alerts_investigated = 0
    rows_processed    = 0
    start_time        = time.time()
    all_reports       = []

    try:
        reader = pd.read_csv(
            args.csv,
            low_memory=False,
            chunksize=args.chunk_size,
            nrows=args.sample,
        )

        for chunk in reader:
            # Drop header artifacts
            chunk = chunk[chunk["Label"] != "Label"] if "Label" in chunk.columns else chunk
            chunk = chunk.reset_index(drop=True)

            for _, row in chunk.iterrows():
                rows_processed += 1

                # Progress every 5k rows
                if rows_processed % 5_000 == 0:
                    print_progress(rows_processed, alerts_found, start_time)

                # Run alert layer
                flow  = row.to_dict()
                alert = alert_layer.process_flow(flow)

                if alert is None:
                    continue  # Benign — skip

                alerts_found += 1

                # Filter by severity
                if SEVERITY_ORDER.get(alert.severity, 4) > min_severity_rank:
                    continue

                # Print alert summary
                print_alert_summary(alert)

                # Run investigation
                if not args.no_report:
                    print(f"\n  🔍 Investigating {alert.alert_id} ...")
                    t0     = time.time()
                    report = agent.investigate(alert)
                    elapsed = time.time() - t0

                    # Print full report
                    agent.report_gen.print_report(report)

                    # Save text version
                    txt_path = agent.report_gen.save_text(report)
                    print(f"\n  💾 Report saved → {txt_path.name}  ({elapsed:.1f}s)")

                    all_reports.append(report)
                    alerts_investigated += 1

                # Stop after max alerts
                if alerts_investigated >= args.max_alerts:
                    print(f"\n\n  Reached max-alerts limit ({args.max_alerts}). Stopping.")
                    break

            if alerts_investigated >= args.max_alerts:
                break

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user.")

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed_total = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  DONE")
    print(f"  Rows processed    : {rows_processed:,}")
    print(f"  Alerts fired      : {alerts_found:,}")
    print(f"  Alerts investigated: {alerts_investigated}")
    print(f"  Total time        : {elapsed_total:.1f}s")
    print(f"  Reports saved to  : {BASE_DIR / 'reports'}/")
    print(f"{'='*60}")

    if all_reports and not args.no_report:
        print()
        agent.summarize_batch(all_reports)

    # ── Return exit code based on findings ────────────────────────────────────
    # Non-zero if any CRITICAL/HIGH confirmed attack found
    critical_found = any(
        r.alert.severity in ("CRITICAL", "HIGH") and
        r.verdict in ("CONFIRMED_ATTACK", "LIKELY_ATTACK")
        for r in all_reports
    )
    sys.exit(1 if critical_found else 0)


if __name__ == "__main__":
    main()
