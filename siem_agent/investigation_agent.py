"""
Investigation Agent
────────────────────
The central orchestrator of the SIEM triage pipeline.

Given a SIEMAlert it:
  1. Extracts IOCs and time window from the alert
  2. Searches host logs (Ubuntu syslog + Windows EVTX)
  3. Correlates network evidence with host log events
  4. Enriches with MITRE ATT&CK threat intelligence
  5. Generates and saves an investigation report
  6. Returns the full InvestigationReport

Flow:
  SIEMAlert
      │
      ├─► LogSearch    → list[LogEvent]
      │
      ├─► Correlator   → CorrelationResult
      │
      ├─► ThreatIntel  → ThreatIntelResult
      │
      └─► ReportGenerator → InvestigationReport
"""

import sys
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

from alert_layer      import SIEMAlert
from correlator       import Correlator, CorrelationResult
from llm_triage       import LLMTriage, TriageDecision
from log_search       import LogSearch
from report_generator import InvestigationReport, ReportGenerator
from threat_intel     import ThreatIntel

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
LOG_DIR  = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)


# ── Investigation Agent ───────────────────────────────────────────────────────
class InvestigationAgent:

    def __init__(self, verbose: bool = True, use_llm: bool = True):
        self.verbose        = verbose
        self.log_search     = LogSearch()
        self.correlator     = Correlator()
        self.threat_intel   = ThreatIntel()
        self.report_gen     = ReportGenerator()
        self.llm_triage     = LLMTriage(verbose=verbose) if use_llm else None

        # Investigation log for audit trail
        self._log_path = LOG_DIR / f"agent_{datetime.now().strftime('%Y%m%d')}.log"

        if self.verbose:
            self._log(f"InvestigationAgent initialized")
            self._log(f"Available log IPs: {list(self.log_search.list_available_ips().keys())[:5]}...")

    # ── Main entry point ──────────────────────────────────────────────────────
    def investigate(self, alert: SIEMAlert) -> InvestigationReport:
        """
        Run full investigation on a SIEMAlert.
        Returns InvestigationReport, always — even if some steps fail.
        """
        t0 = time.time()
        self._log(f"[{alert.alert_id}] Starting investigation — {alert.attack_type} "
                  f"({alert.severity}) conf={alert.confidence:.3f}")

        # ── Step 1: Extract time window from alert ────────────────────────────
        attack_start, attack_end = self._extract_time_window(alert)
        self._log(f"[{alert.alert_id}] Time window: {attack_start} → {attack_end}")

        # ── Step 2: Identify target IP ────────────────────────────────────────
        dst_ip = self._extract_ip(alert)
        self._log(f"[{alert.alert_id}] Target IP: {dst_ip}")

        # ── Step 3: Search logs ───────────────────────────────────────────────
        log_events = self._search_logs(alert, dst_ip, attack_start, attack_end)
        self._log(f"[{alert.alert_id}] Log events found: {len(log_events)}")

        # ── Step 4: Correlate ─────────────────────────────────────────────────
        correlation = self._correlate(
            alert, dst_ip, attack_start, attack_end, log_events
        )
        self._log(
            f"[{alert.alert_id}] Correlation: confirmed={correlation.attack_confirmed} "
            f"succeeded={correlation.attack_succeeded} "
            f"confidence={correlation.confidence_label}"
        )

        # ── Step 5: Threat intel ──────────────────────────────────────────────
        ti = self._enrich_threat_intel(alert)
        self._log(f"[{alert.alert_id}] Threat intel: {ti.mitre_technique_id} — {ti.mitre_technique}")

        # ── Step 6: LLM triage (if enabled) ───────────────────────────────────
        triage = None
        if self.llm_triage is not None:
            triage = self.llm_triage.triage(alert, correlation, ti)
            self._log(
                f"[{alert.alert_id}] LLM triage: verdict={triage.verdict} "
                f"conf={triage.confidence:.2f} backend={triage.backend}"
            )

        # ── Step 7: Generate report ───────────────────────────────────────────
        report = self.report_gen.generate(alert, correlation, ti, triage)
        self._log(
            f"[{alert.alert_id}] Report generated: {report.report_id} "
            f"verdict={report.verdict} "
            f"({time.time()-t0:.1f}s)"
        )

        # ── Step 8: Save report ───────────────────────────────────────────────
        saved_path = self.report_gen.save(report)
        self._log(f"[{alert.alert_id}] Report saved → {saved_path}")

        return report

    # ── Step implementations ──────────────────────────────────────────────────

    def _extract_time_window(self, alert: SIEMAlert) -> tuple[datetime, datetime]:
        """Parse timestamp from alert and build an investigation window."""
        try:
            ts = datetime.fromisoformat(str(alert.timestamp))
        except (ValueError, TypeError):
            try:
                # Try common date formats from the dataset
                for fmt in ["%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                            "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        ts = datetime.strptime(str(alert.timestamp), fmt)
                        break
                    except ValueError:
                        continue
                else:
                    ts = datetime.now()
            except Exception:
                ts = datetime.now()

        # Window: 30 min before alert → 2 hours after
        # (brute force can run for ~90 min, post-compromise activity follows)
        attack_start = ts - timedelta(minutes=5)
        attack_end   = ts + timedelta(hours=2)
        return attack_start, attack_end

    def _extract_ip(self, alert: SIEMAlert) -> str:
        """
        Extract destination IP from alert.
        The CSV doesn't have IP columns so we match against known log IPs
        using the destination port and attack type as hints.
        """
        available_ips = self.log_search.list_available_ips()

        # Check IOCs for an IP address
        import re
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        for ioc in alert.iocs:
            m = ip_pattern.search(ioc)
            if m and m.group() in available_ips:
                return m.group()

        # Match by port/service to known subnet
        # FTP/SSH targets → Windows hosts (172.31.64-67.x)
        # HTTP targets → could be any
        if alert.dst_port in (21, 22):
            # Look for Windows hosts — take the first matching one
            windows_ips = [
                ip for ip in available_ips
                if ip.startswith("172.31.6") and not ip.startswith("172.31.69")
            ]
            if windows_ips:
                return windows_ips[0]

        # Ubuntu hosts (172.31.69.x) for general queries
        ubuntu_ips = [ip for ip in available_ips if ip.startswith("172.31.69")]
        if ubuntu_ips:
            return ubuntu_ips[0]

        # Fallback: return first available IP
        if available_ips:
            return list(available_ips.keys())[0]

        return "unknown"

    def _search_logs(
        self,
        alert        : SIEMAlert,
        dst_ip       : str,
        attack_start : datetime,
        attack_end   : datetime,
    ) -> list:
        """Search logs for the target IP and time window."""
        try:
            events = self.log_search.search(
                ip            = dst_ip,
                start_time    = attack_start,
                end_time      = attack_end,
                window_minutes= 30,
            )

            # Also search by port for additional context
            port_events = self.log_search.search_by_port(
                port       = alert.dst_port,
                start_time = attack_start,
                end_time   = attack_end,
            )

            # Merge and deduplicate by raw content
            seen  = set()
            all_events = []
            for ev in events + port_events:
                key = ev.raw[:100]
                if key not in seen:
                    seen.add(key)
                    all_events.append(ev)

            all_events.sort(key=lambda e: e.timestamp or datetime.max)
            return all_events

        except Exception as e:
            self._log(f"  Log search error: {e}")
            return []

    def _correlate(
        self,
        alert        : SIEMAlert,
        dst_ip       : str,
        attack_start : datetime,
        attack_end   : datetime,
        log_events   : list,
    ) -> CorrelationResult:
        """Correlate alert with log events."""
        try:
            return self.correlator.correlate(
                alert_id     = alert.alert_id,
                attack_type  = alert.attack_type,
                dst_ip       = dst_ip,
                attack_start = attack_start,
                attack_end   = attack_end,
                log_events   = log_events,
            )
        except Exception as e:
            self._log(f"  Correlation error: {e}")
            # Return minimal result on error
            from correlator import CorrelationResult
            return CorrelationResult(
                alert_id     = alert.alert_id,
                attack_type  = alert.attack_type,
                dst_ip       = dst_ip,
                attack_start = attack_start,
                attack_end   = attack_end,
                findings     = [f"Correlation failed: {str(e)}"],
                confidence_score = 0.3,
                confidence_label = "LOW",
            )

    def _enrich_threat_intel(self, alert: SIEMAlert):
        """Look up threat intel for the attack type."""
        try:
            # Use attack_type for known attacks, decision for uncertain ones
            lookup_key = (
                alert.attack_type
                if alert.decision == "KNOWN_ATTACK"
                else alert.decision
            )
            return self.threat_intel.lookup(lookup_key)
        except Exception as e:
            self._log(f"  Threat intel error: {e}")
            return self.threat_intel.lookup("SUSPICIOUS")

    # ── Logging ───────────────────────────────────────────────────────────────
    def _log(self, msg: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {msg}"
        if self.verbose:
            print(f"  [agent] {msg}")
        try:
            with open(self._log_path, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

    # ── Batch investigation ───────────────────────────────────────────────────
    def investigate_batch(
        self,
        alerts  : list[SIEMAlert],
        max_workers: int = 1,
    ) -> list[InvestigationReport]:
        """
        Investigate multiple alerts sequentially.
        Returns list of reports sorted by severity.
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_alerts  = sorted(
            alerts,
            key=lambda a: severity_order.get(a.severity, 4)
        )

        reports = []
        for i, alert in enumerate(sorted_alerts):
            print(f"\n{'─'*60}")
            print(f"  Investigating alert {i+1}/{len(sorted_alerts)}: {alert.alert_id}")
            print(f"{'─'*60}")
            try:
                report = self.investigate(alert)
                reports.append(report)
            except Exception as e:
                self._log(f"  Failed to investigate {alert.alert_id}: {e}")
                traceback.print_exc()

        return reports

    # ── Summary stats ─────────────────────────────────────────────────────────
    def summarize_batch(self, reports: list[InvestigationReport]):
        """Print a summary table of all investigated alerts."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box

            console = Console()
            table   = Table(
                title="Investigation Batch Summary",
                box=box.ROUNDED,
                header_style="bold cyan",
            )
            table.add_column("Report ID",    style="cyan",   width=38)
            table.add_column("Attack Type",  style="yellow", width=22)
            table.add_column("Severity",     width=10)
            table.add_column("Verdict",      width=22)
            table.add_column("Conf",         width=8)
            table.add_column("Succeeded",    width=12)
            table.add_column("Post-Activity",width=14)

            sev_colors = {"CRITICAL":"red","HIGH":"orange1","MEDIUM":"yellow","LOW":"green"}

            for r in reports:
                sev   = r.alert.severity
                color = sev_colors.get(sev, "white")
                table.add_row(
                    r.report_id,
                    r.alert.attack_type,
                    f"[{color}]{sev}[/{color}]",
                    r.verdict,
                    f"{r.alert.confidence:.1%}",
                    "✅ YES" if r.correlation.attack_succeeded  else "❌ No",
                    "⚠️  YES" if r.correlation.post_activity    else "❌ No",
                )

            console.print(table)

        except ImportError:
            print("\n=== BATCH SUMMARY ===")
            for r in reports:
                print(
                    f"  {r.report_id:<30} {r.alert.attack_type:<20} "
                    f"{r.alert.severity:<10} {r.verdict:<20} "
                    f"conf={r.alert.confidence:.1%}"
                )
