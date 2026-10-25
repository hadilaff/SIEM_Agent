"""
Report Generator Module
────────────────────────
Takes the outputs of AlertLayer + Correlator + ThreatIntel
and produces a structured investigation report.

Output formats:
  - Console (rich terminal output) — for SOC analyst live view
  - JSON                           — for SIEM integration / ticketing
  - Plain text                     — for email / ticketing systems
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from alert_layer import SIEMAlert
from correlator import CorrelationResult
from llm_triage  import TriageDecision
from threat_intel import ThreatIntelResult

# Report output directory
REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# Severity colors for console
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH"    : "red",
    "MEDIUM"  : "yellow",
    "LOW"     : "green",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH"    : "🟠",
    "MEDIUM"  : "🟡",
    "LOW"     : "🟢",
}

DECISION_EMOJI = {
    "KNOWN_ATTACK"  : "🚨",
    "SUSPICIOUS"    : "⚠️ ",
    "UNKNOWN_THREAT": "👾",
    "Benign"        : "✅",
}


# ── Investigation Report dataclass ────────────────────────────────────────────
@dataclass
class InvestigationReport:
    report_id         : str
    generated_at      : str
    alert             : SIEMAlert
    correlation       : CorrelationResult
    threat_intel      : ThreatIntelResult
    triage            : Optional[TriageDecision] = None
    executive_summary : str = ""
    verdict           : str = ""   # CONFIRMED_ATTACK | LIKELY_ATTACK | SUSPICIOUS | FALSE_POSITIVE
                                    #  (or LLM verdict: true_positive|false_positive|benign|escalate)
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "report_id"          : self.report_id,
            "generated_at"       : self.generated_at,
            "verdict"            : self.verdict,
            "executive_summary"  : self.executive_summary,
            "alert"              : self.alert.to_dict(),
            "correlation"        : self.correlation.to_dict(),
            "threat_intel"       : self.threat_intel.to_dict(),
            "triage"             : self.triage.to_dict() if self.triage else None,
            "recommended_actions": self.recommended_actions,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ── Report Generator ──────────────────────────────────────────────────────────
class ReportGenerator:

    def generate(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
        triage      : Optional[TriageDecision] = None,
    ) -> InvestigationReport:
        """Generate a full investigation report from all module outputs."""

        report_id = f"RPT-{alert.alert_id}"
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Use LLM triage verdict if available, else rule-based
        if triage is not None and triage.backend != "none":
            verdict = triage.verdict   # true_positive | false_positive | benign | escalate
            executive_summary = self._write_llm_summary(alert, correlation, threat_intel, triage)
            recommended_actions = self._prioritize_actions(alert, correlation, threat_intel, triage)
        else:
            verdict = self._determine_verdict(alert, correlation)
            executive_summary = self._write_executive_summary(
                alert, correlation, threat_intel, verdict
            )
            recommended_actions = self._prioritize_actions(
                alert, correlation, threat_intel
            )

        report = InvestigationReport(
            report_id          = report_id,
            generated_at       = generated_at,
            alert              = alert,
            correlation        = correlation,
            threat_intel       = threat_intel,
            triage             = triage,
            executive_summary  = executive_summary,
            verdict            = verdict,
            recommended_actions= recommended_actions,
        )

        return report

    # ── Verdict ───────────────────────────────────────────────────────────────
    def _determine_verdict(
        self,
        alert      : SIEMAlert,
        correlation: CorrelationResult,
    ) -> str:
        if alert.decision == "UNKNOWN_THREAT":
            return "UNKNOWN_THREAT"

        if alert.decision == "SUSPICIOUS":
            return "SUSPICIOUS"

        if alert.confidence >= 0.95 and correlation.attack_succeeded:
            return "CONFIRMED_ATTACK"

        if alert.confidence >= 0.85 and correlation.attack_confirmed:
            return "LIKELY_ATTACK"

        if alert.confidence >= 0.85:
            return "LIKELY_ATTACK"

        return "SUSPICIOUS"

    # ── Executive summary ─────────────────────────────────────────────────────
    def _write_executive_summary(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
        verdict     : str,
    ) -> str:
        duration = ""
        try:
            start = datetime.fromisoformat(correlation.attack_start.isoformat())
            end   = datetime.fromisoformat(correlation.attack_end.isoformat())
            mins  = int((end - start).total_seconds() / 60)
            duration = f" over {mins} minutes" if mins > 0 else ""
        except Exception:
            pass

        succeeded_str = (
            " Evidence suggests the attack SUCCEEDED — immediate action required."
            if correlation.attack_succeeded
            else " No conclusive evidence of successful compromise found."
        )

        post_str = (
            f" Post-attack activity detected ({len(correlation.activity_evidence)} events) — "
            "possible post-compromise behavior."
            if correlation.post_activity
            else ""
        )

        log_str = (
            f" {correlation.total_log_events} host log events corroborated the alert."
            if correlation.total_log_events > 0
            else " No host logs available for this IP."
        )

        return (
            f"[{verdict}] {alert.attack_type} detected on {correlation.dst_ip} "
            f"(port {alert.dst_port}/{alert.service}){duration}. "
            f"Model confidence: {alert.confidence:.1%}. "
            f"Investigation confidence: {correlation.confidence_label} "
            f"({correlation.confidence_score:.0%}).{log_str}"
            f"{succeeded_str}{post_str} "
            f"MITRE: [{threat_intel.mitre_technique_id}] {threat_intel.mitre_technique}."
        )

    # ── Prioritize response actions ───────────────────────────────────────────
    def _prioritize_actions(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
        triage      : Optional[TriageDecision] = None,
    ) -> list[str]:
        # If the LLM provided concrete actions, use those (preferred)
        if triage is not None and triage.recommended_actions:
            actions = []
            if correlation.attack_succeeded or triage.verdict == "true_positive":
                actions.append("🔴 IMMEDIATE: Possible compromise — isolate host now")
            for i, action in enumerate(triage.recommended_actions[:6]):
                prefix = "🟠" if i < 2 else "🟡"
                actions.append(f"{prefix} {action}")
            if threat_intel.what_comes_next:
                actions.append(
                    f"🔍 Monitor for follow-on techniques: "
                    f"{', '.join(threat_intel.what_comes_next[:3])}"
                )
            return actions

        # Fallback: rule-based action prioritization
        actions = []

        # Urgent first if attack succeeded
        if correlation.attack_succeeded:
            actions.append("🔴 IMMEDIATE: Possible compromise confirmed — isolate host now")

        if correlation.post_activity:
            actions.append("🔴 IMMEDIATE: Post-attack activity detected — preserve forensic evidence")

        # Threat intel recommended actions
        for i, action in enumerate(threat_intel.response_actions):
            prefix = "🟠" if i < 2 else "🟡"
            actions.append(f"{prefix} {action}")

        # Follow-on technique awareness
        if threat_intel.what_comes_next:
            actions.append(
                f"🔍 Monitor for follow-on techniques: "
                f"{', '.join(threat_intel.what_comes_next[:3])}"
            )

        return actions

    # ── LLM-powered executive summary ─────────────────────────────────────────
    def _write_llm_summary(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
        triage      : TriageDecision,
    ) -> str:
        """Build executive summary from the LLM triage narrative."""
        verdict_label = {
            "true_positive"  : "TRUE POSITIVE — confirmed attack",
            "false_positive" : "FALSE POSITIVE — safe to close",
            "benign"         : "BENIGN — legitimate activity",
            "escalate"       : "ESCALATE — needs senior analyst review",
        }.get(triage.verdict, triage.verdict.upper())

        return (
            f"[{verdict_label}] (LLM confidence: {triage.confidence:.0%}, "
            f"model: {triage.model_name})\n\n"
            f"{triage.narrative}\n\n"
            f"Network detection: {alert.attack_type} on {correlation.dst_ip} "
            f"(port {alert.dst_port}/{alert.service}). "
            f"Model confidence: {alert.confidence:.1%}. "
            f"Host log events: {correlation.total_log_events}. "
            f"Investigation confidence: {correlation.confidence_label} "
            f"({correlation.confidence_score:.0%}). "
            f"MITRE: [{threat_intel.mitre_technique_id}] {threat_intel.mitre_technique}."
        )

    # ── Console output (rich) ─────────────────────────────────────────────────
    def print_report(self, report: InvestigationReport):
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich import box
            from rich.text import Text
            console = Console()
            self._print_rich(report, console)
        except ImportError:
            self._print_plain(report)

    def _print_rich(self, report: InvestigationReport, console):
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        from rich.text import Text

        alert  = report.alert
        corr   = report.correlation
        ti     = report.threat_intel
        sev    = alert.severity
        color  = SEVERITY_COLOR.get(sev, "white")
        emoji  = SEVERITY_EMOJI.get(sev, "⚪")
        d_emoji= DECISION_EMOJI.get(alert.decision, "❓")

        console.print()
        console.rule(f"[{color}]{emoji} INVESTIGATION REPORT — {report.report_id}[/{color}]")

        # ── Header ────────────────────────────────────────────────────────────
        header = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        header.add_column(style="bold cyan", width=22)
        header.add_column()
        header.add_row("Report ID",      report.report_id)
        header.add_row("Generated",      report.generated_at)
        header.add_row("Verdict",        f"[{color}]{report.verdict}[/{color}]")
        header.add_row("Alert ID",       alert.alert_id)
        header.add_row("Timestamp",      alert.timestamp)
        header.add_row("Target IP",      corr.dst_ip)
        header.add_row("Service",        f"port {alert.dst_port} / {alert.service}")
        header.add_row("Attack Type",    f"[{color}]{alert.attack_type}[/{color}]")
        header.add_row("Decision",       f"{d_emoji} {alert.decision}")
        header.add_row("Severity",       f"[{color}]{sev}[/{color}]")
        header.add_row("Model Conf",     f"{alert.confidence:.1%}")
        header.add_row("Invest. Conf",   f"{corr.confidence_label} ({corr.confidence_score:.0%})")
        console.print(header)

        # ── Executive summary ─────────────────────────────────────────────────
        console.print(Panel(
            report.executive_summary,
            title="[bold]Executive Summary[/bold]",
            border_style=color,
        ))

        # ── LLM triage (if available) ─────────────────────────────────────────
        if report.triage and report.triage.backend != "none":
            triage = report.triage
            # Reasoning steps
            reasoning_text = "\n".join(
                f"  {i+1}. {step}" for i, step in enumerate(triage.reasoning_steps)
            )
            console.print(Panel(
                reasoning_text,
                title=f"[bold]LLM Reasoning — {triage.model_name}[/bold]",
                border_style="bright_blue",
            ))

        # ── MITRE ATT&CK ──────────────────────────────────────────────────────
        mitre_text = (
            f"[bold]Tactic  :[/bold] [{ti.mitre_tactic_id}] {ti.mitre_tactic}\n"
            f"[bold]Technique:[/bold] [{ti.mitre_technique_id}] {ti.mitre_technique}\n"
        )
        if ti.mitre_sub_technique:
            mitre_text += f"[bold]Sub-Tech :[/bold] [{ti.mitre_sub_id}] {ti.mitre_sub_technique}\n"
        mitre_text += f"[bold]Reference:[/bold] {ti.mitre_url}\n"
        mitre_text += f"[bold]Stealth  :[/bold] {ti.stealth_level}"
        console.print(Panel(mitre_text, title="[bold]MITRE ATT&CK[/bold]", border_style="blue"))

        # ── Findings ──────────────────────────────────────────────────────────
        if corr.findings:
            findings_text = "\n".join(f"• {f}" for f in corr.findings)
            console.print(Panel(
                findings_text,
                title="[bold]Correlation Findings[/bold]",
                border_style="yellow",
            ))

        # ── Timeline ──────────────────────────────────────────────────────────
        if corr.timeline:
            tl_table = Table(
                title="Incident Timeline",
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold magenta",
            )
            tl_table.add_column("Time",   style="cyan",  width=22)
            tl_table.add_column("Type",   style="yellow", width=22)
            tl_table.add_column("Detail", style="white")

            for entry in corr.timeline:
                t = entry.get("time", "")[:19]
                tp = entry.get("type", "")
                d  = entry.get("detail", "")[:100]
                tl_table.add_row(t, tp, d)
            console.print(tl_table)

        # ── IOCs ──────────────────────────────────────────────────────────────
        if alert.iocs:
            console.print(
                Panel(
                    "\n".join(f"  • {ioc}" for ioc in alert.iocs),
                    title="[bold]Indicators of Compromise (IOCs)[/bold]",
                    border_style="red",
                )
            )

        # ── Response actions ──────────────────────────────────────────────────
        if report.recommended_actions:
            actions_text = "\n".join(report.recommended_actions)
            console.print(Panel(
                actions_text,
                title="[bold]Recommended Response Actions[/bold]",
                border_style="green",
            ))

        # ── What comes next ───────────────────────────────────────────────────
        if ti.what_comes_next:
            next_text = "\n".join(f"  → {t}" for t in ti.what_comes_next)
            console.print(Panel(
                next_text,
                title="[bold]Watch For — Follow-on Techniques[/bold]",
                border_style="magenta",
            ))

        console.rule(f"[{color}]END OF REPORT — {report.report_id}[/{color}]")
        console.print()

    def _print_plain(self, report: InvestigationReport):
        """Fallback plain-text output when rich is not available."""
        sep = "=" * 70
        print(sep)
        print(f"  INVESTIGATION REPORT — {report.report_id}")
        print(sep)
        print(f"  Verdict  : {report.verdict}")
        print(f"  Alert ID : {report.alert.alert_id}")
        print(f"  Attack   : {report.alert.attack_type}")
        print(f"  Severity : {report.alert.severity}")
        print(f"  Confidence: {report.alert.confidence:.1%}")
        print()
        print("EXECUTIVE SUMMARY")
        print("-" * 70)
        print(report.executive_summary)
        print()
        print("FINDINGS")
        print("-" * 70)
        for f in report.correlation.findings:
            print(f"  • {f}")
        print()
        print("TIMELINE")
        print("-" * 70)
        for entry in report.correlation.timeline:
            print(f"  {entry.get('time','')[:19]}  {entry.get('type',''):<25}  {entry.get('detail','')[:80]}")
        print()
        print("RESPONSE ACTIONS")
        print("-" * 70)
        for action in report.recommended_actions:
            print(f"  {action}")
        print(sep)

    # ── Save report ───────────────────────────────────────────────────────────
    def save(self, report: InvestigationReport) -> Path:
        """Save report as JSON to the reports/ directory."""
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORT_DIR / f"{report.report_id}_{ts}.json"
        path.write_text(report.to_json(), encoding="utf-8")
        return path

    def save_text(self, report: InvestigationReport) -> Path:
        """Save report as plain text."""
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORT_DIR / f"{report.report_id}_{ts}.txt"
        lines = self._build_text_lines(report)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _build_text_lines(self, report: InvestigationReport) -> list[str]:
        sep = "=" * 70
        lines = [
            sep,
            f"  INVESTIGATION REPORT",
            f"  Report ID : {report.report_id}",
            f"  Generated : {report.generated_at}",
            f"  Verdict   : {report.verdict}",
            sep, "",
            "ALERT DETAILS",
            "-" * 70,
            f"  Alert ID    : {report.alert.alert_id}",
            f"  Timestamp   : {report.alert.timestamp}",
            f"  Attack Type : {report.alert.attack_type}",
            f"  Decision    : {report.alert.decision}",
            f"  Severity    : {report.alert.severity}",
            f"  Confidence  : {report.alert.confidence:.1%}",
            f"  Target Port : {report.alert.dst_port} ({report.alert.service})",
            f"  IOCs        : {', '.join(report.alert.iocs)}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 70,
            report.executive_summary,
            "",
            "MITRE ATT&CK",
            "-" * 70,
            f"  Tactic    : [{report.threat_intel.mitre_tactic_id}] {report.threat_intel.mitre_tactic}",
            f"  Technique : [{report.threat_intel.mitre_technique_id}] {report.threat_intel.mitre_technique}",
        ]
        if report.threat_intel.mitre_sub_technique:
            lines.append(
                f"  Sub-Tech  : [{report.threat_intel.mitre_sub_id}] "
                f"{report.threat_intel.mitre_sub_technique}"
            )
        lines += [
            f"  Reference : {report.threat_intel.mitre_url}",
            "",
            "CORRELATION FINDINGS",
            "-" * 70,
        ]
        for f in report.correlation.findings:
            lines.append(f"  • {f}")

        lines += ["", "INCIDENT TIMELINE", "-" * 70]
        for entry in report.correlation.timeline:
            t  = entry.get("time", "")[:19]
            tp = entry.get("type", "")
            d  = entry.get("detail", "")[:100]
            lines.append(f"  {t}  [{tp}]  {d}")

        lines += ["", "RECOMMENDED RESPONSE ACTIONS", "-" * 70]
        for action in report.recommended_actions:
            lines.append(f"  {action}")

        lines += ["", "WATCH FOR — FOLLOW-ON TECHNIQUES", "-" * 70]
        for t in report.threat_intel.what_comes_next:
            lines.append(f"  → {t}")

        lines += ["", sep]
        return lines
