"""
Correlator Module
─────────────────
Links a SIEMAlert (network-level detection) to host log events.
Answers the key SOC questions:

  1. Do log events confirm the attack?
  2. Was the attack successful? (e.g. login succeeded after brute force)
  3. Is there post-attack activity? (lateral movement, file access)
  4. What is the attack timeline?
  5. What is the overall confidence of the investigation?
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from log_search import LogEvent

# ── Correlation patterns per attack type ──────────────────────────────────────
# Each attack maps to:
#   success_patterns  : log patterns suggesting the attack SUCCEEDED
#   activity_patterns : log patterns suggesting post-attack activity
#   noise_patterns    : patterns to ignore (benign system activity)

CORRELATION_RULES = {
    "FTP-BruteForce": {
        "success_patterns" : [
            r"ftpd.*login",
            r"vsftpd.*OK LOGIN",
            r"proftpd.*Accepted",
            r"USER.*logged in",
            r"530.*Login incorrect",   # many failures = brute force
            r"ftp.*session opened",
        ],
        "activity_patterns": [
            r"ftp.*STOR",              # file upload after login
            r"ftp.*RETR",              # file download
            r"ftp.*MKD",               # directory created
        ],
        "noise_patterns"   : [r"dhclient", r"CRON", r"systemd.*Daily"],
    },
    "SSH-BruteForce": {
        "success_patterns" : [
            r"sshd.*Accepted password",
            r"sshd.*Accepted publickey",
            r"sshd.*session opened for user",
            r"Failed password.*ssh",   # many failures = brute force
        ],
        "activity_patterns": [
            r"sudo",
            r"useradd|adduser",
            r"passwd",
            r"chmod|chown",
            r"crontab",
            r"bash.*history",
        ],
        "noise_patterns"   : [r"dhclient", r"CRON", r"systemd.*Daily"],
    },
    "DDoS-HOIC": {
        "success_patterns" : [
            r"apache.*error",
            r"nginx.*error",
            r"kernel.*connection.*refused",
            r"Out of memory",
            r"Too many open files",
        ],
        "activity_patterns": [r"service.*restart", r"oom.*kill"],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "DoS-Hulk": {
        "success_patterns" : [
            r"apache.*error",
            r"connection.*reset",
            r"timeout",
            r"server.*unavailable",
        ],
        "activity_patterns": [r"service.*restart", r"memory.*exhausted"],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "DoS-SlowHTTPTest": {
        "success_patterns" : [
            r"apache.*timeout",
            r"connection.*timeout",
            r"keepalive.*timeout",
        ],
        "activity_patterns": [r"apache.*restart"],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "Bot": {
        "success_patterns" : [
            r"outbound.*connection",
            r"irc.*connect",
            r"c2.*beacon",
            r"wget|curl",
            r"base64",
        ],
        "activity_patterns": [
            r"crontab.*modified",
            r"new.*process",
            r"network.*scan",
            r"port.*scan",
        ],
        "noise_patterns"   : [r"dhclient", r"CRON.*sessionclean"],
    },
    "Infiltration": {
        "success_patterns" : [
            r"new.*session",
            r"sudo.*command",
            r"privilege.*escalat",
            r"root.*access",
        ],
        "activity_patterns": [
            r"useradd|adduser",
            r"ssh.*tunnel",
            r"netcat|nc\s",
            r"wget|curl",
            r"chmod.*777",
        ],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "SQL-Injection": {
        "success_patterns" : [
            r"mysql.*error",
            r"sql.*syntax",
            r"database.*error",
            r"SELECT.*FROM",
            r"UNION.*SELECT",
        ],
        "activity_patterns": [
            r"mysql.*root",
            r"mysqldump",
            r"database.*export",
        ],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "BruteForce-Web": {
        "success_patterns" : [
            r"http.*200.*POST.*login",
            r"authentication.*success",
            r"session.*created",
        ],
        "activity_patterns": [
            r"admin.*access",
            r"file.*upload",
            r"shell.*upload",
        ],
        "noise_patterns"   : [r"dhclient", r"CRON"],
    },
    "SUSPICIOUS": {
        "success_patterns" : [r"error", r"fail", r"denied"],
        "activity_patterns": [r"connection", r"access"],
        "noise_patterns"   : [r"dhclient", r"CRON", r"systemd.*Daily"],
    },
    "UNKNOWN_THREAT": {
        "success_patterns" : [r"error", r"fail", r"denied", r"refused"],
        "activity_patterns": [r"connection", r"access", r"new.*process"],
        "noise_patterns"   : [r"dhclient", r"CRON", r"systemd.*Daily"],
    },
}

# Windows Event IDs that matter for security
WINDOWS_SECURITY_EVENTS = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4634": "Logoff",
    "4648": "Logon with explicit credentials",
    "4672": "Special privileges assigned",
    "4688": "New process created",
    "4698": "Scheduled task created",
    "4720": "User account created",
    "4732": "Member added to security group",
    "4776": "Credential validation",
    "7036": "Service state change",
    "7045": "New service installed",
}


# ── Correlation result ─────────────────────────────────────────────────────────
@dataclass
class CorrelationResult:
    alert_id          : str
    attack_type       : str
    dst_ip            : str
    attack_start      : datetime
    attack_end        : datetime

    # Log evidence
    total_log_events  : int = 0
    success_evidence  : list[LogEvent] = field(default_factory=list)
    activity_evidence : list[LogEvent] = field(default_factory=list)
    windows_security  : list[LogEvent] = field(default_factory=list)
    all_events        : list[LogEvent] = field(default_factory=list)

    # Findings
    attack_confirmed  : bool  = False
    attack_succeeded  : bool  = False
    post_activity     : bool  = False
    confidence_score  : float = 0.0   # 0.0 – 1.0
    confidence_label  : str   = "LOW"
    findings          : list[str] = field(default_factory=list)
    timeline          : list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_id"         : self.alert_id,
            "attack_type"      : self.attack_type,
            "dst_ip"           : self.dst_ip,
            "attack_start"     : self.attack_start.isoformat(),
            "attack_end"       : self.attack_end.isoformat(),
            "total_log_events" : self.total_log_events,
            "attack_confirmed" : self.attack_confirmed,
            "attack_succeeded" : self.attack_succeeded,
            "post_activity"    : self.post_activity,
            "confidence_score" : self.confidence_score,
            "confidence_label" : self.confidence_label,
            "findings"         : self.findings,
            "timeline"         : self.timeline,
            "success_evidence" : [e.to_dict() for e in self.success_evidence[:5]],
            "activity_evidence": [e.to_dict() for e in self.activity_evidence[:5]],
            "windows_security" : [e.to_dict() for e in self.windows_security[:5]],
        }


# ── Correlator ────────────────────────────────────────────────────────────────
class Correlator:

    def correlate(
        self,
        alert_id    : str,
        attack_type : str,
        dst_ip      : str,
        attack_start: datetime,
        attack_end  : datetime,
        log_events  : list[LogEvent],
    ) -> CorrelationResult:
        """
        Correlate network alert with host log events.
        Returns a CorrelationResult with findings and confidence score.
        """
        result = CorrelationResult(
            alert_id     = alert_id,
            attack_type  = attack_type,
            dst_ip       = dst_ip,
            attack_start = attack_start,
            attack_end   = attack_end,
        )

        if not log_events:
            result.findings.append("No log events found for this IP in the time window.")
            result.confidence_score = 0.1
            result.confidence_label = "LOW"
            return result

        result.total_log_events = len(log_events)
        result.all_events = log_events

        # Get rules for this attack type
        rules = CORRELATION_RULES.get(
            attack_type,
            CORRELATION_RULES["SUSPICIOUS"]
        )

        # ── Filter noise ──────────────────────────────────────────────────────
        noise_pats = [re.compile(p, re.IGNORECASE) for p in rules["noise_patterns"]]
        clean_events = [
            e for e in log_events
            if not any(p.search(e.message) for p in noise_pats)
        ]

        # ── Match success patterns ────────────────────────────────────────────
        success_pats = [re.compile(p, re.IGNORECASE) for p in rules["success_patterns"]]
        for ev in clean_events:
            if any(p.search(ev.message) for p in success_pats):
                result.success_evidence.append(ev)

        # ── Match post-attack activity ────────────────────────────────────────
        activity_pats = [re.compile(p, re.IGNORECASE) for p in rules["activity_patterns"]]
        post_window_end = attack_end + timedelta(hours=2)
        for ev in clean_events:
            if ev.timestamp and ev.timestamp > attack_end and ev.timestamp <= post_window_end:
                if any(p.search(ev.message) for p in activity_pats):
                    result.activity_evidence.append(ev)

        # ── Windows security events ───────────────────────────────────────────
        for ev in log_events:
            if ev.log_type == "windows" and ev.event_id in WINDOWS_SECURITY_EVENTS:
                ev_copy     = ev
                ev_copy.message = f"{WINDOWS_SECURITY_EVENTS[ev.event_id]}: {ev.message}"
                result.windows_security.append(ev_copy)

        # ── Build timeline ────────────────────────────────────────────────────
        result.timeline = self._build_timeline(
            attack_start, attack_end,
            result.success_evidence,
            result.activity_evidence,
            result.windows_security,
        )

        # ── Determine findings ────────────────────────────────────────────────
        result.attack_confirmed = len(clean_events) > 0
        result.attack_succeeded = len(result.success_evidence) > 0
        result.post_activity    = len(result.activity_evidence) > 0

        result.findings = self._generate_findings(result, attack_type)

        # ── Score confidence ──────────────────────────────────────────────────
        result.confidence_score, result.confidence_label = self._score_confidence(result)

        return result

    # ── Timeline builder ──────────────────────────────────────────────────────
    def _build_timeline(
        self,
        attack_start : datetime,
        attack_end   : datetime,
        success_evs  : list[LogEvent],
        activity_evs : list[LogEvent],
        windows_evs  : list[LogEvent],
    ) -> list[dict]:
        timeline = []

        # Attack start
        timeline.append({
            "time"  : attack_start.isoformat(),
            "type"  : "ATTACK_START",
            "detail": "Network-level attack traffic detected by model",
        })

        # Success evidence
        for ev in sorted(success_evs, key=lambda e: e.timestamp or datetime.max)[:5]:
            timeline.append({
                "time"  : ev.timestamp.isoformat() if ev.timestamp else "unknown",
                "type"  : "SUCCESS_EVIDENCE",
                "detail": ev.message[:200],
                "source": ev.log_type,
            })

        # Windows security events
        for ev in sorted(windows_evs, key=lambda e: e.timestamp or datetime.max)[:5]:
            timeline.append({
                "time"  : ev.timestamp.isoformat() if ev.timestamp else "unknown",
                "type"  : f"WINDOWS_EVENT_{ev.event_id}",
                "detail": ev.message[:200],
                "source": "windows",
            })

        # Attack end
        timeline.append({
            "time"  : attack_end.isoformat(),
            "type"  : "ATTACK_END",
            "detail": "Attack traffic subsided",
        })

        # Post-attack activity
        for ev in sorted(activity_evs, key=lambda e: e.timestamp or datetime.max)[:5]:
            timeline.append({
                "time"  : ev.timestamp.isoformat() if ev.timestamp else "unknown",
                "type"  : "POST_ATTACK_ACTIVITY",
                "detail": ev.message[:200],
                "source": ev.log_type,
            })

        # Sort by time
        def sort_key(entry):
            try:
                return datetime.fromisoformat(entry["time"])
            except (ValueError, TypeError):
                return datetime.max

        timeline.sort(key=sort_key)
        return timeline

    # ── Findings generator ────────────────────────────────────────────────────
    def _generate_findings(self, result: CorrelationResult, attack_type: str) -> list[str]:
        findings = []

        findings.append(
            f"Network alert: {attack_type} detected on {result.dst_ip} "
            f"from {result.attack_start.strftime('%H:%M:%S')} "
            f"to {result.attack_end.strftime('%H:%M:%S')}."
        )

        if result.total_log_events > 0:
            findings.append(
                f"Found {result.total_log_events} log events for this host "
                f"in the investigation window."
            )
        else:
            findings.append("No host logs found for this IP — may be a Windows-only host.")

        if result.attack_succeeded:
            findings.append(
                f"CRITICAL: {len(result.success_evidence)} log event(s) suggest "
                f"the attack may have SUCCEEDED. Immediate action required."
            )
            for ev in result.success_evidence[:3]:
                findings.append(f"  Evidence: {ev.message[:150]}")
        else:
            findings.append("No evidence found that the attack succeeded.")

        if result.post_activity:
            findings.append(
                f"WARNING: {len(result.activity_evidence)} suspicious event(s) "
                f"detected AFTER the attack — possible post-compromise activity."
            )
            for ev in result.activity_evidence[:3]:
                findings.append(f"  Activity: {ev.message[:150]}")

        if result.windows_security:
            findings.append(
                f"Windows security events: {len(result.windows_security)} relevant "
                f"events found (logon attempts, process creation, etc.)"
            )

        return findings

    # ── Confidence scoring ────────────────────────────────────────────────────
    def _score_confidence(self, result: CorrelationResult) -> tuple[float, str]:
        score = 0.0

        # Base: alert fired
        score += 0.3

        # Log events found
        if result.total_log_events > 0:
            score += 0.2

        # Success evidence
        if result.attack_succeeded:
            score += 0.3

        # Post-attack activity
        if result.post_activity:
            score += 0.1

        # Windows security events
        if result.windows_security:
            score += 0.1

        score = min(score, 1.0)

        if score >= 0.8:
            label = "HIGH"
        elif score >= 0.5:
            label = "MEDIUM"
        else:
            label = "LOW"

        return round(score, 2), label
