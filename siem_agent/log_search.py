"""
Log Search Module
─────────────────
Queries Ubuntu syslog and Windows .evtx log files from the ZIP archive.
Given an IP address and a time window, returns all relevant log events.

Supports:
  - Ubuntu plain-text syslogs  (U172.31.69.x)
  - Windows EVTX binary logs   (*.evtx)
"""

import io
import os
import re
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
ZIP_PATH = Path(__file__).parent.parent / "cse_logs_14_02-20261012T095300Z-1-001.zip"

# Windows EVTX XML namespace
EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Syslog date format (no year — dataset is Feb 2018)
SYSLOG_YEAR = 2018


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class LogEvent:
    timestamp  : Optional[datetime]
    source_ip  : str
    log_type   : str          # "windows" | "ubuntu"
    event_id   : Optional[str]
    process    : Optional[str]
    message    : str
    raw        : str

    def to_dict(self) -> dict:
        return {
            "timestamp" : self.timestamp.isoformat() if self.timestamp else None,
            "source_ip" : self.source_ip,
            "log_type"  : self.log_type,
            "event_id"  : self.event_id,
            "process"   : self.process,
            "message"   : self.message,
        }

    def __str__(self) -> str:
        ts  = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "unknown"
        eid = f" [EventID:{self.event_id}]" if self.event_id else ""
        proc = f" ({self.process})" if self.process else ""
        return f"[{ts}] [{self.log_type.upper()}]{eid}{proc} {self.message}"


# ── Log Search ────────────────────────────────────────────────────────────────
class LogSearch:

    def __init__(self, zip_path: Path = ZIP_PATH):
        if not zip_path.exists():
            raise FileNotFoundError(f"Log archive not found: {zip_path}")
        self.zip_path = zip_path
        self._index  = None   # lazy-loaded: {ip → [zip_entry_names]}

    # ── Public API ────────────────────────────────────────────────────────────
    def search(
        self,
        ip           : str,
        start_time   : datetime,
        end_time     : datetime,
        window_minutes: int = 30,
    ) -> list[LogEvent]:
        """
        Search all logs for events related to `ip` within the time window.
        Expands window by window_minutes on each side to catch context.
        Returns events sorted by timestamp.
        """
        # Expand window slightly to catch surrounding context
        t_start = start_time - timedelta(minutes=window_minutes)
        t_end   = end_time   + timedelta(minutes=window_minutes)

        events = []
        events += self._search_ubuntu(ip, t_start, t_end)
        events += self._search_windows(ip, t_start, t_end)

        # Sort by timestamp (None timestamps go last)
        events.sort(key=lambda e: e.timestamp or datetime.max)
        return events

    def search_by_port(
        self,
        port        : int,
        start_time  : datetime,
        end_time    : datetime,
    ) -> list[LogEvent]:
        """Search logs for any mention of a specific port."""
        events = []
        t_start = start_time - timedelta(minutes=30)
        t_end   = end_time   + timedelta(minutes=30)

        with zipfile.ZipFile(self.zip_path) as z:
            ubuntu_files = [f for f in z.namelist() if "/logs/U" in f]
            for zname in ubuntu_files:
                ip = zname.split("/")[-1].replace("U", "")
                content = z.read(zname).decode("utf-8", errors="replace")
                for line in content.splitlines():
                    if str(port) in line:
                        ev = self._parse_syslog_line(line, ip)
                        if ev and self._in_window(ev.timestamp, t_start, t_end):
                            events.append(ev)

        events.sort(key=lambda e: e.timestamp or datetime.max)
        return events

    def list_available_ips(self) -> dict:
        """Return dict of {ip: [log_files]} available in the archive."""
        if self._index:
            return self._index

        index = {}
        with zipfile.ZipFile(self.zip_path) as z:
            for name in z.namelist():
                fname = name.split("/")[-1]
                # Ubuntu: U172.31.69.25
                if fname.startswith("U") and re.match(r"U\d+\.\d+\.\d+\.\d+", fname):
                    ip = fname[1:]
                    index.setdefault(ip, []).append(name)
                # Windows: WIN-xxx-172.31.65.47.evtx or PC1-172.31.64.21.evtx
                elif fname.endswith(".evtx"):
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\.evtx$", fname)
                    if m:
                        ip = m.group(1)
                        index.setdefault(ip, []).append(name)

        self._index = index
        return index

    # ── Ubuntu syslog search ──────────────────────────────────────────────────
    def _search_ubuntu(
        self, ip: str, t_start: datetime, t_end: datetime
    ) -> list[LogEvent]:
        events = []
        ubuntu_ip = f"U{ip}"

        with zipfile.ZipFile(self.zip_path) as z:
            ubuntu_files = [
                f for f in z.namelist()
                if f.split("/")[-1] == ubuntu_ip or ip in f.split("/")[-1]
            ]

            for zname in ubuntu_files:
                src_ip = zname.split("/")[-1].replace("U", "")
                try:
                    content = z.read(zname).decode("utf-8", errors="replace")
                except Exception:
                    continue

                for line in content.splitlines():
                    ev = self._parse_syslog_line(line, src_ip)
                    if ev and self._in_window(ev.timestamp, t_start, t_end):
                        events.append(ev)

        return events

    # ── Windows EVTX search ───────────────────────────────────────────────────
    def _search_windows(
        self, ip: str, t_start: datetime, t_end: datetime
    ) -> list[LogEvent]:
        events   = []
        index    = self.list_available_ips()
        log_files = index.get(ip, [])

        if not log_files:
            return events

        try:
            import Evtx.Evtx as evtx_lib
        except ImportError:
            return events

        with zipfile.ZipFile(self.zip_path) as z:
            for zname in log_files:
                if not zname.endswith(".evtx"):
                    continue
                try:
                    data = z.read(zname)
                    with tempfile.TemporaryDirectory() as tmpdir:
                        fpath = os.path.join(tmpdir, "log.evtx")
                        with open(fpath, "wb") as f:
                            f.write(data)
                        with evtx_lib.Evtx(fpath) as log:
                            for record in log.records():
                                ev = self._parse_evtx_record(record.xml(), ip)
                                if ev and self._in_window(ev.timestamp, t_start, t_end):
                                    events.append(ev)
                except Exception:
                    continue

        return events

    # ── Parsers ───────────────────────────────────────────────────────────────
    def _parse_syslog_line(self, line: str, ip: str) -> Optional[LogEvent]:
        """Parse a syslog-format line: 'Feb 14 10:33:26 hostname process[pid]: message'"""
        # Pattern: Month Day HH:MM:SS hostname process[pid]: message
        pattern = r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$"
        m = re.match(pattern, line.strip())
        if not m:
            return None

        ts_str, process, message = m.group(1), m.group(2), m.group(3)

        try:
            ts = datetime.strptime(f"{SYSLOG_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

        return LogEvent(
            timestamp = ts,
            source_ip = ip,
            log_type  = "ubuntu",
            event_id  = None,
            process   = process,
            message   = message.strip(),
            raw       = line,
        )

    def _parse_evtx_record(self, xml_str: str, ip: str) -> Optional[LogEvent]:
        """Parse a Windows EVTX XML record."""
        try:
            root = ET.fromstring(xml_str)
            ns   = {"e": EVTX_NS}

            # Timestamp
            ts_el = root.find(".//e:TimeCreated", ns)
            ts    = None
            if ts_el is not None:
                ts_str = ts_el.get("SystemTime", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("+00:00", ""))
                except ValueError:
                    pass

            # Event ID
            eid_el  = root.find(".//e:EventID", ns)
            event_id = eid_el.text if eid_el is not None else None

            # Provider / process
            prov_el = root.find(".//e:Provider", ns)
            process = None
            if prov_el is not None:
                process = prov_el.get("Name", None)

            # Message — collect EventData values
            data_els = root.findall(".//e:EventData/e:Data", ns)
            if data_els:
                parts = []
                for d in data_els:
                    name = d.get("Name", "")
                    val  = d.text or ""
                    if val.strip():
                        parts.append(f"{name}={val}" if name else val)
                message = " | ".join(parts)
            else:
                message = xml_str[200:400].replace("\n", " ")

            return LogEvent(
                timestamp = ts,
                source_ip = ip,
                log_type  = "windows",
                event_id  = event_id,
                process   = process,
                message   = message.strip(),
                raw       = xml_str,
            )
        except ET.ParseError:
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _in_window(ts: Optional[datetime], t_start: datetime, t_end: datetime) -> bool:
        if ts is None:
            return False
        # Make both timezone-naive for comparison
        ts_naive = ts.replace(tzinfo=None) if ts.tzinfo else ts
        return t_start <= ts_naive <= t_end
