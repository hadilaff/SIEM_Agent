"""
SIEM Alert Layer
────────────────
Sits between the detection models (XGBoost + Isolation Forest)
and the investigation agent.

Responsibilities:
  1. Run inference on a NetFlow record (or batch)
  2. Apply confidence threshold + ISO forest decision logic
  3. Enrich with severity, MITRE ATT&CK, IOCs, description
  4. Return a structured SIEMAlert object

Usage:
    from alert_layer import AlertLayer
    layer = AlertLayer()
    alert = layer.process_flow(flow_dict)
"""

import json
import pickle
import uuid
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import xgboost as xgb

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
MODEL_DIR = Path(__file__).parent / "models"

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
# Maps attack class → (tactic, technique_id, technique_name)
MITRE_MAP = {
    "FTP-BruteForce"  : ("Credential Access", "T1110.001", "Brute Force: Password Guessing - FTP"),
    "SSH-BruteForce"  : ("Credential Access", "T1110.001", "Brute Force: Password Guessing - SSH"),
    "BruteForce-Web"  : ("Credential Access", "T1110.001", "Brute Force: Password Guessing - Web"),
    "BruteForce-XSS"  : ("Initial Access",    "T1189",     "Drive-by Compromise via XSS"),
    "SQL-Injection"   : ("Initial Access",     "T1190",     "Exploit Public-Facing Application"),
    "Bot"             : ("Command and Control","T1071",     "Application Layer Protocol"),
    "DDoS-HOIC"       : ("Impact",             "T1498.001", "Network DoS: Direct Network Flood"),
    "DDoS-LOIC-UDP"   : ("Impact",             "T1498.001", "Network DoS: Direct Network Flood - UDP"),
    "DoS-Hulk"        : ("Impact",             "T1499.001", "Endpoint DoS: OS Exhaustion Flood"),
    "DoS-SlowHTTPTest": ("Impact",             "T1499.002", "Endpoint DoS: Service Exhaustion Flood"),
    "Infiltration"    : ("Lateral Movement",   "T1210",     "Exploitation of Remote Services"),
    "SUSPICIOUS"      : ("Unknown",            "T????",     "Unclassified — manual review required"),
    "UNKNOWN_THREAT"  : ("Unknown",            "T????",     "Anomaly — potential zero-day or novel attack"),
}

# ── Severity rules ────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "FTP-BruteForce"  : "HIGH",
    "SSH-BruteForce"  : "HIGH",
    "BruteForce-Web"  : "HIGH",
    "BruteForce-XSS"  : "MEDIUM",
    "SQL-Injection"   : "HIGH",
    "Bot"             : "HIGH",
    "DDoS-HOIC"       : "CRITICAL",
    "DDoS-LOIC-UDP"   : "CRITICAL",
    "DoS-Hulk"        : "CRITICAL",
    "DoS-SlowHTTPTest": "HIGH",
    "Infiltration"    : "CRITICAL",
    "SUSPICIOUS"      : "MEDIUM",
    "UNKNOWN_THREAT"  : "HIGH",
}

# ── Port → service name ───────────────────────────────────────────────────────
PORT_SERVICE = {
    21  : "FTP",
    22  : "SSH",
    23  : "Telnet",
    25  : "SMTP",
    53  : "DNS",
    80  : "HTTP",
    443 : "HTTPS",
    445 : "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}

# ── Confidence threshold ──────────────────────────────────────────────────────
CONFIDENCE_THRESHOLD = 0.85


# ── Alert dataclass ───────────────────────────────────────────────────────────
@dataclass
class SIEMAlert:
    alert_id      : str
    timestamp     : str
    decision      : str           # KNOWN_ATTACK | SUSPICIOUS | UNKNOWN_THREAT | Benign
    attack_type   : str           # predicted class name
    confidence    : float         # model confidence [0–1]
    severity      : str           # CRITICAL | HIGH | MEDIUM | LOW
    dst_port      : int
    service       : str           # FTP, SSH, HTTP, etc.
    mitre_tactic  : str
    mitre_technique_id  : str
    mitre_technique_name: str
    iocs          : list[str]
    description   : str
    iso_flagged   : bool          # True if Isolation Forest flagged as anomaly
    iso_score     : float         # anomaly score (lower = more anomalous)
    raw_features  : dict          # original 15 features for log search
    all_probs     : dict          # probability per class for transparency

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """One-line summary for console display."""
        return (
            f"[{self.severity:<8}] {self.alert_id} | "
            f"{self.decision:<20} | {self.attack_type:<20} | "
            f"conf={self.confidence:.3f} | port={self.dst_port}({self.service}) | "
            f"ISO={'⚠️ ' if self.iso_flagged else '✅'} | "
            f"{self.mitre_technique_id}"
        )


# ── Alert Layer ───────────────────────────────────────────────────────────────
class AlertLayer:

    def __init__(self, model_dir: Path = MODEL_DIR, confidence_threshold: float = CONFIDENCE_THRESHOLD):
        self.confidence_threshold = confidence_threshold
        self._load_models(model_dir)

    def _load_models(self, model_dir: Path):
        """Load XGBoost, Isolation Forest, LabelEncoder and feature list."""
        self.model = xgb.XGBClassifier()
        self.model.load_model(str(model_dir / "xgb_flow_classifier.json"))

        with open(model_dir / "isolation_forest.pkl", "rb") as f:
            self.iso = pickle.load(f)

        with open(model_dir / "label_encoder.pkl", "rb") as f:
            self.le = pickle.load(f)

        with open(model_dir / "feature_config.json") as f:
            self.features = json.load(f)["features"]

        print(f"[AlertLayer] Models loaded — {len(self.le.classes_)} classes, "
              f"{len(self.features)} features")

    # ── Single flow ───────────────────────────────────────────────────────────
    def process_flow(self, flow: dict) -> Optional[SIEMAlert]:
        """
        Process one NetFlow record.
        Returns SIEMAlert if malicious/suspicious, None if Benign.

        flow: dict with at minimum the 15 feature keys + 'Timestamp'
        """
        X = self._prepare(flow)

        # XGBoost
        probs       = self.model.predict_proba(X)[0]
        pred_idx    = int(probs.argmax())
        pred_class  = self.le.classes_[pred_idx]
        confidence  = float(probs.max())
        all_probs   = {cls: round(float(p), 4)
                       for cls, p in zip(self.le.classes_, probs)}

        # Isolation Forest
        iso_pred  = int(self.iso.predict(X)[0])   # -1=anomaly, 1=normal
        iso_score = float(self.iso.decision_function(X)[0])
        iso_flag  = iso_pred == -1

        # Decision logic
        decision = self._decide(pred_class, confidence, iso_flag)

            # Benign and not flagged by ISO → ignore
        if decision == "Benign":
            return None

        # Build alert
        return self._build_alert(
            flow, decision, pred_class, confidence,
            all_probs, iso_flag, iso_score
        )

    # ── Batch processing ──────────────────────────────────────────────────────
    def process_batch(self, df: pd.DataFrame) -> list[SIEMAlert]:
        """
        Process a DataFrame of flows.
        Returns only the alerts (Benign flows are filtered out).
        """
        alerts = []

        X = df[self.features].apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        probs_all  = self.model.predict_proba(X)
        pred_idxs  = probs_all.argmax(axis=1)
        pred_cls   = self.le.inverse_transform(pred_idxs)
        confs      = probs_all.max(axis=1)

        iso_preds  = self.iso.predict(X)
        iso_scores = self.iso.decision_function(X)

        for i, row in df.iterrows():
            flow       = row.to_dict()
            pred_class = pred_cls[i - df.index[0]] if isinstance(i, int) else pred_cls[list(df.index).index(i)]
            confidence = float(confs[i - df.index[0]] if isinstance(i, int) else confs[list(df.index).index(i)])
            iso_flag   = iso_preds[i - df.index[0]] == -1 if isinstance(i, int) else iso_preds[list(df.index).index(i)] == -1
            iso_score  = float(iso_scores[i - df.index[0]] if isinstance(i, int) else iso_scores[list(df.index).index(i)])
            all_probs  = {cls: round(float(p), 4)
                          for cls, p in zip(self.le.classes_,
                          probs_all[i - df.index[0]] if isinstance(i, int) else probs_all[list(df.index).index(i)])}

            decision = self._decide(pred_class, confidence, iso_flag)
            if decision == "Benign":
                continue

            alert = self._build_alert(
                flow, decision, pred_class, confidence,
                all_probs, iso_flag, iso_score
            )
            alerts.append(alert)

        return alerts

    # ── Decision logic ────────────────────────────────────────────────────────
    def _decide(self, pred_class: str, confidence: float, iso_flag: bool) -> str:
        if confidence < self.confidence_threshold:
            return "SUSPICIOUS"
        if pred_class != "Benign":
            return "KNOWN_ATTACK"
        if iso_flag:
            return "UNKNOWN_THREAT"
        return "Benign"

    # ── Build alert object ────────────────────────────────────────────────────
    def _build_alert(
        self,
        flow      : dict,
        decision  : str,
        pred_class: str,
        confidence: float,
        all_probs : dict,
        iso_flag  : bool,
        iso_score : float,
    ) -> SIEMAlert:

        # Resolve attack type for enrichment lookups
        enrich_key = pred_class if decision == "KNOWN_ATTACK" else decision

        dst_port = int(flow.get("Dst Port", 0))

        # Drop port 0 flows — protocol artifacts, not real attacks
        if dst_port == 0:
            return None

        service  = PORT_SERVICE.get(dst_port, f"port/{dst_port}")
        ts       = flow.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        mitre    = MITRE_MAP.get(enrich_key, MITRE_MAP["SUSPICIOUS"])
        severity = SEVERITY_MAP.get(enrich_key, "MEDIUM")

        iocs = self._extract_iocs(flow, dst_port, service, pred_class)

        description = self._describe(
            decision, pred_class, confidence,
            dst_port, service, ts, iso_flag, flow
        )

        return SIEMAlert(
            alert_id            = f"ALT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
            timestamp           = str(ts),
            decision            = decision,
            attack_type         = pred_class,
            confidence          = round(confidence, 4),
            severity            = severity,
            dst_port            = dst_port,
            service             = service,
            mitre_tactic        = mitre[0],
            mitre_technique_id  = mitre[1],
            mitre_technique_name= mitre[2],
            iocs                = iocs,
            description         = description,
            iso_flagged         = iso_flag,
            iso_score           = round(iso_score, 4),
            raw_features        = {k: flow.get(k) for k in self.features},
            all_probs           = all_probs,
        )

    # ── IOC extraction ────────────────────────────────────────────────────────
    def _extract_iocs(self, flow: dict, dst_port: int, service: str, pred_class: str) -> list[str]:
        iocs = []

        if dst_port:
            iocs.append(f"port:{dst_port}")
        if service:
            iocs.append(f"service:{service}")

        # Flow-based IOCs
        pkts_s = float(flow.get("Flow Pkts/s", 0) or 0)
        if pkts_s > 10_000:
            iocs.append(f"high_packet_rate:{pkts_s:.0f}_pkt/s")

        duration = float(flow.get("Flow Duration", 0) or 0)
        if duration < 100 and pred_class in ("FTP-BruteForce", "SSH-BruteForce"):
            iocs.append("micro_flow:possible_credential_stuffing")

        fwd_pkts = float(flow.get("Tot Fwd Pkts", 0) or 0)
        bwd_pkts = float(flow.get("Tot Bwd Pkts", 0) or 0)
        if fwd_pkts == 1 and bwd_pkts == 1:
            iocs.append("single_packet_exchange:typical_brute_force_attempt")

        return iocs

    # ── Description generator ─────────────────────────────────────────────────
    def _describe(
        self,
        decision   : str,
        pred_class : str,
        confidence : float,
        dst_port   : int,
        service    : str,
        timestamp  : str,
        iso_flag   : bool,
        flow       : dict,
    ) -> str:

        pkts_s   = float(flow.get("Flow Pkts/s", 0) or 0)
        duration = float(flow.get("Flow Duration", 0) or 0)

        if decision == "KNOWN_ATTACK":
            return (
                f"Detected {pred_class} attack targeting {service} (port {dst_port}) "
                f"at {timestamp}. Model confidence: {confidence:.1%}. "
                f"Flow rate: {pkts_s:,.0f} pkt/s over {duration:.0f}µs. "
                f"MITRE: {MITRE_MAP.get(pred_class, ('','',''))[1]}."
            )
        elif decision == "SUSPICIOUS":
            return (
                f"Suspicious flow to {service} (port {dst_port}) at {timestamp}. "
                f"Model predicted {pred_class} but with low confidence ({confidence:.1%} < "
                f"{self.confidence_threshold:.0%} threshold). Manual review recommended."
            )
        elif decision == "UNKNOWN_THREAT":
            return (
                f"Anomalous flow to {service} (port {dst_port}) at {timestamp}. "
                f"XGBoost classified as Benign but Isolation Forest flagged it as an anomaly "
                f"(score={flow.get('iso_score', 'N/A')}). Potential unknown or novel attack. "
                f"Immediate investigation recommended."
            )
        return "No threat detected."

    # ── Preprocess single flow ────────────────────────────────────────────────
    def _prepare(self, flow: dict) -> pd.DataFrame:
        row = {}
        for feat in self.features:
            val = flow.get(feat, 0)
            try:
                val = float(val)
            except (TypeError, ValueError):
                val = 0.0
            if np.isinf(val) or np.isnan(val):
                val = 0.0
            row[feat] = val
        return pd.DataFrame([row])
