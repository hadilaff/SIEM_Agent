"""
LLM Triage Layer
────────────────
Uses a Large Language Model to reason over the structured evidence
collected by the rest of the pipeline and produce a SOC triage decision:

  Verdict options (matching real SOAR systems):
    - true_positive   : confirmed real attack, requires response
    - false_positive  : noise / misclassification, safe to close
    - benign          : legitimate activity incorrectly flagged
    - escalate        : uncertain or critical — needs senior analyst

Backend is swappable. Built-in backends:
  - GroqBackend    : free API, Llama-3.3-70B, fast (recommended)
  - OllamaBackend  : local offline, when Ollama is installed
  - NoLLMBackend   : fallback when no LLM is available — returns
                     the deterministic rule-based verdict

API key lookup order:
  1. Environment variable  GROQ_API_KEY
  2. Config file           ~/.siem_agent_config.json  → {"groq_api_key": "..."}
  3. Config file           siem_agent/.config.json    → {"groq_api_key": "..."}

If no key is found, automatically falls back to NoLLMBackend.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from alert_layer      import SIEMAlert
from correlator       import CorrelationResult
from threat_intel     import ThreatIntelResult

# ── Config paths ──────────────────────────────────────────────────────────────
CONFIG_PATHS = [
    Path.home() / ".siem_agent_config.json",
    Path(__file__).parent / ".config.json",
]

# Default model on Groq free tier
GROQ_MODEL = "openai/gpt-oss-120b"


# ── Triage decision ───────────────────────────────────────────────────────────
@dataclass
class TriageDecision:
    verdict             : str          # true_positive | false_positive | benign | escalate
    confidence          : float        # 0.0 – 1.0  (LLM's self-reported confidence)
    narrative           : str          # natural-language reasoning + conclusion
    recommended_actions : list[str]    # concrete next steps for the analyst
    reasoning_steps     : list[str]    # chain-of-thought, transparent reasoning
    model_name          : str          # which LLM produced this (for audit trail)
    backend             : str          # "groq" | "ollama" | "none"
    raw_response        : str          # full raw model output, for debugging

    # Allowed verdicts
    VALID = {"true_positive", "false_positive", "benign", "escalate"}

    def __post_init__(self):
        if self.verdict not in self.VALID:
            # Coerce unknown verdicts to "escalate" (safe default)
            self.verdict = "escalate"

    def to_dict(self) -> dict:
        return asdict(self)

    def is_attack(self) -> bool:
        return self.verdict == "true_positive"

    def needs_human(self) -> bool:
        return self.verdict in ("escalate",)


# ── Backend interface ─────────────────────────────────────────────────────────
class LLMBackend(Protocol):
    """Any LLM backend must implement this."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return the model's text response given system + user prompts."""
        ...

    @property
    def name(self) -> str:
        ...


# ── Groq backend ──────────────────────────────────────────────────────────────
class GroqBackend:
    """Free-tier Groq API backend. Uses Llama-3.3-70B by default."""

    def __init__(self, api_key: str, model: str = GROQ_MODEL):
        try:
            from groq import Groq
        except ImportError as e:
            raise RuntimeError(
                "groq SDK not installed — run: pip install groq"
            ) from e

        self.client = Groq(api_key=api_key)
        self.model   = model
        self._name   = f"groq:{model}"

    @property
    def name(self) -> str:
        return self._name

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Call Groq chat completion with JSON response format."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.2,        # low temperature → consistent triage
            max_tokens=1500,
            response_format={"type": "json_object"},  # strict JSON output
        )
        return response.choices[0].message.content


# ── Ollama backend (offline fallback) ─────────────────────────────────────────
class OllamaBackend:
    """Local Ollama backend. Requires `ollama serve` running locally."""

    def __init__(self, model: str = "llama3.2:3b", host: str = "http://localhost:11434"):
        import urllib.request
        self.model = model
        self.host  = host.rstrip("/")
        self._name = f"ollama:{model}"

    @property
    def name(self) -> str:
        return self._name

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request, json as _json
        payload = _json.dumps({
            "model"  : self.model,
            "stream" : False,
            "format" : "json",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "options": {"temperature": 0.2},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = _json.loads(r.read())
        return data["message"]["content"]


# ── No-LLM fallback (deterministic rule-based verdict) ─────────────────────────
class NoLLMBackend:
    """
    Used when no LLM API key is available.
    Produces a verdict using the existing deterministic rules so the
    pipeline keeps working without an LLM.
    """

    @property
    def name(self) -> str:
        return "none:rule-based"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        # NoLLMBackend is handled specially in LLMTriage._fallback_decision
        # so this method is never actually called.
        raise NotImplementedError("NoLLMBackend does not call an LLM")


# ── LLM Triage ────────────────────────────────────────────────────────────────
class LLMTriage:

    def __init__(self, backend: Optional[LLMBackend] = None, verbose: bool = True):
        self.verbose = verbose

        if backend is not None:
            self.backend = backend
        else:
            # Auto-detect: try Groq, then Ollama, then fall back
            self.backend = self._auto_detect_backend()

        if self.verbose:
            print(f"[LLMTriage] Backend: {self.backend.name}")

    # ── Auto-detect a working backend ──────────────────────────────────────────
    @staticmethod
    def _auto_detect_backend() -> LLMBackend:
        # 1. Try Groq
        api_key = LLMTriage._load_groq_key()
        if api_key:
            try:
                return GroqBackend(api_key=api_key)
            except Exception as e:
                print(f"[LLMTriage] Groq key found but backend failed: {e}")

        # 2. Try Ollama (localhost)
        try:
            import urllib.request
            req = urllib.request.Request("http://localhost:11434/api/tags")
            with urllib.request.urlopen(req, timeout=2) as r:
                if r.status == 200:
                    return OllamaBackend()
        except Exception:
            pass

        # 3. Fallback
        return NoLLMBackend()

    @staticmethod
    def _load_groq_key() -> Optional[str]:
        # Env var
        key = os.environ.get("GROQ_API_KEY")
        if key:
            return key.strip()

        # Config files
        for path in CONFIG_PATHS:
            if path.exists():
                try:
                    cfg = json.loads(path.read_text())
                    key = cfg.get("groq_api_key") or cfg.get("groq", {}).get("api_key")
                    if key:
                        return key.strip()
                except (json.JSONDecodeError, KeyError):
                    continue
        return None

    # ── Main entry ────────────────────────────────────────────────────────────
    def triage(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
    ) -> TriageDecision:
        """Produce a triage decision by reasoning over the evidence."""

        # Fallback path when no LLM is configured
        if isinstance(self.backend, NoLLMBackend):
            return self._fallback_decision(alert, correlation, threat_intel)

        # Build prompts
        system_prompt = self._build_system_prompt()
        user_prompt   = self._build_user_prompt(alert, correlation, threat_intel)

        # Call LLM
        try:
            raw = self.backend.complete(system_prompt, user_prompt)
        except Exception as e:
            if self.verbose:
                print(f"[LLMTriage] LLM call failed: {e} — using fallback")
            return self._fallback_decision(alert, correlation, threat_intel, error=str(e))

        # Parse JSON response
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Model didn't return valid JSON — try to extract
            data = self._extract_json(raw) or {}

        return TriageDecision(
            verdict             = data.get("verdict", "escalate"),
            confidence          = float(data.get("confidence", 0.5)),
            narrative           = data.get("narrative", raw[:500]),
            recommended_actions = data.get("recommended_actions", []),
            reasoning_steps     = data.get("reasoning_steps", []),
            model_name          = self.backend.name,
            backend             = "groq" if isinstance(self.backend, GroqBackend) else "ollama",
            raw_response        = raw,
        )

    # ── System prompt ─────────────────────────────────────────────────────────
    def _build_system_prompt(self) -> str:
        return (
            "You are a Senior SOC L1/L2 analyst triaging security alerts. "
            "You reason about network alerts and host log evidence using MITRE ATT&CK.\n\n"
            "Your job: read the structured evidence and decide ONE of four triage verdicts:\n"
            "  - true_positive   : confirmed real attack, requires response\n"
            "  - false_positive  : noise or misclassification, safe to close\n"
            "  - benign           : legitimate activity incorrectly flagged\n"
            "  - escalate         : uncertain or too critical — needs senior analyst\n\n"
            "Rules:\n"
            "  1. Reason step-by-step before deciding. Show your reasoning.\n"
            "  2. If host logs show successful login AFTER brute force → true_positive.\n"
            "  3. If only network detection, no host evidence → still true_positive if "
            "model confidence is high (>0.85), otherwise escalate.\n"
            "  4. If the flow is clearly normal traffic the model misclassified "
            "(port 0, internal DHCP, etc.) → false_positive.\n"
            "  5. Confidence is YOUR confidence in the verdict (0.0–1.0), not the model's.\n"
            "  6. Recommended actions must be concrete and specific to this incident.\n\n"
            "Respond ONLY with a JSON object in exactly this schema:\n"
            "{\n"
            "  \"verdict\": \"true_positive|false_positive|benign|escalate\",\n"
            "  \"confidence\": 0.0–1.0,\n"
            "  \"reasoning_steps\": [\"step 1\", \"step 2\", ...],\n"
            "  \"narrative\": \"one paragraph conclusion for the analyst\",\n"
            "  \"recommended_actions\": [\"action 1\", \"action 2\", ...]\n"
            "}"
        )

    # ── User prompt with all evidence ──────────────────────────────────────────
    def _build_user_prompt(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
    ) -> str:

        # Log evidence summary (cap to keep prompt small)
        log_events_summary = "No host log events found."
        if correlation.total_log_events > 0:
            sample = [
                f"  - [{e.log_type}] {e.message[:120]}"
                for e in correlation.all_events[:8]
            ]
            log_events_summary = (
                f"Found {correlation.total_log_events} log events. Sample:\n"
                + "\n".join(sample)
            )

        # Success evidence
        success_summary = "None"
        if correlation.success_evidence:
            success_summary = "\n".join(
                f"  - {e.message[:150]}" for e in correlation.success_evidence[:5]
            )

        # Windows security events
        win_summary = "None"
        if correlation.windows_security:
            win_summary = "\n".join(
                f"  - EventID {e.event_id}: {e.message[:120]}"
                for e in correlation.windows_security[:5]
            )

        # Timeline
        timeline_str = "\n".join(
            f"  - {t.get('time','')[:19]} [{t.get('type','')}] {t.get('detail','')[:100]}"
            for t in correlation.timeline[:10]
        )

        return (
            f"INVESTIGATE THIS ALERT AND GIVE A TRIAGE VERDICT.\n\n"
            f"=== ALERT ===\n"
            f"alert_id      : {alert.alert_id}\n"
            f"timestamp     : {alert.timestamp}\n"
            f"attack_type   : {alert.attack_type}\n"
            f"decision      : {alert.decision}   (KNOWN_ATTACK / SUSPICIOUS / UNKNOWN_THREAT)\n"
            f"model_conf   : {alert.confidence:.3f}\n"
            f"severity      : {alert.severity}\n"
            f"dst_port      : {alert.dst_port} ({alert.service})\n"
            f"iocs          : {', '.join(alert.iocs)}\n"
            f"description   : {alert.description}\n\n"
            f"=== MITRE ATT&CK CONTEXT ===\n"
            f"tactic        : [{threat_intel.mitre_tactic_id}] {threat_intel.mitre_tactic}\n"
            f"technique     : [{threat_intel.mitre_technique_id}] {threat_intel.mitre_technique}\n"
            f"description   : {threat_intel.description}\n"
            f"stealth_level : {threat_intel.stealth_level}\n"
            f"typical_tools : {', '.join(threat_intel.typical_tools)}\n"
            f"what_comes_next: {', '.join(threat_intel.what_comes_next[:3])}\n\n"
            f"=== HOST LOG CORRELATION ===\n"
            f"total_log_events   : {correlation.total_log_events}\n"
            f"attack_confirmed   : {correlation.attack_confirmed}\n"
            f"attack_succeeded   : {correlation.attack_succeeded}\n"
            f"post_activity      : {correlation.post_activity}\n"
            f"invest_confidence  : {correlation.confidence_label} ({correlation.confidence_score:.2f})\n"
            f"success_evidence   :\n{success_summary}\n"
            f"windows_security   :\n{win_summary}\n"
            f"log_events_sample  :\n{log_events_summary}\n\n"
            f"=== FINDINGS ===\n"
            + "\n".join(f"  - {f}" for f in correlation.findings)
            + f"\n\n=== TIMELINE ===\n{timeline_str}\n\n"
            f"Now produce your triage verdict as JSON."
        )

    # ── Fallback decision when no LLM is available ─────────────────────────────
    def _fallback_decision(
        self,
        alert       : SIEMAlert,
        correlation : CorrelationResult,
        threat_intel: ThreatIntelResult,
        error       : Optional[str] = None,
    ) -> TriageDecision:
        """Rule-based verdict — used when LLM unavailable or fails."""
        if alert.decision == "UNKNOWN_THREAT":
            verdict = "escalate"
        elif alert.confidence >= 0.95 and correlation.attack_succeeded:
            verdict = "true_positive"
        elif alert.confidence >= 0.85 and correlation.attack_confirmed:
            verdict = "true_positive"
        elif alert.confidence >= 0.85:
            verdict = "true_positive"
        elif alert.decision == "SUSPICIOUS":
            verdict = "escalate"
        else:
            verdict = "false_positive"

        conf = max(alert.confidence, correlation.confidence_score)

        narrative = (
            f"[rule-based fallback"
            + (f" — LLM error: {error}" if error else "")
            + f"] Verdict: {verdict}. "
            f"Network detection classified as {alert.attack_type} with "
            f"{alert.confidence:.1%} model confidence. "
            f"Host log correlation: {correlation.confidence_label}. "
            f"MITRE: {threat_intel.mitre_technique_id}."
        )

        return TriageDecision(
            verdict             = verdict,
            confidence          = round(conf, 3),
            narrative           = narrative,
            recommended_actions = threat_intel.response_actions[:3],
            reasoning_steps     = [
                "LLM unavailable — using deterministic rule-based verdict",
                f"Model confidence: {alert.confidence:.3f}",
                f"Attack confirmed by logs: {correlation.attack_confirmed}",
                f"Attack succeeded: {correlation.attack_succeeded}",
            ],
            model_name          = "none",
            backend             = "none",
            raw_response        = "",
        )

    # ── JSON extraction (fallback if model doesn't return clean JSON) ──────────
    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """Try to pull a JSON object out of a non-conforming response."""
        import re
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                return None
        return None


# ── Helper: how to set up the Groq key ────────────────────────────────────────
def print_setup_instructions():
    """Print how to configure the Groq API key."""
    print(
        "\n  To enable LLM triage with Groq:\n"
        "  1. Get a free API key at: https://console.groq.com/keys\n"
        "  2. Set it via one of:\n"
        f"     export GROQ_API_KEY='your-key-here'\n"
        f"     OR create {CONFIG_PATHS[0]} with: "
        "{\"groq_api_key\": \"your-key-here\"}\n"
        "  3. Re-run the agent. It will auto-detect the key.\n"
        "  Without a key, the agent falls back to the rule-based triage.\n"
    )
