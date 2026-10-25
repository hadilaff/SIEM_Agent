"""
Threat Intelligence Module
──────────────────────────
Enriches a SIEMAlert with:
  1. Full MITRE ATT&CK context (tactic, technique, sub-technique, description)
  2. Attack pattern profile (behavior, tools, indicators)
  3. Recommended response actions
  4. Related attack techniques (what usually follows this attack)
  5. Severity justification

No external API required — all knowledge is embedded as a structured
local database aligned with CSE-CIC-IDS2018 attack classes.
"""

from dataclasses import dataclass, field
from typing import Optional


# ── MITRE ATT&CK knowledge base ───────────────────────────────────────────────
# Aligned with the 12 classes in the trained model
THREAT_INTEL_DB = {

    "FTP-BruteForce": {
        "mitre": {
            "tactic"          : "Credential Access",
            "tactic_id"       : "TA0006",
            "technique"       : "Brute Force",
            "technique_id"    : "T1110",
            "sub_technique"   : "Password Guessing",
            "sub_technique_id": "T1110.001",
            "url"             : "https://attack.mitre.org/techniques/T1110/001/",
        },
        "profile": {
            "description": (
                "Adversaries attempt to gain access to an FTP service by "
                "systematically trying username/password combinations. "
                "FTP (port 21) transmits credentials in plaintext, making "
                "it a high-value target for credential harvesting."
            ),
            "typical_tools"   : ["Hydra", "Medusa", "Ncrack", "Metasploit"],
            "indicators"      : [
                "High volume of short TCP flows to port 21",
                "Repeated 530 (Login incorrect) FTP responses",
                "Single-packet exchanges at high frequency",
                "Flow duration < 100 microseconds",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "LOW — very noisy, easy to detect",
        },
        "what_comes_next": [
            "T1078 — Valid Accounts (if credentials found)",
            "T1048 — Exfiltration over FTP",
            "T1105 — Ingress Tool Transfer via FTP",
        ],
        "response_actions": [
            "Block source IP at firewall immediately",
            "Lock affected FTP accounts temporarily",
            "Check FTP logs for any successful logins",
            "Disable plain FTP — migrate to SFTP (port 22)",
            "Enable account lockout after N failed attempts",
            "Review files uploaded/downloaded if login succeeded",
        ],
        "severity_justification": (
            "HIGH — FTP brute force can lead to full credential compromise. "
            "FTP is unencrypted so captured credentials expose plaintext passwords."
        ),
    },

    "SSH-BruteForce": {
        "mitre": {
            "tactic"          : "Credential Access",
            "tactic_id"       : "TA0006",
            "technique"       : "Brute Force",
            "technique_id"    : "T1110",
            "sub_technique"   : "Password Guessing",
            "sub_technique_id": "T1110.001",
            "url"             : "https://attack.mitre.org/techniques/T1110/001/",
        },
        "profile": {
            "description": (
                "Adversaries systematically attempt SSH credentials to gain "
                "remote shell access. SSH (port 22) provides full system access "
                "if compromised, making it one of the most critical brute force targets."
            ),
            "typical_tools"   : ["Hydra", "Medusa", "Patator", "Crowbar"],
            "indicators"      : [
                "High volume of flows to port 22",
                "Repeated authentication failures in auth.log",
                "Multiple flows with 22 forward + 22 backward packets",
                "Consistent inter-arrival timing (automated tool signature)",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "LOW — high volume, detectable in auth logs",
        },
        "what_comes_next": [
            "T1078 — Valid Accounts (shell access if credentials found)",
            "T1059 — Command and Scripting Interpreter",
            "T1053 — Scheduled Task/Job (persistence)",
            "T1021 — Remote Services (lateral movement)",
        ],
        "response_actions": [
            "Block source IP at firewall",
            "Check auth.log for 'Accepted password' after failed attempts",
            "Disable password authentication — enforce SSH key pairs only",
            "Move SSH to non-standard port",
            "Deploy fail2ban or equivalent",
            "Audit all active SSH sessions immediately",
        ],
        "severity_justification": (
            "HIGH — Successful SSH brute force gives full shell access. "
            "Attacker can pivot to other systems, exfiltrate data, or install malware."
        ),
    },

    "Bot": {
        "mitre": {
            "tactic"          : "Command and Control",
            "tactic_id"       : "TA0011",
            "technique"       : "Application Layer Protocol",
            "technique_id"    : "T1071",
            "sub_technique"   : "Web Protocols",
            "sub_technique_id": "T1071.001",
            "url"             : "https://attack.mitre.org/techniques/T1071/",
        },
        "profile": {
            "description": (
                "A compromised host is communicating with a Command & Control (C2) "
                "server. The bot receives instructions, participates in botnets for "
                "DDoS, spam, or credential theft, and may exfiltrate data."
            ),
            "typical_tools"   : ["IRC-based bots", "HTTP bots", "Zeus", "Mirai"],
            "indicators"      : [
                "Periodic beaconing to external IPs",
                "Connections to unusual ports (8080, 6667 IRC)",
                "Low-and-slow persistent connections",
                "DNS queries to dynamic DNS providers",
            ],
            "attack_duration" : "Persistent — ongoing until remediated",
            "stealth_level"   : "HIGH — blends with normal traffic",
        },
        "what_comes_next": [
            "T1498 — Network Denial of Service (DDoS participation)",
            "T1041 — Exfiltration Over C2 Channel",
            "T1105 — Ingress Tool Transfer (download more malware)",
            "T1021 — Lateral Movement to other hosts",
        ],
        "response_actions": [
            "Isolate infected host from network immediately",
            "Block C2 IP/domain at firewall and DNS",
            "Capture memory dump for forensic analysis",
            "Scan all hosts in same subnet for similar beaconing",
            "Reimage infected host after forensics",
            "Identify initial infection vector (phishing, exploit)",
        ],
        "severity_justification": (
            "HIGH — Active botnet infection means the host is under adversary control. "
            "Can be used for DDoS, data theft, or as pivot point."
        ),
    },

    "DDoS-HOIC": {
        "mitre": {
            "tactic"          : "Impact",
            "tactic_id"       : "TA0040",
            "technique"       : "Network Denial of Service",
            "technique_id"    : "T1498",
            "sub_technique"   : "Direct Network Flood",
            "sub_technique_id": "T1498.001",
            "url"             : "https://attack.mitre.org/techniques/T1498/001/",
        },
        "profile": {
            "description": (
                "High Orbit Ion Cannon (HOIC) is used to flood HTTP/HTTPS targets "
                "with high-volume requests from multiple sources. "
                "Designed to overwhelm web servers and take services offline."
            ),
            "typical_tools"   : ["HOIC", "LOIC", "Botnets"],
            "indicators"      : [
                "Extremely high packet rate (>100k pkt/s)",
                "Large number of flows targeting port 80/443",
                "Multiple source IPs (coordinated attack)",
                "HTTP GET/POST floods",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "VERY LOW — highly visible volumetric attack",
        },
        "what_comes_next": [
            "T1499 — Endpoint Denial of Service (application layer)",
            "T1491 — Defacement (if service goes down)",
        ],
        "response_actions": [
            "Activate DDoS mitigation / scrubbing service (Cloudflare, AWS Shield)",
            "Apply rate limiting on web server",
            "Block attacking IP ranges at upstream provider",
            "Enable geo-blocking if attack originates from specific regions",
            "Scale up server capacity if cloud-based",
            "Notify ISP for upstream filtering",
        ],
        "severity_justification": (
            "CRITICAL — Service availability directly impacted. "
            "Can cause complete outage of internet-facing services."
        ),
    },

    "DDoS-LOIC-UDP": {
        "mitre": {
            "tactic"          : "Impact",
            "tactic_id"       : "TA0040",
            "technique"       : "Network Denial of Service",
            "technique_id"    : "T1498",
            "sub_technique"   : "Direct Network Flood",
            "sub_technique_id": "T1498.001",
            "url"             : "https://attack.mitre.org/techniques/T1498/001/",
        },
        "profile": {
            "description": (
                "Low Orbit Ion Cannon (LOIC) UDP flood sends massive volumes of "
                "UDP packets to exhaust target bandwidth and resources. "
                "UDP floods are harder to filter than TCP as they are connectionless."
            ),
            "typical_tools"   : ["LOIC", "UDP flood scripts"],
            "indicators"      : [
                "Massive UDP packet volume",
                "Random destination ports",
                "High bandwidth consumption",
                "ICMP port unreachable responses",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "VERY LOW — volumetric, immediately visible",
        },
        "what_comes_next": [
            "T1498.001 — Continued flood from additional sources",
            "T1491 — Defacement after service disruption",
        ],
        "response_actions": [
            "Enable UDP flood protection at network edge",
            "Apply ACLs to block UDP traffic from attacking sources",
            "Contact upstream ISP for traffic scrubbing",
            "Implement BCP38 anti-spoofing filtering",
        ],
        "severity_justification": (
            "CRITICAL — UDP floods can saturate network links completely, "
            "causing collateral damage to all services on the network."
        ),
    },

    "DoS-Hulk": {
        "mitre": {
            "tactic"          : "Impact",
            "tactic_id"       : "TA0040",
            "technique"       : "Endpoint Denial of Service",
            "technique_id"    : "T1499",
            "sub_technique"   : "OS Exhaustion Flood",
            "sub_technique_id": "T1499.001",
            "url"             : "https://attack.mitre.org/techniques/T1499/001/",
        },
        "profile": {
            "description": (
                "HULK (HTTP Unbearable Load King) generates unique HTTP GET requests "
                "per connection to bypass caching. Each request consumes server "
                "resources until the web server becomes unresponsive."
            ),
            "typical_tools"   : ["HULK", "Custom HTTP flood scripts"],
            "indicators"      : [
                "High volume unique HTTP GET requests to port 80",
                "Bypasses CDN/cache (each URL is unique)",
                "Rapid connection establishment and teardown",
                "Server CPU and memory spikes",
            ],
            "attack_duration" : "Minutes",
            "stealth_level"   : "LOW — visible in web server access logs",
        },
        "what_comes_next": [
            "T1499.002 — Service Exhaustion Flood (escalation)",
            "T1491.002 — External Defacement",
        ],
        "response_actions": [
            "Enable rate limiting per IP on web server (nginx/apache)",
            "Deploy Web Application Firewall (WAF)",
            "Block attacking IPs at load balancer",
            "Enable connection rate limiting",
            "Scale horizontally if cloud-based",
        ],
        "severity_justification": (
            "CRITICAL — Targets web server directly. Cache bypass means "
            "CDN protection is ineffective. Can take down service quickly."
        ),
    },

    "DoS-SlowHTTPTest": {
        "mitre": {
            "tactic"          : "Impact",
            "tactic_id"       : "TA0040",
            "technique"       : "Endpoint Denial of Service",
            "technique_id"    : "T1499",
            "sub_technique"   : "Service Exhaustion Flood",
            "sub_technique_id": "T1499.002",
            "url"             : "https://attack.mitre.org/techniques/T1499/002/",
        },
        "profile": {
            "description": (
                "Slowloris-style attack holds HTTP connections open by sending "
                "partial requests slowly. This exhausts the server's connection "
                "pool without requiring high bandwidth."
            ),
            "typical_tools"   : ["SlowHTTPTest", "Slowloris", "R-U-Dead-Yet (RUDY)"],
            "indicators"      : [
                "Many long-duration connections to port 80",
                "Low bandwidth but high connection count",
                "Connection pool exhaustion",
                "Server keeps connections in ESTABLISHED state",
            ],
            "attack_duration" : "Minutes to hours (persistent low-rate)",
            "stealth_level"   : "MEDIUM — low bandwidth may evade threshold alerts",
        },
        "what_comes_next": [
            "T1499.001 — Escalation to high-volume flood",
            "T1491.002 — Defacement",
        ],
        "response_actions": [
            "Set aggressive connection timeouts on web server",
            "Limit max connections per IP",
            "Deploy reverse proxy (nginx) in front of vulnerable server",
            "Enable mod_reqtimeout (Apache) or equivalent",
        ],
        "severity_justification": (
            "HIGH — Low-bandwidth attack can take down servers with few connections. "
            "Hard to detect without connection-count monitoring."
        ),
    },

    "Infiltration": {
        "mitre": {
            "tactic"          : "Lateral Movement",
            "tactic_id"       : "TA0008",
            "technique"       : "Exploitation of Remote Services",
            "technique_id"    : "T1210",
            "sub_technique"   : None,
            "sub_technique_id": None,
            "url"             : "https://attack.mitre.org/techniques/T1210/",
        },
        "profile": {
            "description": (
                "An adversary has gained initial access and is moving laterally "
                "within the network. Infiltration involves exploiting internal "
                "services, pivoting through compromised hosts, and establishing "
                "persistence for long-term access."
            ),
            "typical_tools"   : ["Metasploit", "Cobalt Strike", "PsExec", "Mimikatz"],
            "indicators"      : [
                "Unusual internal traffic patterns",
                "Access to multiple internal services",
                "Credential dumping activity",
                "New scheduled tasks or services",
                "Data staging before exfiltration",
            ],
            "attack_duration" : "Hours to days (persistent)",
            "stealth_level"   : "HIGH — designed to blend with normal traffic",
        },
        "what_comes_next": [
            "T1003 — OS Credential Dumping",
            "T1078 — Valid Accounts (using stolen credentials)",
            "T1041 — Exfiltration Over C2 Channel",
            "T1486 — Data Encrypted for Impact (ransomware)",
        ],
        "response_actions": [
            "IMMEDIATE: Isolate affected hosts from network",
            "Revoke all active sessions and credentials on affected systems",
            "Engage incident response team",
            "Preserve forensic evidence before remediation",
            "Identify patient zero — initial entry point",
            "Scan entire network for indicators of compromise",
            "Review privileged account activity",
        ],
        "severity_justification": (
            "CRITICAL — Active adversary inside the network. "
            "Can lead to data breach, ransomware, or full domain compromise."
        ),
    },

    "SQL-Injection": {
        "mitre": {
            "tactic"          : "Initial Access",
            "tactic_id"       : "TA0001",
            "technique"       : "Exploit Public-Facing Application",
            "technique_id"    : "T1190",
            "sub_technique"   : None,
            "sub_technique_id": None,
            "url"             : "https://attack.mitre.org/techniques/T1190/",
        },
        "profile": {
            "description": (
                "Adversaries inject malicious SQL code into web application inputs "
                "to manipulate the backend database. Can lead to data extraction, "
                "authentication bypass, and in some cases remote code execution."
            ),
            "typical_tools"   : ["sqlmap", "Havij", "manual injection"],
            "indicators"      : [
                "SQL keywords in HTTP parameters (SELECT, UNION, DROP)",
                "Unusual database error messages in responses",
                "HTTP 500 errors correlated with injection attempts",
                "Large data responses to simple queries",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "MEDIUM — visible in web logs but may bypass simple IDS",
        },
        "what_comes_next": [
            "T1005 — Data from Local System (database dump)",
            "T1059 — Command Execution via xp_cmdshell",
            "T1078 — Valid Accounts (bypass authentication)",
            "T1190 — Further exploitation of web application",
        ],
        "response_actions": [
            "Block attacking IP at WAF immediately",
            "Review database query logs for exfiltrated data",
            "Patch or sanitize vulnerable input fields",
            "Use parameterized queries / prepared statements",
            "Assess what data may have been exposed",
            "Notify data protection officer if PII was accessed",
        ],
        "severity_justification": (
            "HIGH — Can expose entire database contents including credentials, "
            "PII, and business-critical data."
        ),
    },

    "BruteForce-Web": {
        "mitre": {
            "tactic"          : "Credential Access",
            "tactic_id"       : "TA0006",
            "technique"       : "Brute Force",
            "technique_id"    : "T1110",
            "sub_technique"   : "Password Guessing",
            "sub_technique_id": "T1110.001",
            "url"             : "https://attack.mitre.org/techniques/T1110/001/",
        },
        "profile": {
            "description": (
                "Adversaries attempt to compromise web application login forms by "
                "systematically trying credentials. Targets admin panels, CMS logins, "
                "and other web-based authentication endpoints."
            ),
            "typical_tools"   : ["Burp Suite Intruder", "Hydra", "Medusa", "custom scripts"],
            "indicators"      : [
                "High volume POST requests to login endpoints",
                "HTTP 401/403 responses at high frequency",
                "Same source IP targeting /admin, /login, /wp-login",
            ],
            "attack_duration" : "Minutes to hours",
            "stealth_level"   : "LOW to MEDIUM",
        },
        "what_comes_next": [
            "T1078 — Valid Accounts (admin access)",
            "T1505.003 — Web Shell upload",
            "T1190 — Further application exploitation",
        ],
        "response_actions": [
            "Block source IP at WAF",
            "Implement CAPTCHA on login forms",
            "Enable account lockout policy",
            "Enforce MFA on all web admin panels",
            "Check for successful logins from the attacking IP",
        ],
        "severity_justification": (
            "HIGH — Web admin access can lead to full application compromise, "
            "data theft, and web shell installation."
        ),
    },

    "BruteForce-XSS": {
        "mitre": {
            "tactic"          : "Initial Access",
            "tactic_id"       : "TA0001",
            "technique"       : "Drive-by Compromise",
            "technique_id"    : "T1189",
            "sub_technique"   : None,
            "sub_technique_id": None,
            "url"             : "https://attack.mitre.org/techniques/T1189/",
        },
        "profile": {
            "description": (
                "Cross-Site Scripting (XSS) attacks inject malicious scripts into "
                "web pages. Reflected XSS can steal session cookies, redirect users, "
                "or execute actions on behalf of victims."
            ),
            "typical_tools"   : ["XSSer", "Burp Suite", "manual probing"],
            "indicators"      : [
                "Script tags in HTTP parameters (<script>, onerror=)",
                "JavaScript event handlers in inputs",
                "Encoded payloads (%3Cscript%3E)",
            ],
            "attack_duration" : "Short (scanning phase)",
            "stealth_level"   : "MEDIUM",
        },
        "what_comes_next": [
            "T1539 — Steal Web Session Cookie",
            "T1185 — Browser Session Hijacking",
            "T1566 — Phishing via injected content",
        ],
        "response_actions": [
            "Deploy Content Security Policy (CSP) headers",
            "Sanitize all user inputs server-side",
            "Implement output encoding",
            "Review web application for XSS vulnerabilities",
            "Block attacking IP at WAF",
        ],
        "severity_justification": (
            "MEDIUM — XSS requires victim interaction but can lead to "
            "session hijacking and credential theft."
        ),
    },

    "SUSPICIOUS": {
        "mitre": {
            "tactic"          : "Unknown",
            "tactic_id"       : "TA????",
            "technique"       : "Unclassified",
            "technique_id"    : "T????",
            "sub_technique"   : None,
            "sub_technique_id": None,
            "url"             : "https://attack.mitre.org/",
        },
        "profile": {
            "description": (
                "Suspicious traffic detected with low model confidence. "
                "The pattern does not clearly match any known attack class. "
                "Could be a novel attack, misconfiguration, or rare legitimate traffic."
            ),
            "typical_tools"   : ["Unknown"],
            "indicators"      : ["Low classification confidence", "Unusual flow patterns"],
            "attack_duration" : "Unknown",
            "stealth_level"   : "UNKNOWN",
        },
        "what_comes_next": ["Manual investigation required"],
        "response_actions": [
            "Flag for manual analyst review",
            "Capture full packet trace for deeper analysis",
            "Compare against threat intelligence feeds",
            "Check if source IP appears in known malicious IP lists",
        ],
        "severity_justification": (
            "MEDIUM — Uncertain classification. Could be benign or novel threat."
        ),
    },

    "UNKNOWN_THREAT": {
        "mitre": {
            "tactic"          : "Unknown",
            "tactic_id"       : "TA????",
            "technique"       : "Potential Zero-Day or Novel Attack",
            "technique_id"    : "T????",
            "sub_technique"   : None,
            "sub_technique_id": None,
            "url"             : "https://attack.mitre.org/",
        },
        "profile": {
            "description": (
                "Anomalous traffic flagged by Isolation Forest as deviating "
                "significantly from normal baseline. The XGBoost classifier "
                "could not map it to any known attack class. This could indicate "
                "a zero-day exploit, novel attack technique, or insider threat."
            ),
            "typical_tools"   : ["Unknown — potential zero-day"],
            "indicators"      : [
                "Anomaly score well below normal baseline",
                "Traffic pattern unlike any trained class",
            ],
            "attack_duration" : "Unknown",
            "stealth_level"   : "POTENTIALLY HIGH",
        },
        "what_comes_next": ["Unknown — requires full forensic investigation"],
        "response_actions": [
            "IMMEDIATE: Isolate affected host",
            "Capture full packet trace",
            "Submit traffic sample to threat intelligence platform",
            "Engage threat hunting team",
            "Preserve all logs for forensic analysis",
        ],
        "severity_justification": (
            "HIGH — Unknown threat with confirmed anomalous behavior. "
            "Treat as high priority until proven otherwise."
        ),
    },
}


# ── Threat Intel result ────────────────────────────────────────────────────────
@dataclass
class ThreatIntelResult:
    attack_type        : str
    mitre_tactic       : str
    mitre_tactic_id    : str
    mitre_technique    : str
    mitre_technique_id : str
    mitre_sub_technique: Optional[str]
    mitre_sub_id       : Optional[str]
    mitre_url          : str
    description        : str
    typical_tools      : list[str]
    indicators         : list[str]
    attack_duration    : str
    stealth_level      : str
    what_comes_next    : list[str]
    response_actions   : list[str]
    severity_justification: str

    def to_dict(self) -> dict:
        return {
            "attack_type"          : self.attack_type,
            "mitre_tactic"         : f"[{self.mitre_tactic_id}] {self.mitre_tactic}",
            "mitre_technique"      : f"[{self.mitre_technique_id}] {self.mitre_technique}",
            "mitre_sub_technique"  : f"[{self.mitre_sub_id}] {self.mitre_sub_technique}"
                                     if self.mitre_sub_technique else None,
            "mitre_url"            : self.mitre_url,
            "description"          : self.description,
            "typical_tools"        : self.typical_tools,
            "indicators"           : self.indicators,
            "attack_duration"      : self.attack_duration,
            "stealth_level"        : self.stealth_level,
            "what_comes_next"      : self.what_comes_next,
            "response_actions"     : self.response_actions,
            "severity_justification": self.severity_justification,
        }

    def summary(self) -> str:
        sub = f" > {self.mitre_sub_id}" if self.mitre_sub_id else ""
        return (
            f"{self.mitre_tactic_id} {self.mitre_tactic} | "
            f"{self.mitre_technique_id}{sub} {self.mitre_technique} | "
            f"Stealth: {self.stealth_level}"
        )


# ── Threat Intel Lookup ───────────────────────────────────────────────────────
class ThreatIntel:

    def lookup(self, attack_type: str) -> ThreatIntelResult:
        """
        Look up threat intelligence for a given attack type.
        Falls back to SUSPICIOUS profile for unknown types.
        """
        data = THREAT_INTEL_DB.get(attack_type, THREAT_INTEL_DB["SUSPICIOUS"])

        return ThreatIntelResult(
            attack_type            = attack_type,
            mitre_tactic           = data["mitre"]["tactic"],
            mitre_tactic_id        = data["mitre"]["tactic_id"],
            mitre_technique        = data["mitre"]["technique"],
            mitre_technique_id     = data["mitre"]["technique_id"],
            mitre_sub_technique    = data["mitre"]["sub_technique"],
            mitre_sub_id           = data["mitre"]["sub_technique_id"],
            mitre_url              = data["mitre"]["url"],
            description            = data["profile"]["description"],
            typical_tools          = data["profile"]["typical_tools"],
            indicators             = data["profile"]["indicators"],
            attack_duration        = data["profile"]["attack_duration"],
            stealth_level          = data["profile"]["stealth_level"],
            what_comes_next        = data["what_comes_next"],
            response_actions       = data["response_actions"],
            severity_justification = data["severity_justification"],
        )

    def get_response_actions(self, attack_type: str) -> list[str]:
        """Quick access to response actions only."""
        data = THREAT_INTEL_DB.get(attack_type, THREAT_INTEL_DB["SUSPICIOUS"])
        return data["response_actions"]

    def get_what_comes_next(self, attack_type: str) -> list[str]:
        """Quick access to follow-on techniques."""
        data = THREAT_INTEL_DB.get(attack_type, THREAT_INTEL_DB["SUSPICIOUS"])
        return data["what_comes_next"]

    def list_known_attacks(self) -> list[str]:
        """Return all attack types in the knowledge base."""
        return list(THREAT_INTEL_DB.keys())
