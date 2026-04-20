"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DETECTION RULES — NETWORK                                                  ║
║  MITRE ATT&CK: T1071 (C2), T1105 (Tool Transfer), T1048 (Exfiltration)    ║
║                                                                              ║
║  Rules detect:                                                               ║
║    - Reverse shells (LOLBin → suspicious port)                              ║
║    - C2 beaconing (regular outbound intervals)                              ║
║    - Office apps making network connections (phishing callback)             ║
║    - Script interpreters making direct network calls                        ║
║    - Known suspicious destination ports                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
from typing import Optional, Dict, List
from datetime import datetime, timezone
from detection_engine.event_schema import (
    BaseEvent, NetworkConnectEvent, ProcessCreateEvent, DetectionAlert
)
from detection_engine.rules.base_rule import BaseRule


# Common attacker tool ports — connecting here is almost always malicious
SUSPICIOUS_PORTS = {
    4444, 4445, 4446,         # Metasploit defaults
    1234, 1235,               # Common test shell ports
    9001, 9002,               # Common C2 ports / Tor
    6666, 6667, 6668, 6669,   # IRC (old C2 method)
    1337, 31337,              # "Elite" hacker ports
    8888, 8889,               # Jupyter/common alternates
    2222,                     # Alt SSH
    5555,                     # Android Debug Bridge / common C2
    7777, 7788,               # Common custom backdoors
}

# Processes that should NEVER initiate outbound connections
NO_NETWORK_PROCESSES = {
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "write.exe", "charmap.exe", "magnify.exe", "narrator.exe",
    "sndvol.exe", "control.exe",
}

# LOLBins (living-off-the-land binaries) that attackers abuse for networking
LOLBIN_NETWORK = {
    "certutil.exe",     # Download via -urlcache -split -f
    "bitsadmin.exe",    # Background file transfer (BITS)
    "regsvr32.exe",     # Squiblydoo — execute remote script
    "rundll32.exe",     # Execute DLL functions
    "msiexec.exe",      # Execute remote MSI packages
    "installutil.exe",  # AppLocker bypass + download
    "cmstp.exe",        # Execute remote INF files
    "wmic.exe",         # Remote execution via WMI
    "mshta.exe",        # Execute remote HTA files
    "cmd.exe",          # Shell connecting out
    "powershell.exe",   # Handled by PS rules but also here for port checks
    "pwsh.exe",
}

# Office applications — should never make raw TCP connections
OFFICE_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe", "mspub.exe",
}


class LOLBinNetworkConnectionRule(BaseRule):
    """
    Detects LOLBins (living-off-the-land binaries) making outbound connections.

    These Windows built-in tools are frequently abused to download payloads
    or establish C2 channels because they're trusted and often whitelisted.
    A network connection FROM certutil.exe, bitsadmin.exe, etc. is almost
    always malicious in a standard environment.
    """
    rule_id = "NET001"
    rule_name = "LOLBin Network Connection"
    description = "Built-in Windows binary making outbound network connection — LOLBin abuse"
    mitre_tactic = "Command and Control"
    mitre_technique_id = "T1105"
    mitre_technique_name = "Ingress Tool Transfer"
    severity = 8
    event_types = (NetworkConnectEvent,)

    def evaluate(self, event: NetworkConnectEvent) -> Optional[DetectionAlert]:
        if not event.is_outbound:
            return None
        if event.image_name not in LOLBIN_NETWORK:
            return None

        desc = (
            f"LOLBin '{event.image_name}' made outbound network connection to "
            f"{event.destination_hostname or event.destination_ip}:{event.destination_port}. "
            f"This is a common attacker technique to download tools or establish C2. "
            f"User: {event.user}"
        )
        return self._make_alert(event, desc)


class SuspiciousPortConnectionRule(BaseRule):
    """
    Detects outbound connections to ports commonly used for reverse shells and C2.

    Port 4444 is Metasploit's default. Ports 6666/6667 are IRC C2.
    When ANY process connects to these, it warrants investigation.
    """
    rule_id = "NET002"
    rule_name = "Connection to Suspicious Port"
    description = "Outbound connection to port commonly used for reverse shells or C2"
    mitre_tactic = "Command and Control"
    mitre_technique_id = "T1071"
    mitre_technique_name = "Application Layer Protocol"
    severity = 9
    event_types = (NetworkConnectEvent,)

    def evaluate(self, event: NetworkConnectEvent) -> Optional[DetectionAlert]:
        if not event.is_outbound:
            return None
        if event.destination_port not in SUSPICIOUS_PORTS:
            return None

        desc = (
            f"Process '{event.image_name}' connected to suspicious port "
            f"{event.destination_port} at {event.destination_hostname or event.destination_ip}. "
            f"Port {event.destination_port} is commonly used for reverse shells/C2. "
            f"PID: {event.process_id}, User: {event.user}"
        )
        return self._make_alert(event, desc)


class OfficeAppNetworkConnectionRule(BaseRule):
    """
    Detects Office applications making raw outbound TCP connections.

    Legitimate Office apps use the HTTP stack through system APIs — not raw
    socket connections. A direct TCP connection from Word or Excel usually
    means a malicious macro is calling back to an attacker-controlled server.

    Note: Outlook is excluded here because it legitimately makes connections,
    but we still flag it when on suspicious ports.
    """
    rule_id = "NET003"
    rule_name = "Office Application Outbound Connection"
    description = "Office application making outbound connection — possible macro C2 callback"
    mitre_tactic = "Command and Control"
    mitre_technique_id = "T1071.001"
    mitre_technique_name = "Web Protocols"
    severity = 8
    event_types = (NetworkConnectEvent,)

    def evaluate(self, event: NetworkConnectEvent) -> Optional[DetectionAlert]:
        if not event.is_outbound:
            return None
        if event.image_name not in OFFICE_APPS:
            return None

        # Skip common Office update/license servers
        trusted_office_hosts = [
            "microsoft.com", "office.com", "office365.com",
            "microsoftonline.com", "live.com", "outlook.com",
        ]
        dst = (event.destination_hostname or "").lower()
        if any(h in dst for h in trusted_office_hosts):
            return None

        desc = (
            f"Office app '{event.image_name}' connected to "
            f"{event.destination_hostname or event.destination_ip}:{event.destination_port}. "
            f"Possible malicious macro callback. User: {event.user}"
        )
        return self._make_alert(event, desc)


class NonNetworkProcessConnectionRule(BaseRule):
    """
    Detects processes that should never make network connections doing so.

    calc.exe, notepad.exe, mspaint.exe — these have no business on the network.
    Any outbound connection from them means they've been hijacked (process
    hollowing, DLL injection, etc.).
    """
    rule_id = "NET004"
    rule_name = "Unexpected Process Network Connection"
    description = "Process with no business making network connections established outbound connection — possible injection"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1055"
    mitre_technique_name = "Process Injection"
    severity = 9
    event_types = (NetworkConnectEvent,)

    def evaluate(self, event: NetworkConnectEvent) -> Optional[DetectionAlert]:
        if not event.is_outbound:
            return None
        if event.image_name not in NO_NETWORK_PROCESSES:
            return None

        desc = (
            f"'{event.image_name}' made an unexpected outbound connection to "
            f"{event.destination_hostname or event.destination_ip}:{event.destination_port}. "
            f"This process should never initiate network connections — likely process injection. "
            f"PID: {event.process_id}"
        )
        return self._make_alert(event, desc)


class ReverseShellPortAndProcessRule(BaseRule):
    """
    High-confidence reverse shell detection: cmd.exe or powershell.exe
    connecting out on a non-standard port.

    A reverse shell by definition is a shell (cmd/powershell) that connects
    outbound to an attacker's listener. This combination of process + port
    is extremely high confidence.
    """
    rule_id = "NET005"
    rule_name = "Likely Reverse Shell"
    description = "Shell process (cmd/powershell) connecting outbound on non-standard port — reverse shell"
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059"
    mitre_technique_name = "Command and Scripting Interpreter"
    severity = 10
    event_types = (NetworkConnectEvent,)

    SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh"}
    STANDARD_PORTS = {80, 443, 8080, 8443}

    def evaluate(self, event: NetworkConnectEvent) -> Optional[DetectionAlert]:
        if not event.is_outbound:
            return None
        if event.image_name not in self.SHELL_PROCESSES:
            return None
        if event.destination_port in self.STANDARD_PORTS:
            return None  # HTTPS/HTTP from shell can be legit (downloads, etc.)

        desc = (
            f"REVERSE SHELL DETECTED: '{event.image_name}' (PID {event.process_id}) "
            f"is connecting outbound to {event.destination_hostname or event.destination_ip}"
            f":{event.destination_port} on a non-standard port. "
            f"User: {event.user}"
        )
        return self._make_alert(event, desc)


ALL_RULES = [
    LOLBinNetworkConnectionRule,
    SuspiciousPortConnectionRule,
    OfficeAppNetworkConnectionRule,
    NonNetworkProcessConnectionRule,
    ReverseShellPortAndProcessRule,
]
