"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DETECTION RULES — CREDENTIAL ACCESS                                        ║
║  MITRE ATT&CK: T1003 (OS Credential Dumping)                               ║
║                                                                              ║
║  Rules detect:                                                               ║
║    - LSASS memory access (Mimikatz, ProcDump, Task Manager dump)           ║
║    - SAM database access                                                    ║
║    - NTDS.dit access (domain controller credential dump)                    ║
║    - Password dump utilities by name                                        ║
║    - Credential dump via Volume Shadow Copy                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
from typing import Optional
from detection_engine.event_schema import (
    BaseEvent, ProcessAccessEvent, ProcessCreateEvent,
    FileCreateEvent, DetectionAlert
)
from detection_engine.rules.base_rule import BaseRule


# Processes legitimately accessing LSASS (reduce false positives)
LSASS_WHITELIST = {
    "wininit.exe",          # LSASS parent
    "csrss.exe",            # Windows subsystem
    "lsass.exe",            # Self-access
    "antimalware service executable",  # Windows Defender
    "mssense.exe",          # Microsoft Defender for Endpoint
    "mssecsvr.exe",
    "vmtoolsd.exe",         # VMware (common in labs)
}

# Known credential dumping tool names
CRED_DUMP_TOOLS = {
    "mimikatz.exe",
    "mimikatz",
    "wce.exe",              # Windows Credential Editor
    "pwdump.exe",
    "pwdump7.exe",
    "fgdump.exe",
    "gsecdump.exe",
    "cachedump.exe",
    "msvaultdump.exe",
    "quarkspwdump.exe",
}

# GrantedAccess masks used by credential dumpers when reading LSASS
# These specific combinations of access rights are the fingerprint of
# tools like Mimikatz, ProcDump, and Task Manager memory dumps.
CREDENTIAL_DUMP_ACCESS_MASKS = {
    "0x1010",   # VM_READ | QUERY_LIMITED_INFORMATION (Mimikatz sekurlsa)
    "0x1410",   # VM_READ | QUERY_INFORMATION | DUP_HANDLE
    "0x143a",   # Full Mimikatz/Cobalt Strike access
    "0x1438",
    "0x1fffff",  # PROCESS_ALL_ACCESS — very suspicious
    "0x0810",
    "0x0410",
    "0x1000",
    "0x0040",
}


class LSASSMemoryAccessRule(BaseRule):
    """
    Detects processes reading LSASS memory — the primary credential dumping method.

    Mimikatz, ProcDump (procdump -ma lsass.exe), Task Manager dump, and
    many other tools access LSASS with specific access masks to read
    credential material from memory.

    This is the #1 post-exploitation activity detected on real incidents.
    GrantedAccess values are the key — specific bit combinations signal
    the intent to read credential-related memory regions.
    """
    rule_id = "CRED001"
    rule_name = "LSASS Memory Access (Credential Dumping)"
    description = "Process accessed LSASS memory with credential-dump access rights"
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1003.001"
    mitre_technique_name = "LSASS Memory"
    severity = 10
    event_types = (ProcessAccessEvent,)

    def evaluate(self, event: ProcessAccessEvent) -> Optional[DetectionAlert]:
        # Must be targeting lsass.exe
        if "lsass.exe" not in event.target_image.lower():
            return None

        # Skip known-legitimate accessors
        if event.source_image_name in LSASS_WHITELIST:
            return None

        # Check GrantedAccess mask
        granted = event.granted_access.lower()
        is_cred_mask = granted in {m.lower() for m in CREDENTIAL_DUMP_ACCESS_MASKS}

        if not is_cred_mask:
            return None

        desc = (
            f"CREDENTIAL DUMP DETECTED: '{event.source_image_name}' (PID {event.source_process_id}) "
            f"accessed LSASS (PID {event.target_process_id}) "
            f"with GrantedAccess={event.granted_access}. "
            f"This is the exact access pattern used by Mimikatz and credential dumpers. "
            f"Immediate response required. CallTrace: {event.call_trace[:200]}"
        )
        return self._make_alert(event, desc)


class KnownCredentialDumpToolRule(BaseRule):
    """
    Detects known credential dumping tools by filename.

    While attackers rename their tools, this catches unmodified
    tool names. Combined with behavioral rules, provides comprehensive coverage.
    """
    rule_id = "CRED002"
    rule_name = "Known Credential Dump Tool Executed"
    description = "Known credential dumping utility detected by filename"
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1003"
    mitre_technique_name = "OS Credential Dumping"
    severity = 10
    event_types = (ProcessCreateEvent,)

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        img_name = event.image_name
        cmd = (event.command_line or "").lower()

        # Check image name
        if img_name in CRED_DUMP_TOOLS:
            desc = (
                f"Known credential dumping tool '{img_name}' was executed. "
                f"Parent: {event.parent_image_name}. User: {event.user}. "
                f"Command: {event.command_line[:200]}"
            )
            return self._make_alert(event, desc)

        # Check if the command line references mimikatz even if renamed
        if "mimikatz" in cmd or "sekurlsa" in cmd or "lsadump" in cmd:
            desc = (
                f"Mimikatz-related command detected in '{event.image_name}'. "
                f"Command contains Mimikatz module names. "
                f"Command: {event.command_line[:300]}"
            )
            return self._make_alert(event, desc)

        return None


class ProcDumpLSASSRule(BaseRule):
    """
    Detects ProcDump being used to dump LSASS memory.

    ProcDump (Microsoft Sysinternals) is a legitimate tool for capturing
    crash dumps, but it's frequently abused to dump LSASS memory:
    > procdump.exe -ma lsass.exe lsass_dump.dmp

    The combination of procdump + lsass in the command is definitive.
    """
    rule_id = "CRED003"
    rule_name = "ProcDump Targeting LSASS"
    description = "ProcDump used to dump LSASS memory — credential theft via memory dump"
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1003.001"
    mitre_technique_name = "LSASS Memory"
    severity = 10
    event_types = (ProcessCreateEvent,)

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name not in ("procdump.exe", "procdump64.exe"):
            return None

        cmd = (event.command_line or "").lower()
        if "lsass" not in cmd:
            return None

        desc = (
            f"ProcDump targeting LSASS: '{event.command_line[:300]}'. "
            f"This dumps LSASS memory to disk for offline credential extraction. "
            f"Parent: {event.parent_image_name}, User: {event.user}"
        )
        return self._make_alert(event, desc)


class SAMDatabaseAccessRule(BaseRule):
    """
    Detects attempts to access the SAM database directly.

    The Security Account Manager (SAM) database stores local user credentials.
    Accessing it requires SYSTEM privileges. Common methods:
    - reg save HKLM\\SAM C:\\sam.dump
    - Volume Shadow Copy method
    - Impacket's secretsdump.py (remote)
    """
    rule_id = "CRED004"
    rule_name = "SAM Database Access Attempt"
    description = "Attempt to access or export the SAM credential database"
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1003.002"
    mitre_technique_name = "Security Account Manager"
    severity = 9
    event_types = (ProcessCreateEvent,)

    SAM_PATTERNS = [
        re.compile(r'(?i)reg\b.*save\b.*HKLM\\SAM'),
        re.compile(r'(?i)reg\b.*save\b.*sam'),
        re.compile(r'(?i)reg\b.*export\b.*sam'),
        re.compile(r'(?i)\\config\\sam\b'),
        re.compile(r'(?i)secretsdump'),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        cmd = event.command_line or ""
        for pattern in self.SAM_PATTERNS:
            if pattern.search(cmd):
                desc = (
                    f"SAM database access attempt by '{event.image_name}'. "
                    f"Pattern matched: {pattern.pattern}. "
                    f"Command: {cmd[:300]}. User: {event.user}"
                )
                return self._make_alert(event, desc)
        return None


class VolumeShadowCopyCredentialAccessRule(BaseRule):
    """
    Detects credential extraction via Volume Shadow Copies.

    When LSASS/SAM/NTDS.dit is locked, attackers use VSS to access
    an unlocked copy through a shadow volume:
    > vssadmin create shadow /for=C:
    > copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM

    This technique bypasses file locks and is used heavily by ransomware groups.
    """
    rule_id = "CRED005"
    rule_name = "Credential Access via Volume Shadow Copy"
    description = "Volume Shadow Copy used to access credential stores — VSS theft technique"
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1003.003"
    mitre_technique_name = "NTDS"
    severity = 9
    event_types = (ProcessCreateEvent,)

    VSS_CRED_PATTERNS = [
        re.compile(r'(?i)HarddiskVolumeShadowCopy.*\\config\\sam'),
        re.compile(r'(?i)HarddiskVolumeShadowCopy.*\\config\\system'),
        re.compile(r'(?i)HarddiskVolumeShadowCopy.*\\config\\security'),
        re.compile(r'(?i)HarddiskVolumeShadowCopy.*ntds\.dit'),
        re.compile(r'(?i)GLOBALROOT.*Shadow.*sam'),
        re.compile(r'(?i)GLOBALROOT.*Shadow.*ntds'),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        cmd = event.command_line or ""
        for pattern in self.VSS_CRED_PATTERNS:
            if pattern.search(cmd):
                desc = (
                    f"Volume Shadow Copy used to access credential files. "
                    f"Executed by '{event.image_name}' ({event.parent_image_name}). "
                    f"Command: {cmd[:300]}"
                )
                return self._make_alert(event, desc)
        return None


ALL_RULES = [
    LSASSMemoryAccessRule,
    KnownCredentialDumpToolRule,
    ProcDumpLSASSRule,
    SAMDatabaseAccessRule,
    VolumeShadowCopyCredentialAccessRule,
]
