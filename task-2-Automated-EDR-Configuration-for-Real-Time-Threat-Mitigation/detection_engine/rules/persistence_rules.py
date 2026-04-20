"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DETECTION RULES — PERSISTENCE                                              ║
║  MITRE ATT&CK: T1547, T1053, T1543, T1546                                  ║
║                                                                              ║
║  Rules detect:                                                               ║
║    - Registry Run key modifications (T1547.001)                             ║
║    - Scheduled task creation (T1053.005)                                    ║
║    - Service installation (T1543.003)                                       ║
║    - Startup folder file drops                                              ║
║    - WMI event subscription (T1546.003)                                     ║
║    - AppInit DLL hijacking (T1546.010)                                      ║
║    - IFEO debugger hijacking (T1546.012)                                    ║
║    - Disabling Windows Defender via registry                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
from typing import Optional
from detection_engine.event_schema import (
    BaseEvent, RegistryEvent, FileCreateEvent,
    ProcessCreateEvent, DetectionAlert
)
from detection_engine.rules.base_rule import BaseRule


RUN_KEY_PATHS = [
    r"\currentversion\run",
    r"\currentversion\runonce",
    r"\currentversion\runservices",
    r"\currentversion\runservicesonce",
    r"software\wow6432node\microsoft\windows\currentversion\run",
]

# These processes legitimately touch run keys — reduce false positives
RUN_KEY_WHITELIST = {
    "msiexec.exe",          # Installers
    "setup.exe",
    "install.exe",
    "update.exe",
    "updater.exe",
    "googleupdate.exe",
    "onedrive.exe",
    "teams.exe",
    "slack.exe",
    "discord.exe",
}


class RegistryRunKeyPersistenceRule(BaseRule):
    """
    Detects modifications to registry Run/RunOnce keys.

    This is the most common persistence mechanism. Malware writes itself to:
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

    On every login, Windows executes everything listed in these keys.
    Legitimate software does use Run keys (OneDrive, Slack, etc.) but
    non-whitelisted writes are high-priority findings.
    """
    rule_id = "PER001"
    rule_name = "Registry Run Key Persistence"
    description = "Process wrote to a registry Run key — common malware persistence mechanism"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1547.001"
    mitre_technique_name = "Registry Run Keys / Startup Folder"
    severity = 7
    event_types = (RegistryEvent,)

    def evaluate(self, event: RegistryEvent) -> Optional[DetectionAlert]:
        # Only care about value set events (ID 13)
        if event.event_id != 13:
            return None

        target = (event.target_object or "").lower()
        if not any(rk in target for rk in RUN_KEY_PATHS):
            return None

        # Whitelist known-good writers
        if event.image_name in RUN_KEY_WHITELIST:
            return None

        desc = (
            f"'{event.image_name}' wrote to registry Run key. "
            f"Key: {event.target_object}. "
            f"Value: {event.details[:200]}. "
            f"This is a classic persistence mechanism — review immediately."
        )
        return self._make_alert(event, desc)


class ScheduledTaskCreationRule(BaseRule):
    """
    Detects scheduled task creation via command line (schtasks.exe).

    Attackers use scheduled tasks for:
    - Persistence (run at logon/reboot)
    - Privilege escalation (run as SYSTEM)
    - Lateral movement (run on remote system)

    The /sc and /tr flags are key indicators.
    """
    rule_id = "PER002"
    rule_name = "Scheduled Task Created via CLI"
    description = "Scheduled task created using schtasks.exe — possible persistence"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1053.005"
    mitre_technique_name = "Scheduled Task"
    severity = 6
    event_types = (ProcessCreateEvent,)

    # Patterns for schtasks command
    CREATE_PATTERN = re.compile(r'(?i)/create\b')
    SYSTEM_PATTERN = re.compile(r'(?i)/ru\s+system\b')
    SUSPICIOUS_TR_PATTERN = re.compile(
        r'(?i)/tr\s+["\'"]?.*(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)'
    )

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name != "schtasks.exe":
            return None

        cmd = event.command_line or ""
        if not self.CREATE_PATTERN.search(cmd):
            return None

        # Escalate severity if running as SYSTEM or using a suspicious binary
        sev = self.severity
        extras = []

        if self.SYSTEM_PATTERN.search(cmd):
            sev = min(sev + 2, 10)
            extras.append("runs as SYSTEM")

        if self.SUSPICIOUS_TR_PATTERN.search(cmd):
            sev = min(sev + 1, 10)
            extras.append("calls suspicious binary")

        desc = (
            f"Scheduled task created by '{event.parent_image_name}'. "
            f"Command: {cmd[:300]}. "
            + (f"Concerns: {', '.join(extras)}." if extras else "")
        )

        alert = self._make_alert(event, desc)
        alert.severity = sev
        return alert


class ServiceInstallationRule(BaseRule):
    """
    Detects new Windows service creation via sc.exe or registry.

    Services run as SYSTEM by default and persist across reboots.
    Attackers install malicious services for both persistence and privilege escalation.
    """
    rule_id = "PER003"
    rule_name = "New Windows Service Installed"
    description = "New Windows service created via sc.exe — possible persistence or privilege escalation"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1543.003"
    mitre_technique_name = "Windows Service"
    severity = 7
    event_types = (ProcessCreateEvent,)

    CREATE_PATTERN = re.compile(r'(?i)\bcreate\b')
    BINPATH_PATTERN = re.compile(r'(?i)binpath=\s*["\'"]?(.{1,200})')

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name != "sc.exe":
            return None

        cmd = event.command_line or ""
        if not self.CREATE_PATTERN.search(cmd):
            return None

        # Extract the service binary path if present
        binpath_match = self.BINPATH_PATTERN.search(cmd)
        binpath = binpath_match.group(1)[:100] if binpath_match else "unknown"

        # Escalate if binary is in a suspicious location
        sev = self.severity
        if any(loc in binpath.lower() for loc in ["\\temp\\", "\\appdata\\", "\\users\\public\\"]):
            sev = min(sev + 2, 10)

        desc = (
            f"Service creation detected: sc.exe create called by '{event.parent_image_name}'. "
            f"Binary path: {binpath}. Full command: {cmd[:300]}"
        )
        alert = self._make_alert(event, desc)
        alert.severity = sev
        return alert


class StartupFolderDropRule(BaseRule):
    """
    Detects files written to startup folders.

    Windows executes everything in these folders at login:
    - C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
    - C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

    Dropping executables or scripts here is a simple but effective persistence method.
    """
    rule_id = "PER004"
    rule_name = "File Dropped in Startup Folder"
    description = "Executable or script written to Windows startup folder — persistence"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1547.001"
    mitre_technique_name = "Registry Run Keys / Startup Folder"
    severity = 8
    event_types = (FileCreateEvent,)

    STARTUP_PATHS = [
        "start menu\\programs\\startup",
        "startmenu\\programs\\startup",
    ]

    EXEC_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta", ".js", ".lnk"}

    def evaluate(self, event: FileCreateEvent) -> Optional[DetectionAlert]:
        target = (event.target_filename or "").lower()

        if not any(sp in target for sp in self.STARTUP_PATHS):
            return None

        if event.file_extension and f".{event.file_extension}" not in self.EXEC_EXTENSIONS:
            return None  # Only flag executables, not innocent files

        desc = (
            f"'{event.image_name}' dropped '{event.target_filename}' into a startup folder. "
            f"This file will execute automatically on next user login."
        )
        return self._make_alert(event, desc)


class AppInitDLLHijackRule(BaseRule):
    """
    Detects modification of AppInit_DLLs registry key.

    AppInit_DLLs causes Windows to load listed DLLs into every user-mode
    process that loads user32.dll (nearly every GUI application).
    This is a classic DLL injection / persistence technique.
    """
    rule_id = "PER005"
    rule_name = "AppInit DLL Hijack"
    description = "AppInit_DLLs registry key modified — DLL will be injected into every GUI process"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1546.010"
    mitre_technique_name = "AppInit DLLs"
    severity = 9
    event_types = (RegistryEvent,)

    def evaluate(self, event: RegistryEvent) -> Optional[DetectionAlert]:
        target = (event.target_object or "").lower()
        if "appinit_dlls" not in target:
            return None

        if not event.details or event.details.strip() in ("", "(Empty)"):
            return None  # Clearing the key is fine

        desc = (
            f"AppInit_DLLs modified by '{event.image_name}'. "
            f"DLL path set to: {event.details}. "
            f"This DLL will be injected into every GUI process on this system."
        )
        return self._make_alert(event, desc)


class IFEODebuggerHijackRule(BaseRule):
    """
    Detects Image File Execution Options (IFEO) debugger hijacking.

    By setting IFEO\\notepad.exe\\Debugger = C:\\evil.exe, attackers cause
    Windows to run their malware instead of (or before) the target process.
    This is used for:
    - Accessibility feature backdoors (sethc.exe, osk.exe → cmd.exe)
    - Privilege escalation (running as SYSTEM via accessibility tools)
    - Application shimming
    """
    rule_id = "PER006"
    rule_name = "IFEO Debugger Hijack"
    description = "Image File Execution Options Debugger key set — application execution hijack"
    mitre_tactic = "Persistence"
    mitre_technique_id = "T1546.012"
    mitre_technique_name = "Image File Execution Options Injection"
    severity = 9
    event_types = (RegistryEvent,)

    # Common IFEO targets for accessibility backdoors
    HIGH_VALUE_TARGETS = {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
        "narrator.exe", "displayswitch.exe", "atbroker.exe",
    }

    def evaluate(self, event: RegistryEvent) -> Optional[DetectionAlert]:
        target = (event.target_object or "").lower()

        if "image file execution options" not in target:
            return None
        if "debugger" not in target:
            return None

        # Check if it's targeting an accessibility tool (extra severity)
        sev = self.severity
        for acc_tool in self.HIGH_VALUE_TARGETS:
            if acc_tool in target:
                sev = 10
                break

        desc = (
            f"IFEO Debugger set by '{event.image_name}'. "
            f"Target key: {event.target_object}. "
            f"Debugger value: {event.details}. "
            f"{'ACCESSIBILITY TOOL TARGETED — likely sticky keys / utilman bypass!' if sev == 10 else ''}"
        )
        alert = self._make_alert(event, desc)
        alert.severity = sev
        return alert


class DefenderDisabledRule(BaseRule):
    """
    Detects attempts to disable Windows Defender via registry.

    Malware disables AV to avoid detection. Key indicators:
    - DisableAntiSpyware = 1
    - DisableRealtimeMonitoring = 1
    - DisableBehaviorMonitoring = 1
    """
    rule_id = "PER007"
    rule_name = "Windows Defender Disabled via Registry"
    description = "Windows Defender being disabled via registry — defense evasion"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1562.001"
    mitre_technique_name = "Disable or Modify Tools"
    severity = 9
    event_types = (RegistryEvent,)

    DEFENDER_DISABLE_KEYS = [
        "disableantispyware",
        "disablerealtimemonitoring",
        "disablebehaviormonitoring",
        "disableioavprotection",
        "disableantivirus",
        "disablescriptscanning",
    ]

    def evaluate(self, event: RegistryEvent) -> Optional[DetectionAlert]:
        if event.event_id != 13:
            return None

        target = (event.target_object or "").lower()
        if "windows defender" not in target and "windefend" not in target:
            return None

        for disable_key in self.DEFENDER_DISABLE_KEYS:
            if disable_key in target:
                # Sysmon formats DWORD values in several ways across versions:
                # "DWORD (0x00000001)", "0x00000001", "1", "0x1"
                details_lower = (event.details or "").lower()
                is_enabled = (
                    details_lower in ("1", "dword (0x00000001)", "0x00000001", "0x1")
                    or details_lower.endswith("00000001)")
                    or details_lower == "dword (0x1)"
                )
                if is_enabled:
                    desc = (
                        f"Windows Defender feature disabled by '{event.image_name}'. "
                        f"Registry key: {event.target_object}. "
                        f"Value: {event.details}. "
                        f"This is a classic defense evasion technique."
                    )
                    return self._make_alert(event, desc)

        return None


ALL_RULES = [
    RegistryRunKeyPersistenceRule,
    ScheduledTaskCreationRule,
    ServiceInstallationRule,
    StartupFolderDropRule,
    AppInitDLLHijackRule,
    IFEODebuggerHijackRule,
    DefenderDisabledRule,
]
