"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — EVENT SCHEMA                                                  ║
║  Normalized dataclasses for every Sysmon event type.                        ║
║                                                                              ║
║  Why dataclasses?                                                            ║
║  - Type hints make rule writing safer and easier to debug                   ║
║  - IDE autocomplete works properly                                           ║
║  - Easy serialization to JSON for logging                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import json


# ─── BASE EVENT ───────────────────────────────────────────────────────────────

@dataclass
class BaseEvent:
    """All Sysmon events share these fields."""
    event_id: int = 0
    event_type: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str = "unknown"
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)


# ─── EVENT ID 1: PROCESS CREATION ────────────────────────────────────────────

@dataclass
class ProcessCreateEvent(BaseEvent):
    """
    Sysmon Event ID 1 — Process Created
    The most important event for detection. Captures full process lineage.
    """
    event_id: int = 1
    event_type: str = "ProcessCreate"

    process_guid: str = ""
    process_id: int = 0
    image: str = ""                    # Full path to executable
    file_version: str = ""
    description: str = ""
    product: str = ""
    company: str = ""
    original_filename: str = ""
    command_line: str = ""             # CRITICAL: full command with args
    current_directory: str = ""
    user: str = ""
    logon_id: str = ""
    terminal_session_id: str = ""
    integrity_level: str = ""         # System, High, Medium, Low
    hashes: str = ""                  # MD5+SHA256 hashes
    parent_process_guid: str = ""
    parent_process_id: int = 0
    parent_image: str = ""            # Full path to parent executable
    parent_command_line: str = ""
    parent_user: str = ""

    @property
    def image_name(self) -> str:
        """Just the filename, not full path."""
        return self.image.split("\\")[-1].lower() if self.image else ""

    @property
    def parent_image_name(self) -> str:
        return self.parent_image.split("\\")[-1].lower() if self.parent_image else ""

    @property
    def is_elevated(self) -> bool:
        return self.integrity_level.lower() in ("high", "system")

    @property
    def sha256(self) -> str:
        """Extract SHA256 from the hashes field."""
        for part in self.hashes.split(","):
            if part.strip().upper().startswith("SHA256="):
                return part.strip().split("=", 1)[1]
        return ""


# ─── EVENT ID 3: NETWORK CONNECTION ──────────────────────────────────────────

@dataclass
class NetworkConnectEvent(BaseEvent):
    """
    Sysmon Event ID 3 — Network Connection Detected
    Critical for catching reverse shells and C2 beaconing.
    """
    event_id: int = 3
    event_type: str = "NetworkConnect"

    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    user: str = ""
    protocol: str = ""               # tcp or udp
    initiated: bool = True           # True = outbound
    source_ip: str = ""
    source_hostname: str = ""
    source_port: int = 0
    destination_ip: str = ""
    destination_hostname: str = ""
    destination_port: int = 0
    destination_port_name: str = ""  # e.g., "https", "http"

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""

    @property
    def is_outbound(self) -> bool:
        return self.initiated

    @property
    def connection_str(self) -> str:
        dst = self.destination_hostname or self.destination_ip
        return f"{self.image_name} → {dst}:{self.destination_port}"


# ─── EVENT ID 5: PROCESS TERMINATED ──────────────────────────────────────────

@dataclass
class ProcessTerminateEvent(BaseEvent):
    event_id: int = 5
    event_type: str = "ProcessTerminate"
    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    user: str = ""

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""


# ─── EVENT ID 8: CREATE REMOTE THREAD ────────────────────────────────────────

@dataclass
class CreateRemoteThreadEvent(BaseEvent):
    """
    Sysmon Event ID 8 — Remote thread created in another process.
    Classic process injection technique used by almost all advanced malware.
    """
    event_id: int = 8
    event_type: str = "CreateRemoteThread"

    source_process_guid: str = ""
    source_process_id: int = 0
    source_image: str = ""
    target_process_guid: str = ""
    target_process_id: int = 0
    target_image: str = ""
    new_thread_id: int = 0
    start_address: str = ""
    start_module: str = ""
    start_function: str = ""

    @property
    def source_image_name(self) -> str:
        return self.source_image.split("\\")[-1].lower() if self.source_image else ""

    @property
    def target_image_name(self) -> str:
        return self.target_image.split("\\")[-1].lower() if self.target_image else ""


# ─── EVENT ID 10: PROCESS ACCESS ─────────────────────────────────────────────

@dataclass
class ProcessAccessEvent(BaseEvent):
    """
    Sysmon Event ID 10 — Process accessed by another process.
    Key detection: Mimikatz reading LSASS memory.
    GrantedAccess 0x1010 or 0x1410 = credential dumping access rights.
    """
    event_id: int = 10
    event_type: str = "ProcessAccess"

    source_process_guid: str = ""
    source_process_id: int = 0
    source_thread_id: int = 0
    source_image: str = ""
    target_process_guid: str = ""
    target_process_id: int = 0
    target_image: str = ""
    granted_access: str = ""          # Hex string like "0x1410"
    call_trace: str = ""

    # Access masks that indicate credential dumping
    CRED_DUMP_ACCESS_MASKS = {
        "0x1010",   # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
        "0x1410",   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE
        "0x143a",   # Full Mimikatz access
        "0x1438",
        "0x1fffff", # PROCESS_ALL_ACCESS
        "0x0810",
        "0x1010",
    }

    @property
    def source_image_name(self) -> str:
        return self.source_image.split("\\")[-1].lower() if self.source_image else ""

    @property
    def target_image_name(self) -> str:
        return self.target_image.split("\\")[-1].lower() if self.target_image else ""

    @property
    def is_credential_dump_access(self) -> bool:
        return self.granted_access.lower() in {m.lower() for m in self.CRED_DUMP_ACCESS_MASKS}


# ─── EVENT ID 11: FILE CREATED ───────────────────────────────────────────────

@dataclass
class FileCreateEvent(BaseEvent):
    """Sysmon Event ID 11 — File created."""
    event_id: int = 11
    event_type: str = "FileCreate"

    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    target_filename: str = ""
    creation_utc_time: str = ""
    hashes: str = ""
    user: str = ""

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""

    @property
    def file_extension(self) -> str:
        if "." in self.target_filename:
            return self.target_filename.rsplit(".", 1)[-1].lower()
        return ""

    @property
    def is_in_temp(self) -> bool:
        return "\\temp\\" in self.target_filename.lower() or \
               "\\appdata\\" in self.target_filename.lower()


# ─── EVENT IDs 12/13/14: REGISTRY EVENTS ─────────────────────────────────────

@dataclass
class RegistryEvent(BaseEvent):
    """
    Sysmon Event IDs 12 (create/delete), 13 (value set), 14 (rename).
    Core persistence detection.
    """
    event_id: int = 13
    event_type: str = "RegistryEvent"

    registry_event_type: str = ""  # SetValue, CreateKey, DeleteKey, etc.
    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    target_object: str = ""         # Full registry path
    details: str = ""               # For Event 13: the value being written
    new_name: str = ""              # For Event 14: renamed key/value

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""

    @property
    def is_run_key(self) -> bool:
        run_keys = [
            "\\currentversion\\run",
            "\\currentversion\\runonce",
        ]
        lower = self.target_object.lower()
        return any(k in lower for k in run_keys)

    @property
    def is_security_tool_modification(self) -> bool:
        security_keys = ["windows defender", "windefend", "firewall"]
        lower = self.target_object.lower()
        return any(k in lower for k in security_keys)


# ─── EVENT ID 22: DNS QUERY ───────────────────────────────────────────────────

@dataclass
class DnsQueryEvent(BaseEvent):
    """
    Sysmon Event ID 22 — DNS query observed.
    Useful for C2 detection, DGA, DNS tunneling.
    """
    event_id: int = 22
    event_type: str = "DnsQuery"

    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    query_name: str = ""            # The domain being queried
    query_status: str = ""
    query_results: str = ""         # IPs returned
    user: str = ""

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""

    @property
    def query_depth(self) -> int:
        """Number of subdomain levels — high count can indicate DGA."""
        return len(self.query_name.split(".")) if self.query_name else 0

    @property
    def tld(self) -> str:
        parts = self.query_name.split(".")
        return parts[-1] if len(parts) >= 2 else ""


# ─── EVENT ID 25: PROCESS TAMPERING ──────────────────────────────────────────

@dataclass
class ProcessTamperingEvent(BaseEvent):
    """
    Sysmon Event ID 25 — Process image was tampered.
    Covers process hollowing, herpaderping, ghosting.
    """
    event_id: int = 25
    event_type: str = "ProcessTampering"

    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    tampering_type: str = ""        # "Image is replaced", etc.

    @property
    def image_name(self) -> str:
        return self.image.split("\\")[-1].lower() if self.image else ""


# ─── DETECTION ALERT ─────────────────────────────────────────────────────────

@dataclass
class DetectionAlert:
    """
    Produced by a rule when it detects malicious/suspicious activity.
    This is what flows into the response and alerting systems.
    """
    # Rule identification
    rule_id: str                        # Unique rule identifier, e.g. "PS001"
    rule_name: str                      # Human-readable name
    description: str                    # What was detected and why it's suspicious

    # MITRE ATT&CK
    mitre_tactic: str                   # e.g. "Execution"
    mitre_technique_id: str             # e.g. "T1059.001"
    mitre_technique_name: str           # e.g. "PowerShell"

    # Severity: 1=Informational, 3=Low, 5=Medium, 7=High, 9=Critical
    severity: int
    severity_label: str = ""

    # The event that triggered this alert
    event: Any = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Response tracking
    response_taken: str = ""
    alert_sent: bool = False

    # Unique key for deduplication
    dedup_key: str = ""

    def __post_init__(self):
        if not self.severity_label:
            self.severity_label = self._get_severity_label()
        if not self.dedup_key:
            self.dedup_key = f"{self.rule_id}:{getattr(self.event, 'process_id', 0)}"

    def _get_severity_label(self) -> str:
        if self.severity >= 9:
            return "CRITICAL"
        elif self.severity >= 7:
            return "HIGH"
        elif self.severity >= 5:
            return "MEDIUM"
        elif self.severity >= 3:
            return "LOW"
        else:
            return "INFO"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "timestamp": self.timestamp.isoformat(),
            "response_taken": self.response_taken,
            "event_type": self.event.event_type if self.event else None,
            "event_details": self.event.to_dict() if self.event else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)
