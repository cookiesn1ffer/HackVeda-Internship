"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — AUTOMATED RESPONSE ENGINE                                     ║
║                                                                              ║
║  When a detection fires, this module takes automated action:                ║
║    1. Kill the offending process                                             ║
║    2. Block the process from making further network connections             ║
║    3. Log the incident to disk                                              ║
║    4. (Optional) Full network isolation of the endpoint                     ║
║                                                                              ║
║  Every action is logged so you have a full audit trail.                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from detection_engine.event_schema import DetectionAlert

log = logging.getLogger("edr.response")

# Try importing Windows-specific modules
try:
    import win32api
    import win32con
    import win32process
    WINDOWS = True
except ImportError:
    WINDOWS = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


class ResponseEngine:
    """
    Executes automated response actions based on detection alerts.

    Design principles:
    - Never kill a whitelisted process (avoids bricking the system)
    - Log every action taken, whether it succeeded or failed
    - Fail gracefully — a failed response should never crash the EDR
    - Require minimum severity before taking destructive actions
    """

    def __init__(self, config: dict):
        resp_cfg = config.get("response", {})
        log_cfg = config.get("logging", {})
        eng_cfg = config.get("engine", {})

        self.kill_process = resp_cfg.get("kill_process", True)
        self.firewall_block = resp_cfg.get("firewall_block", True)
        self.network_isolate = resp_cfg.get("network_isolate", False)
        self.auto_response_enabled = eng_cfg.get("auto_response_enabled", True)
        self.auto_response_min_severity = eng_cfg.get("auto_response_min_severity", 7)

        # Process whitelist — NEVER kill these
        self.process_whitelist = set(
            p.lower() for p in resp_cfg.get("process_whitelist", [])
        )

        # Incident log directory
        self.incidents_dir = Path(log_cfg.get("incidents_dir", "logs\\incidents"))
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

    def respond(self, alert: DetectionAlert) -> str:
        """
        Main entry point. Decides what actions to take and executes them.

        Args:
            alert: The detection alert to respond to

        Returns:
            Human-readable string describing what was done.
        """
        if not self.auto_response_enabled:
            log.info(f"Auto-response disabled. Alert: {alert.rule_name}")
            return "auto-response disabled"

        if alert.severity < self.auto_response_min_severity:
            log.info(
                f"Alert severity {alert.severity} below threshold "
                f"{self.auto_response_min_severity} — no automated response"
            )
            return f"severity {alert.severity} below auto-response threshold"

        actions_taken = []

        # Extract process information from the alert's event
        pid = self._get_pid(alert)
        image_path = self._get_image_path(alert)
        image_name = image_path.split("\\")[-1].lower() if image_path else ""

        # Check whitelist BEFORE doing anything
        if self._is_whitelisted(image_path, image_name):
            log.warning(
                f"Whitelisted process '{image_name}' triggered alert '{alert.rule_name}'. "
                f"Skipping kill/block. Logging only."
            )
            self._log_incident(alert, ["whitelisted — logged only"])
            return "whitelisted process — logged only"

        # ── ACTION 1: Kill the process ────────────────────────────────────────
        if self.kill_process and pid:
            kill_result = self._kill_process(pid, image_name, alert.rule_name)
            actions_taken.append(kill_result)

        # ── ACTION 2: Firewall block ──────────────────────────────────────────
        if self.firewall_block and image_path:
            block_result = self._add_firewall_block(image_path, alert.rule_name)
            actions_taken.append(block_result)

        # ── ACTION 3: Network isolation (high severity only) ──────────────────
        if self.network_isolate and alert.severity >= 9:
            isolate_result = self._isolate_endpoint(alert.rule_name)
            actions_taken.append(isolate_result)

        # ── ACTION 4: Always log the incident ─────────────────────────────────
        self._log_incident(alert, actions_taken)

        summary = "; ".join(actions_taken) if actions_taken else "logged only"
        alert.response_taken = summary
        return summary

    # ─── PROCESS TERMINATION ─────────────────────────────────────────────────

    def _kill_process(self, pid: int, image_name: str, rule_name: str) -> str:
        """
        Terminate a process by PID using the most reliable available method.

        Priority:
        1. win32api.TerminateProcess (most direct, works on protected processes)
        2. psutil.Process.kill() (cross-platform fallback)
        3. taskkill.exe (last resort)
        """
        log.warning(f"RESPONSE: Killing PID {pid} ({image_name}) — triggered by {rule_name}")

        # Method 1: Win32 API (most reliable on Windows)
        if WINDOWS:
            try:
                handle = win32api.OpenProcess(
                    win32con.PROCESS_TERMINATE,
                    False,
                    pid
                )
                win32api.TerminateProcess(handle, 1)
                win32api.CloseHandle(handle)
                log.info(f"✓ Killed PID {pid} via Win32 API")
                return f"killed PID {pid} ({image_name}) via Win32 API"
            except Exception as e:
                log.warning(f"Win32 kill failed for PID {pid}: {e}")

        # Method 2: psutil
        if PSUTIL:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.kill()
                proc.wait(timeout=5)
                log.info(f"✓ Killed PID {pid} via psutil")
                return f"killed PID {pid} ({image_name}) via psutil"
            except psutil.NoSuchProcess:
                return f"PID {pid} already dead"
            except Exception as e:
                log.warning(f"psutil kill failed for PID {pid}: {e}")

        # Method 3: taskkill (last resort)
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                log.info(f"✓ Killed PID {pid} via taskkill")
                return f"killed PID {pid} ({image_name}) via taskkill"
            else:
                log.error(f"taskkill failed: {result.stderr}")
                return f"kill failed for PID {pid}: {result.stderr[:100]}"
        except Exception as e:
            log.error(f"All kill methods failed for PID {pid}: {e}")
            return f"kill failed for PID {pid}: {e}"

    # ─── FIREWALL BLOCKING ────────────────────────────────────────────────────

    def _add_firewall_block(self, image_path: str, rule_name: str) -> str:
        """
        Add a Windows Firewall rule to block all outbound connections from the process.

        Uses netsh advfirewall — no additional dependencies required.
        The rule name includes the EDR prefix so we can manage them later.
        """
        if not WINDOWS and sys.platform != "win32":
            return "firewall block skipped (not Windows)"

        # Sanitize the rule name for use in firewall rule names
        fw_rule_name = f"EDR_BLOCK_{rule_name.replace(' ', '_')[:40]}"
        image_name = image_path.split("\\")[-1]

        log.warning(f"RESPONSE: Adding firewall block for '{image_name}'")

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={fw_rule_name}",
                "dir=out",
                "action=block",
                f"program={image_path}",
                "enable=yes",
                "profile=any",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                log.info(f"✓ Firewall rule '{fw_rule_name}' added for '{image_name}'")
                return f"firewall blocked '{image_name}' (rule: {fw_rule_name})"
            else:
                log.error(f"Firewall block failed: {result.stderr}")
                return f"firewall block failed: {result.stderr[:100]}"

        except Exception as e:
            log.error(f"Firewall block error: {e}")
            return f"firewall block error: {e}"

    def remove_firewall_block(self, rule_name: str) -> bool:
        """Remove a previously added firewall block rule."""
        try:
            fw_rule_name = f"EDR_BLOCK_{rule_name.replace(' ', '_')[:40]}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={fw_rule_name}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def list_edr_firewall_rules(self) -> list:
        """List all firewall rules created by this EDR."""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15
            )
            lines = result.stdout.split("\n")
            edr_rules = []
            current_rule = {}
            for line in lines:
                if line.startswith("Rule Name:") and "EDR_BLOCK" in line:
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Program:") and current_rule:
                    current_rule["program"] = line.split(":", 1)[1].strip()
                    edr_rules.append(current_rule)
                    current_rule = {}
            return edr_rules
        except Exception:
            return []

    # ─── NETWORK ISOLATION ────────────────────────────────────────────────────

    def _isolate_endpoint(self, rule_name: str) -> str:
        """
        Isolate the endpoint by blocking ALL outbound traffic except:
        - Velociraptor management traffic (port 8000)
        - DNS (port 53)
        - Local loopback

        WARNING: This will cut off the machine from the network!
        Only use for severe incidents (severity 9-10).
        Use remove_isolation() to restore connectivity.
        """
        log.critical(f"RESPONSE: ISOLATING ENDPOINT — triggered by {rule_name}")

        commands = [
            # Block all outbound first
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=EDR_ISOLATE_BLOCK_ALL_OUT", "dir=out", "action=block",
             "protocol=any", "enable=yes", "profile=any"],
            # Allow Velociraptor
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=EDR_ISOLATE_ALLOW_VELOCIRAPTOR", "dir=out", "action=allow",
             "protocol=tcp", "localport=8000,8889", "enable=yes"],
            # Allow DNS
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=EDR_ISOLATE_ALLOW_DNS", "dir=out", "action=allow",
             "protocol=udp", "remoteport=53", "enable=yes"],
        ]

        results = []
        for cmd in commands:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                results.append("ok" if r.returncode == 0 else "failed")
            except Exception as e:
                results.append(f"error: {e}")

        # Create isolation marker file
        marker = self.incidents_dir / "ISOLATED.flag"
        marker.write_text(
            f"Endpoint isolated at {datetime.now(timezone.utc).isoformat()}\n"
            f"Triggered by: {rule_name}\n"
            f"Run remove_isolation() to restore connectivity.\n"
        )

        return f"ENDPOINT ISOLATED (results: {results})"

    def remove_isolation(self):
        """Remove all EDR isolation firewall rules and restore connectivity."""
        isolation_rules = [
            "EDR_ISOLATE_BLOCK_ALL_OUT",
            "EDR_ISOLATE_ALLOW_VELOCIRAPTOR",
            "EDR_ISOLATE_ALLOW_DNS",
        ]
        for rule in isolation_rules:
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                    capture_output=True, timeout=10
                )
            except Exception:
                pass

        marker = self.incidents_dir / "ISOLATED.flag"
        if marker.exists():
            marker.unlink()

        log.info("Endpoint isolation removed — connectivity restored.")

    # ─── INCIDENT LOGGING ─────────────────────────────────────────────────────

    def _log_incident(self, alert: DetectionAlert, actions: list):
        """
        Write a full incident record to disk as JSON.

        Each incident gets its own timestamped file. This creates a searchable
        record of everything the EDR detected and responded to.
        """
        ts = datetime.now(timezone.utc)
        filename = f"incident_{ts.strftime('%Y%m%d_%H%M%S')}_{alert.rule_id}.json"
        filepath = self.incidents_dir / filename

        incident = {
            "incident_id": filename,
            "timestamp": ts.isoformat(),
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "severity_label": alert.severity_label,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique_id": alert.mitre_technique_id,
            "mitre_technique_name": alert.mitre_technique_name,
            "description": alert.description,
            "actions_taken": actions,
            "event": alert.event.to_dict() if alert.event else None,
        }

        try:
            filepath.write_text(json.dumps(incident, indent=2, default=str))
            log.info(f"Incident logged: {filepath}")
        except Exception as e:
            log.error(f"Failed to write incident log: {e}")

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _get_pid(self, alert: DetectionAlert) -> Optional[int]:
        """Extract the primary PID from the alert's event."""
        event = alert.event
        if not event:
            return None
        return (
            getattr(event, "process_id", None) or
            getattr(event, "source_process_id", None)
        )

    def _get_image_path(self, alert: DetectionAlert) -> str:
        """Extract the primary executable path from the alert's event."""
        event = alert.event
        if not event:
            return ""
        return (
            getattr(event, "image", "") or
            getattr(event, "source_image", "")
        )

    def _is_whitelisted(self, image_path: str, image_name: str) -> bool:
        """Check if a process is on the whitelist."""
        if image_path.lower() in self.process_whitelist:
            return True
        # Check by name only (partial match)
        for wl_entry in self.process_whitelist:
            if image_name and image_name in wl_entry.lower():
                return True
        return False
