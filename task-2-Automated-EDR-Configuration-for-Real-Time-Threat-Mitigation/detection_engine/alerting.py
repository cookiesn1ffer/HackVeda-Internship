"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — ALERTING SYSTEM                                               ║
║                                                                              ║
║  Sends alerts via:                                                           ║
║    1. Discord Webhook (rich embeds with color-coded severity)               ║
║    2. Rich console output (colored terminal display)                        ║
║    3. JSON alert log file (for the dashboard and SIEM integration)         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    logging.getLogger("edr.alerting").warning(
        "requests not installed — Discord alerts disabled. Run: pip install requests"
    )

from detection_engine.event_schema import DetectionAlert

log = logging.getLogger("edr.alerting")

# Severity color mapping for Discord embeds
SEVERITY_COLORS = {
    "INFO":     0x95A5A6,   # Grey
    "LOW":      0x3498DB,   # Blue
    "MEDIUM":   0xF39C12,   # Orange
    "HIGH":     0xE74C3C,   # Red
    "CRITICAL": 0x8B0000,   # Dark Red
}

# ANSI color codes for console output
CONSOLE_COLORS = {
    "INFO":     "\033[37m",      # White
    "LOW":      "\033[34m",      # Blue
    "MEDIUM":   "\033[33m",      # Yellow
    "HIGH":     "\033[31m",      # Red
    "CRITICAL": "\033[41;37m",   # White on Red background
    "RESET":    "\033[0m",
}

SEVERITY_ICONS = {
    "INFO":     "ℹ️",
    "LOW":      "🔵",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}


class AlertManager:
    """
    Manages all alert output channels.
    Respects the minimum severity threshold from config.
    """

    def __init__(self, config: dict):
        alert_cfg = config.get("alerting", {})
        log_cfg = config.get("logging", {})
        eng_cfg = config.get("engine", {})

        self.discord_webhook_url = alert_cfg.get("discord_webhook_url", "")
        self.console_alerts = alert_cfg.get("console_alerts", True)
        self.log_file_alerts = alert_cfg.get("log_file_alerts", True)
        self.min_severity = eng_cfg.get("alert_min_severity", 3)

        self.alerts_dir = Path(log_cfg.get("alerts_dir", "logs\\alerts"))
        self.alerts_dir.mkdir(parents=True, exist_ok=True)
        self._alert_log_file = self.alerts_dir / "alerts.jsonl"

        # In-memory store for dashboard
        self._recent_alerts: list = []
        self._max_recent = 500

    def send(self, alert: DetectionAlert, response_taken: str = ""):
        """
        Send an alert through all configured channels.

        Args:
            alert: The detection alert
            response_taken: String describing what automated response was taken
        """
        if alert.severity < self.min_severity:
            return

        alert.response_taken = response_taken
        alert.alert_sent = True

        # Store for dashboard
        self._recent_alerts.insert(0, alert)
        if len(self._recent_alerts) > self._max_recent:
            self._recent_alerts.pop()

        # Send to each channel
        if self.console_alerts:
            self._send_console(alert)

        if self.log_file_alerts:
            self._send_log_file(alert)

        if self.discord_webhook_url and _REQUESTS_AVAILABLE:
            self._send_discord(alert)

    def _send_console(self, alert: DetectionAlert):
        """Rich colored console output."""
        color = CONSOLE_COLORS.get(alert.severity_label, CONSOLE_COLORS["RESET"])
        reset = CONSOLE_COLORS["RESET"]
        icon = SEVERITY_ICONS.get(alert.severity_label, "⚠️")

        separator = "═" * 70
        event = alert.event

        print(f"\n{color}{separator}{reset}")
        print(f"{color}{icon} [{alert.severity_label}] {alert.rule_name} (Rule {alert.rule_id}){reset}")
        print(f"{color}{separator}{reset}")
        print(f"  Time:        {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  MITRE:       {alert.mitre_technique_id} — {alert.mitre_technique_name}")
        print(f"  Tactic:      {alert.mitre_tactic}")
        print(f"  Severity:    {alert.severity}/10")
        print(f"  Description: {alert.description[:300]}")

        if event:
            print(f"  Event Type:  {event.event_type}")
            if hasattr(event, "image"):
                print(f"  Process:     {event.image}")
            if hasattr(event, "process_id"):
                print(f"  PID:         {event.process_id}")
            if hasattr(event, "command_line") and event.command_line:
                print(f"  CommandLine: {event.command_line[:200]}")
            if hasattr(event, "user"):
                print(f"  User:        {event.user}")

        if alert.response_taken:
            print(f"  {color}Response:    {alert.response_taken}{reset}")

        print(f"{color}{separator}{reset}\n")

    def _send_log_file(self, alert: DetectionAlert):
        """Append alert as JSON line to the alert log file."""
        try:
            record = alert.to_dict()
            record["response_taken"] = alert.response_taken
            record["logged_at"] = datetime.now(timezone.utc).isoformat()

            with open(self._alert_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")

        except Exception as e:
            log.error(f"Failed to write alert log: {e}")

    def _send_discord(self, alert: DetectionAlert):
        """Send a rich Discord embed via webhook."""
        if not self.discord_webhook_url:
            return

        color = SEVERITY_COLORS.get(alert.severity_label, 0x95A5A6)
        icon = SEVERITY_ICONS.get(alert.severity_label, "⚠️")
        event = alert.event

        # Build embed fields
        fields = [
            {"name": "🎯 Rule", "value": f"`{alert.rule_id}` — {alert.rule_name}", "inline": False},
            {"name": "📋 MITRE ATT&CK", "value": f"`{alert.mitre_technique_id}` {alert.mitre_technique_name}\nTactic: {alert.mitre_tactic}", "inline": True},
            {"name": "🔥 Severity", "value": f"{alert.severity}/10 — **{alert.severity_label}**", "inline": True},
        ]

        if event:
            if hasattr(event, "image") and event.image:
                fields.append({"name": "💻 Process", "value": f"`{event.image}`", "inline": False})
            if hasattr(event, "process_id") and event.process_id:
                fields.append({"name": "🆔 PID", "value": str(event.process_id), "inline": True})
            if hasattr(event, "user") and event.user:
                fields.append({"name": "👤 User", "value": event.user, "inline": True})
            if hasattr(event, "command_line") and event.command_line:
                cmd_preview = event.command_line[:500]
                fields.append({"name": "⌨️ Command Line", "value": f"```{cmd_preview}```", "inline": False})
            if hasattr(event, "destination_ip") and event.destination_ip:
                fields.append({
                    "name": "🌐 Connection",
                    "value": f"`{event.destination_ip}:{event.destination_port}`",
                    "inline": True
                })

        if alert.response_taken:
            fields.append({
                "name": "🤖 Auto-Response",
                "value": f"```{alert.response_taken}```",
                "inline": False
            })

        embed = {
            "title": f"{icon} EDR ALERT: {alert.rule_name}",
            "description": alert.description[:2000],
            "color": color,
            "fields": fields,
            "footer": {"text": f"Custom EDR | {event.hostname if event else 'unknown'}"},
            "timestamp": alert.timestamp.isoformat(),
        }

        payload = {
            "username": "Custom EDR",
            "avatar_url": "https://img.icons8.com/color/48/000000/security-shield-green.png",
            "embeds": [embed],
        }

        if not _REQUESTS_AVAILABLE:
            log.warning("requests not installed — cannot send Discord alert")
            return
        try:
            resp = requests.post(
                self.discord_webhook_url,
                json=payload,
                timeout=10,
            )
            if resp.status_code == 204:
                log.debug(f"Discord alert sent for {alert.rule_id}")
            else:
                log.warning(f"Discord webhook returned {resp.status_code}: {resp.text[:100]}")
        except requests.exceptions.ConnectionError:
            log.warning("Discord webhook unreachable — check your internet connection.")
        except Exception as e:
            log.error(f"Discord alert failed: {e}")

    def get_recent_alerts(self, limit: int = 50) -> list:
        """Return recent alerts for the dashboard."""
        return self._recent_alerts[:limit]

    def get_stats(self) -> dict:
        """Return alert statistics for the dashboard."""
        if not self._recent_alerts:
            return {
                "total": 0,
                "by_severity": {},
                "by_tactic": {},
                "by_rule": {},
            }

        by_severity = {}
        by_tactic = {}
        by_rule = {}

        for a in self._recent_alerts:
            by_severity[a.severity_label] = by_severity.get(a.severity_label, 0) + 1
            by_tactic[a.mitre_tactic] = by_tactic.get(a.mitre_tactic, 0) + 1
            by_rule[a.rule_name] = by_rule.get(a.rule_name, 0) + 1

        return {
            "total": len(self._recent_alerts),
            "by_severity": by_severity,
            "by_tactic": by_tactic,
            "top_rules": sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10],
        }
