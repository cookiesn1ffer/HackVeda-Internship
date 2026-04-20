#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — MAIN ENTRY POINT                                              ║
║                                                                              ║
║  USAGE:                                                                      ║
║    python run_edr.py                        # Full EDR + dashboard          ║
║    python run_edr.py --no-dashboard         # Detection only, no web UI     ║
║    python run_edr.py --simulate             # Use simulated events (no Win) ║
║    python run_edr.py --list-rules           # Print all loaded rules        ║
║    python run_edr.py --test-discord         # Test Discord webhook          ║
║    python run_edr.py --remove-isolation     # Restore network after isolate ║
║                                                                              ║
║  REQUIREMENTS:                                                               ║
║    - Python 3.10+                                                            ║
║    - pip install -r requirements.txt                                         ║
║    - Sysmon installed and running (for live mode)                           ║
║    - config.yaml with your settings                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import logging
import os
import sys
import threading
from pathlib import Path

# Force UTF-8 output so Unicode banner characters don't crash on cp1252 terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

import yaml

log = logging.getLogger("edr.main")


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_file = Path(config_path)
    if not config_file.exists():
        print(f"⚠️  Config file '{config_path}' not found. Using defaults.")
        return {}
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        return {}


def print_banner():
    """Print the startup banner."""
    banner = r"""
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║    ██████╗██╗   ██╗███████╗████████╗ ██████╗ ███╗   ███╗    ║
  ║   ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗████╗ ████║    ║
  ║   ██║     ██║   ██║███████╗   ██║   ██║   ██║██╔████╔██║    ║
  ║   ██║     ██║   ██║╚════██║   ██║   ██║   ██║██║╚██╔╝██║    ║
  ║   ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝██║ ╚═╝ ██║    ║
  ║    ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝    ║
  ║                                                               ║
  ║   Custom Automated EDR  |  Learning & Portfolio Edition       ║
  ║   Sysmon + Velociraptor + Python Detection Engine             ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def cmd_list_rules(config: dict):
    """Print all loaded detection rules and exit."""
    from detection_engine.rules import build_registry
    registry = build_registry()
    rules = registry.list_rules()

    print(f"\n{'═' * 70}")
    print(f"  LOADED DETECTION RULES ({len(rules)} total)")
    print(f"{'═' * 70}")

    categories = {}
    for rule in rules:
        prefix = rule["rule_id"][:3]
        categories.setdefault(prefix, []).append(rule)

    category_names = {
        "PS0": "🐚 PowerShell",
        "NET": "🌐 Network",
        "PER": "🔒 Persistence",
        "CRE": "🔑 Credential Access",
        "INJ": "💉 Injection / Evasion",
    }

    for prefix, rules_in_cat in sorted(categories.items()):
        cat_name = category_names.get(prefix, f"📌 {prefix}")
        print(f"\n  {cat_name}")
        print(f"  {'─' * 60}")
        for r in rules_in_cat:
            sev_color = "\033[31m" if r["severity"] >= 8 else "\033[33m" if r["severity"] >= 5 else "\033[34m"
            reset = "\033[0m"
            print(
                f"  [{r['rule_id']}] {r['rule_name']:<45} "
                f"{sev_color}Sev:{r['severity']}/10{reset}  "
                f"\033[35m{r['mitre_technique_id']}\033[0m"
            )

    print(f"\n{'═' * 70}\n")


def cmd_test_discord(config: dict):
    """Send a test Discord alert and exit."""
    webhook_url = config.get("alerting", {}).get("discord_webhook_url", "")
    if not webhook_url:
        print("❌ No Discord webhook URL configured in config.yaml")
        print("   Set alerting.discord_webhook_url in your config file.")
        return

    from detection_engine.alerting import AlertManager
    from detection_engine.event_schema import DetectionAlert, ProcessCreateEvent
    from datetime import datetime, timezone

    manager = AlertManager(config)

    # Create a fake test alert
    test_event = ProcessCreateEvent(
        timestamp=datetime.now(timezone.utc),
        hostname="TEST-MACHINE",
        process_id=9999,
        image="C:\\Test\\custom_edr_test.exe",
        command_line="python run_edr.py --test-discord",
        user="TEST-USER\\admin",
        integrity_level="High",
    )

    test_alert = DetectionAlert(
        rule_id="TEST001",
        rule_name="Discord Webhook Test",
        description="This is a test alert from your Custom EDR system. If you see this, Discord alerting is working correctly! 🎉",
        mitre_tactic="Test",
        mitre_technique_id="T0000",
        mitre_technique_name="Test Technique",
        severity=5,
        event=test_event,
    )

    print("Sending test alert to Discord...")
    manager._send_discord(test_alert)
    print("✓ Done! Check your Discord channel.")


def cmd_remove_isolation(config: dict):
    """Remove endpoint isolation (restore all firewall rules)."""
    from detection_engine.response import ResponseEngine
    engine = ResponseEngine(config)
    engine.remove_isolation()
    print("✓ Network isolation removed. Connectivity restored.")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Custom Automated EDR — Sysmon + Velociraptor + Python"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: config.yaml)"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Run detection engine only, without the web dashboard"
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Use simulated events (for testing without Windows/Sysmon)"
    )
    parser.add_argument(
        "--list-rules", action="store_true",
        help="Print all loaded detection rules and exit"
    )
    parser.add_argument(
        "--test-discord", action="store_true",
        help="Send a test Discord alert and exit"
    )
    parser.add_argument(
        "--remove-isolation", action="store_true",
        help="Remove endpoint isolation firewall rules and restore network"
    )
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)

    # Handle one-shot commands
    if args.list_rules:
        cmd_list_rules(config)
        return

    if args.test_discord:
        cmd_test_discord(config)
        return

    if args.remove_isolation:
        cmd_remove_isolation(config)
        return

    # Force simulation mode if requested
    if args.simulate:
        import detection_engine.log_reader as lr
        lr.WINDOWS = False
        print("⚠️  Simulation mode enabled — using synthetic events")

    # Import engine (after setting WINDOWS flag if needed)
    from detection_engine.engine import EDREngine

    print(f"  Configuration: {args.config}")
    print(f"  Dashboard: {'disabled' if args.no_dashboard else 'http://127.0.0.1:5000'}")
    print(f"  Auto-response: {config.get('engine', {}).get('auto_response_enabled', True)}")
    print()

    # Create the engine
    engine = EDREngine(args.config)

    if args.no_dashboard:
        # Run detection engine in the main thread (blocking)
        print("  Starting detection engine (Ctrl+C to stop)...")
        print()
        try:
            engine.start(blocking=True)
        except KeyboardInterrupt:
            engine.stop()
            print("\n  EDR stopped.")

    else:
        # Run detection engine in background thread, dashboard in main thread
        print("  Starting detection engine in background thread...")
        engine.start(blocking=False)

        # Give engine a moment to initialize
        import time
        time.sleep(1)

        # Start dashboard (blocks in main thread)
        dash_cfg = config.get("dashboard", {})
        host = dash_cfg.get("host", "127.0.0.1")
        port = dash_cfg.get("port", 5000)

        print(f"  Starting dashboard at http://{host}:{port}")
        print(f"  Press Ctrl+C to stop.\n")

        try:
            from dashboard.app import run_dashboard
            run_dashboard(engine, host=host, port=port)
        except KeyboardInterrupt:
            engine.stop()
            print("\n  EDR stopped.")
        except ImportError as e:
            print(f"  Dashboard unavailable: {e}")
            print("  Install: pip install flask flask-cors")
            print("  Running detection engine only...")
            try:
                engine._thread.join()
            except KeyboardInterrupt:
                engine.stop()


if __name__ == "__main__":
    main()
