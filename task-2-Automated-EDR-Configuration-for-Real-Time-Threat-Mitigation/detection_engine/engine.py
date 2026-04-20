"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — MAIN DETECTION ENGINE                                         ║
║                                                                              ║
║  This is the brain of the EDR. It:                                          ║
║    1. Reads events from the Windows Event Log (via SysmonLogReader)         ║
║    2. Passes each event through the rule registry                           ║
║    3. Deduplicates alerts to prevent alert storms                           ║
║    4. Triggers automated response for high-severity findings                ║
║    5. Sends alerts to all configured channels                               ║
║    6. Exposes metrics for the dashboard                                     ║
║                                                                              ║
║  Run this in a thread; it's designed to run indefinitely.                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

import yaml

from detection_engine.log_reader import SysmonLogReader
from detection_engine.rules import build_registry
from detection_engine.response import ResponseEngine
from detection_engine.alerting import AlertManager
from detection_engine.event_schema import DetectionAlert, BaseEvent

log = logging.getLogger("edr.engine")


class DeduplicationCache:
    """
    Prevents the same alert from firing repeatedly within a time window.

    Without dedup, a single malicious process could generate hundreds of
    identical alerts. We track (rule_id, process_id) pairs and suppress
    duplicates for a configurable window.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = timedelta(seconds=window_seconds)
        self._cache: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def is_duplicate(self, alert: DetectionAlert) -> bool:
        """Returns True if this alert is a duplicate within the dedup window."""
        key = alert.dedup_key
        now = datetime.now(timezone.utc)

        with self._lock:
            if key in self._cache:
                last_seen = self._cache[key]
                if now - last_seen < self.window:
                    return True

            self._cache[key] = now
            self._prune()
            return False

    def _prune(self):
        """Remove expired entries to prevent memory growth."""
        now = datetime.now(timezone.utc)
        expired = [k for k, v in self._cache.items() if now - v > self.window * 10]
        for k in expired:
            del self._cache[k]


class EDREngine:
    """
    The main EDR detection and response loop.

    Thread-safe design: can run the detection loop in a background thread
    while the Flask dashboard serves the main thread.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self._setup_logging()

        eng_cfg = self.config.get("engine", {})
        self.poll_interval = eng_cfg.get("poll_interval_seconds", 2)
        self.max_events_per_cycle = eng_cfg.get("max_events_per_cycle", 200)
        self.lookback_seconds = eng_cfg.get("lookback_seconds", 300)

        # Core components
        self.log_reader = SysmonLogReader()
        self.rule_registry = build_registry()
        self.response_engine = ResponseEngine(self.config)
        self.alert_manager = AlertManager(self.config)
        self.dedup = DeduplicationCache(
            window_seconds=self.config.get("detection", {}).get("dedup_window_seconds", 60)
        )

        # Metrics (thread-safe with lock)
        self._metrics_lock = threading.Lock()
        self._metrics = {
            "events_processed": 0,
            "alerts_fired": 0,
            "responses_taken": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "events_by_type": defaultdict(int),
            "rules_triggered": defaultdict(int),
            "status": "stopped",
        }

        self._running = False
        self._thread: Optional[threading.Thread] = None

        log.info(
            f"EDR Engine initialized: "
            f"{self.rule_registry.rule_count} rules loaded"
        )

    def _load_config(self, config_path: str) -> dict:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            log.warning(f"Config not found at {config_path} — using defaults")
            return {}
        except Exception as e:
            log.error(f"Config parse error: {e}")
            return {}

    def _setup_logging(self):
        log_cfg = self.config.get("logging", {})
        level = getattr(logging, log_cfg.get("level", "INFO"), logging.INFO)

        # Configure root logger
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Also log to file
        try:
            from pathlib import Path
            log_dir = Path(log_cfg.get("alerts_dir", "C:\\EDR_Lab\\logs\\alerts"))
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / "edr_engine.log", encoding="utf-8")
            fh.setLevel(level)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))
            logging.getLogger().addHandler(fh)
        except Exception as e:
            log.warning(f"Could not set up file logging: {e}")

    # ─── START / STOP ─────────────────────────────────────────────────────────

    def start(self, blocking: bool = True):
        """
        Start the detection engine.

        Args:
            blocking: If True, run in the current thread (blocks).
                      If False, run in a background thread and return immediately.
        """
        with self._metrics_lock:
            self._metrics["status"] = "running"
        self._running = True

        log.info("=" * 60)
        log.info("  CUSTOM EDR ENGINE STARTING")
        log.info("=" * 60)
        log.info(f"  Rules loaded: {self.rule_registry.rule_count}")
        log.info(f"  Poll interval: {self.poll_interval}s")
        log.info(f"  Auto-response: {self.config.get('engine', {}).get('auto_response_enabled', True)}")
        log.info("=" * 60)

        # Print loaded rules summary
        log.info("LOADED RULES:")
        for rule in self.rule_registry.list_rules():
            log.info(
                f"  [{rule['rule_id']}] {rule['rule_name']} "
                f"(Severity: {rule['severity']}, MITRE: {rule['mitre_technique_id']})"
            )

        if blocking:
            self._detection_loop()
        else:
            self._thread = threading.Thread(
                target=self._detection_loop,
                name="EDR-DetectionLoop",
                daemon=True,
            )
            self._thread.start()
            log.info("Detection engine started in background thread.")

    def stop(self):
        """Stop the detection engine."""
        self._running = False
        with self._metrics_lock:
            self._metrics["status"] = "stopped"
        if self._thread:
            self._thread.join(timeout=10)
        log.info("EDR Engine stopped.")

    # ─── MAIN DETECTION LOOP ──────────────────────────────────────────────────

    def _detection_loop(self):
        """
        The heart of the EDR. Reads events, applies rules, responds.
        Designed to run indefinitely in a thread.
        """
        log.info("Detection loop started. Monitoring Sysmon events...")
        log.info(f"Loading historical events (last {self.lookback_seconds}s)...")

        # Process historical events first (catch anything that happened on startup)
        historical = self.log_reader.read_historical(self.lookback_seconds)
        if historical:
            log.info(f"Processing {len(historical)} historical events...")
            for event in historical:
                self._process_event(event)

        log.info("Switching to live monitoring mode...")

        # Live monitoring loop
        try:
            for event in self.log_reader.read_live(self.poll_interval):
                if not self._running:
                    break
                self._process_event(event)

        except KeyboardInterrupt:
            log.info("Interrupted — stopping detection loop.")
        except Exception as e:
            log.error(f"Detection loop error: {e}", exc_info=True)
            with self._metrics_lock:
                self._metrics["status"] = "error"

    def _process_event(self, event: BaseEvent):
        """Process a single event through the rule engine."""
        # Update metrics
        with self._metrics_lock:
            self._metrics["events_processed"] += 1
            self._metrics["events_by_type"][event.event_type] += 1

        # Verbose event logging — makes debugging easy
        img  = getattr(event, "image", "") or getattr(event, "source_image", "")
        cmd  = getattr(event, "command_line", "") or ""
        tgt  = getattr(event, "target_object", "") or getattr(event, "query_name", "")
        dport = getattr(event, "destination_port", "")
        detail = cmd[:120] or tgt[:120] or (f"→port {dport}" if dport else "")
        log.info(f"[EVENT] {event.event_type:<22} | {img.split(chr(92))[-1]:<30} | {detail}")

        # Run all applicable rules
        alerts: List[DetectionAlert] = self.rule_registry.evaluate_all(event)

        for alert in alerts:
            # Deduplicate
            if self.dedup.is_duplicate(alert):
                log.debug(f"Duplicate alert suppressed: {alert.rule_id}")
                continue

            with self._metrics_lock:
                self._metrics["alerts_fired"] += 1
                self._metrics["rules_triggered"][alert.rule_name] += 1

            log.warning(
                f"ALERT [{alert.severity_label}] {alert.rule_id}: {alert.rule_name} "
                f"on {event.event_type} event"
            )

            # Take automated response
            response = self.response_engine.respond(alert)

            if response and response not in ("auto-response disabled", "logged only"):
                with self._metrics_lock:
                    self._metrics["responses_taken"] += 1

            # Send alert notifications
            self.alert_manager.send(alert, response)

    # ─── METRICS & STATUS ─────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """Return current engine metrics (thread-safe)."""
        with self._metrics_lock:
            m = dict(self._metrics)
            m["events_by_type"] = dict(m["events_by_type"])
            m["rules_triggered"] = dict(m["rules_triggered"])
            m["uptime_seconds"] = (
                datetime.now(timezone.utc) -
                datetime.fromisoformat(m["start_time"])
            ).total_seconds()
            return m

    def get_loaded_rules(self) -> list:
        """Return info about all loaded rules."""
        return self.rule_registry.list_rules()

    def get_recent_alerts(self, limit: int = 50) -> list:
        """Return recent alerts for the dashboard."""
        return [a.to_dict() for a in self.alert_manager.get_recent_alerts(limit)]

    def get_alert_stats(self) -> dict:
        """Return alert statistics for dashboard charts."""
        return self.alert_manager.get_stats()

    @property
    def is_running(self) -> bool:
        return self._running
