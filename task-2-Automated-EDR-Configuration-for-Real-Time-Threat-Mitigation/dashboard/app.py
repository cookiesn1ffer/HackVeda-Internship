"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — FLASK WEB DASHBOARD                                           ║
║                                                                              ║
║  Live web dashboard showing:                                                 ║
║    - Real-time alert feed                                                   ║
║    - Severity distribution chart                                            ║
║    - MITRE ATT&CK tactic breakdown                                          ║
║    - Engine metrics (events/sec, uptime, rule count)                       ║
║    - Loaded rules list                                                      ║
║                                                                              ║
║  The dashboard runs in the main thread while the detection engine           ║
║  runs in a background thread.                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import sys
import os
import time
from pathlib import Path

# Add parent directory to path so we can import detection_engine
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, jsonify, render_template, send_from_directory, Response, stream_with_context
from flask_cors import CORS

app = Flask(__name__, template_folder="templates")
CORS(app)

# Global reference to the EDR engine (injected by run_edr.py)
_engine = None


def set_engine(engine):
    global _engine
    _engine = engine


# ─── API ENDPOINTS ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard HTML."""
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """Engine status and metrics."""
    if not _engine:
        return jsonify({"status": "not_started", "error": "Engine not initialized"})

    metrics = _engine.get_metrics()
    return jsonify({
        "status": metrics.get("status", "unknown"),
        "uptime_seconds": metrics.get("uptime_seconds", 0),
        "events_processed": metrics.get("events_processed", 0),
        "alerts_fired": metrics.get("alerts_fired", 0),
        "responses_taken": metrics.get("responses_taken", 0),
        "rule_count": len(_engine.get_loaded_rules()),
        "start_time": metrics.get("start_time", ""),
        "events_by_type": metrics.get("events_by_type", {}),
    })


@app.route("/api/alerts")
def api_alerts():
    """Recent alerts list."""
    if not _engine:
        return jsonify({"alerts": [], "total": 0})

    alerts = _engine.get_recent_alerts(limit=100)
    return jsonify({
        "alerts": alerts,
        "total": len(alerts),
    })


@app.route("/api/stats")
def api_stats():
    """Alert statistics for charts."""
    if not _engine:
        return jsonify({})

    stats = _engine.get_alert_stats()
    return jsonify(stats)


@app.route("/api/rules")
def api_rules():
    """List of all loaded detection rules."""
    if not _engine:
        return jsonify({"rules": []})

    rules = _engine.get_loaded_rules()
    return jsonify({
        "rules": rules,
        "total": len(rules),
    })


@app.route("/api/metrics/events_by_type")
def api_events_by_type():
    """Event type breakdown for charts."""
    if not _engine:
        return jsonify({})
    m = _engine.get_metrics()
    return jsonify(m.get("events_by_type", {}))


@app.route("/api/rules/triggered")
def api_rules_triggered():
    """Which rules have fired and how many times."""
    if not _engine:
        return jsonify({})
    m = _engine.get_metrics()
    return jsonify(m.get("rules_triggered", {}))


@app.route("/api/events/stream")
def event_stream():
    """
    Server-Sent Events endpoint — pushes updates to the browser instantly
    whenever the alert count changes or metrics tick over.

    The browser opens one long-lived connection; we yield 'data:' lines
    whenever something changes.  No more 5-second stale polling.
    """
    def generate():
        last_alert_count = -1
        last_events_processed = -1

        while True:
            try:
                if _engine:
                    metrics = _engine.get_metrics()
                    alert_count = metrics.get("alerts_fired", 0)
                    events_processed = metrics.get("events_processed", 0)

                    # Push whenever alerts or event counts change
                    if alert_count != last_alert_count or events_processed != last_events_processed:
                        last_alert_count = alert_count
                        last_events_processed = events_processed

                        # Bundle status + alerts + stats in one push
                        alerts = _engine.get_recent_alerts(limit=100)
                        stats = _engine.get_alert_stats()

                        payload = json.dumps({
                            "type": "update",
                            "status": {
                                "status": metrics.get("status", "unknown"),
                                "uptime_seconds": metrics.get("uptime_seconds", 0),
                                "events_processed": events_processed,
                                "alerts_fired": alert_count,
                                "responses_taken": metrics.get("responses_taken", 0),
                                "rule_count": len(_engine.get_loaded_rules()),
                                "start_time": metrics.get("start_time", ""),
                                "events_by_type": metrics.get("events_by_type", {}),
                            },
                            "alerts": alerts,
                            "stats": stats,
                        }, default=str)
                        yield f"data: {payload}\n\n"

                    else:
                        # Send a heartbeat every ~10 s so the connection stays alive
                        yield f": heartbeat\n\n"

                else:
                    yield f": waiting for engine\n\n"

            except GeneratorExit:
                break
            except Exception:
                pass

            time.sleep(0.5)   # check for changes twice per second

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if proxied
            "Connection": "keep-alive",
        },
    )


def run_dashboard(engine, host="127.0.0.1", port=5000):
    """Start the Flask dashboard with the given engine instance."""
    set_engine(engine)
    app.run(host=host, port=port, debug=False, use_reloader=False)
