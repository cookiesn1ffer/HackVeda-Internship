#!/usr/bin/env python3
"""
Custom EDR — One-Shot Live Demo Runner
Run as Administrator:  python run_demo.py
"""

import os, sys, time, subprocess, threading, urllib.request, webbrowser
from pathlib import Path

# ─── ANSI colours ────────────────────────────────────────────────────────────
os.system("")          # enable virtual terminal on Windows
R  = "\033[0m"
B  = "\033[1m"
RD = "\033[91m"
GR = "\033[92m"
YL = "\033[93m"
MG = "\033[95m"
CY = "\033[96m"
GY = "\033[90m"

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent
EDR_SCRIPT = ROOT / "run_edr.py"
SIM_SCRIPT = ROOT / "test_scenarios" / "attack_sim_mega_test.ps1"
DASHBOARD  = "http://127.0.0.1:5000"
STATUS_URL = f"{DASHBOARD}/api/status"

_alerts = 0   # live counter

# ─── UI helpers ───────────────────────────────────────────────────────────────
def banner():
    print(f"""
{MG}{B}╔══════════════════════════════════════════════════════════════╗
║   ██████╗██╗   ██╗███████╗████████╗ ██████╗ ███╗   ███╗   ║
║  ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗████╗ ████║   ║
║  ██║     ██║   ██║███████╗   ██║   ██║   ██║██╔████╔██║   ║
║  ██║     ██║   ██║╚════██║   ██║   ██║   ██║██║╚██╔╝██║   ║
║  ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝██║ ╚═╝ ██║   ║
║   ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝   ║
║                                                              ║
║        LIVE DEMO RUNNER  ·  One terminal. Fully automated.  ║
╚══════════════════════════════════════════════════════════════╝{R}
""")

def divider(title="", color=MG):
    bar = "─" * 62
    if title:
        pad = (60 - len(title)) // 2
        print(f"\n{color}{B}┌{bar}┐")
        print(f"│{' ' * pad}{title}{' ' * (60 - pad - len(title))}│")
        print(f"└{bar}┘{R}\n")
    else:
        print(f"{color}{'─' * 64}{R}")

def log(kind, msg, color=CY):
    icons = {"OK": f"{GR}✔{R}", "INFO": f"{CY}·{R}", "WARN": f"{YL}!{R}",
             "ERR": f"{RD}✘{R}", "SIM": f"{MG}▶{R}", "EDR": f"{CY}⬡{R}"}
    icon = icons.get(kind, "·")
    print(f"  {icon}  {color}{msg}{R}", flush=True)

def alert_box(line):
    global _alerts
    _alerts += 1
    sev_color = RD if "CRITICAL" in line or "HIGH" in line else YL if "MEDIUM" in line else GR
    rule = ""
    for part in line.split():
        if part.startswith(("PS", "NET", "PER", "CRED", "INJ")):
            rule = part.rstrip(":")
            break
    short = line.split("ALERT")[-1].strip().lstrip("[").strip() if "ALERT" in line else line
    print(f"""
{sev_color}{B}  ╔══ 🚨 ALERT #{_alerts:02d} ══════════════════════════════════════════╗
  ║  {short[:58]:<58}║
  ╚═══════════════════════════════════════════════════════════╝{R}""",
          flush=True)

# ─── Step 1 — Sysmon ─────────────────────────────────────────────────────────
def check_sysmon():
    divider("STEP 1 — Sysmon Check")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-Service Sysmon64 -EA SilentlyContinue).Status"],
        capture_output=True, text=True)
    s = r.stdout.strip()
    if s == "Running":
        log("OK", "Sysmon64 is RUNNING — kernel-level telemetry active")
    elif s:
        log("WARN", f"Sysmon64 is {s} — starting...", YL)
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Start-Service Sysmon64 -EA SilentlyContinue"],
                       capture_output=True)
        time.sleep(3)
        r2 = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "(Get-Service Sysmon64 -EA SilentlyContinue).Status"],
                             capture_output=True, text=True)
        if r2.stdout.strip() == "Running":
            log("OK", "Sysmon64 started successfully")
        else:
            log("WARN", "Sysmon could not start — EDR runs with limited visibility", YL)
    else:
        log("WARN", "Sysmon not found — install from sysinternals.com for full coverage", YL)

# ─── Step 2 — Start EDR ──────────────────────────────────────────────────────
_SUPPRESS = ("werkzeug", "127.0.0.1 - -", "Running on http")

def _stream_edr(proc):
    for raw in iter(proc.stdout.readline, ""):
        line = raw.rstrip()
        if not line or any(s in line for s in _SUPPRESS):
            continue
        if "ALERT" in line and ("[WARNING]" in line or "WARNING" in line):
            alert_box(line)
        elif "[WARNING]" in line:
            log("EDR", line, YL)
        elif "[ERROR]" in line:
            log("EDR", line, RD)
        elif "[INFO]" in line:
            # Only print meaningful INFO lines, skip boilerplate
            if any(k in line for k in ("rules loaded", "started", "monitoring",
                                       "record #", "Strategy", "RUNNING", "LIVE",
                                       "historical", "Fast-forward")):
                log("EDR", line.split("] ", 1)[-1] if "] " in line else line, GY)
        else:
            log("EDR", line, GY)

def start_edr():
    divider("STEP 2 — Starting EDR")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"   # force UTF-8 in the child process
    env["PYTHONUTF8"]       = "1"       # Python 3.7+ UTF-8 mode flag
    proc = subprocess.Popen(
        [sys.executable, str(EDR_SCRIPT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, encoding="utf-8", errors="replace",
        cwd=str(ROOT), env=env)
    threading.Thread(target=_stream_edr, args=(proc,), daemon=True).start()
    log("OK", f"EDR process started  (PID {proc.pid})")
    return proc

# ─── Step 3 — Wait for dashboard ─────────────────────────────────────────────
def wait_for_dashboard(timeout=90):
    divider("STEP 3 — Dashboard")
    log("INFO", f"Polling {STATUS_URL} ...")
    deadline = time.time() + timeout
    spinner = ["|", "/", "-", "\\"]
    i = 0
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(STATUS_URL, timeout=2) as r:
                if r.status == 200:
                    print()   # clear spinner line
                    return True
        except KeyboardInterrupt:
            raise
        except Exception:
            pass
        elapsed = int(time.time() - (deadline - timeout))
        print(f"  {CY}{spinner[i % len(spinner)]}{R}  waiting for Flask... {elapsed}s / {timeout}s",
              end="\r", flush=True)
        i += 1
        time.sleep(1)
    print()
    return False

# ─── Step 4 — Run simulations ─────────────────────────────────────────────────
def run_simulations():
    divider("STEP 4 — Attack Simulations  (10 scenarios)")
    if not SIM_SCRIPT.exists():
        log("ERR", f"Simulation script not found: {SIM_SCRIPT}", RD)
        return

    log("INFO", "Firing all 10 simulations — watch for ALERT boxes above each step")
    print()

    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(SIM_SCRIPT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True, bufsize=1, encoding="utf-8", errors="replace")

    try:
        proc.stdin.write("\n")
        proc.stdin.flush()
        proc.stdin.close()
    except Exception:
        pass

    for raw in iter(proc.stdout.readline, ""):
        line = raw.rstrip()
        if not line:
            continue
        if "/10]" in line and "[" in line:
            print(f"\n  {MG}{B}{line}{R}", flush=True)
        elif "OK - Fired" in line or "OK -" in line:
            log("SIM", line.strip(), GR)
        elif "MEGA TEST COMPLETE" in line:
            print(f"\n  {GR}{B}  {line}{R}", flush=True)
        elif "Duration" in line or "Simulations" in line:
            log("SIM", line.strip(), GY)
        elif "Expected" in line or "PS00" in line or "NET00" in line or "PER00" in line:
            log("SIM", line.strip(), CY)
        elif "======" in line or "------" in line:
            print(f"  {MG}  {line}{R}", flush=True)
        elif line.strip():
            print(f"     {line}", flush=True)

    proc.wait()

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    check_sysmon()
    edr = start_edr()

    ready = wait_for_dashboard(timeout=90)
    if ready:
        log("OK",   f"Dashboard LIVE  →  {DASHBOARD}")
        log("INFO", "Opening browser...")
        webbrowser.open(DASHBOARD)
    else:
        log("WARN", "Dashboard didn't respond — running simulations anyway", YL)

    log("INFO", "Waiting 5 s for live event monitor to initialise...")
    time.sleep(5)

    run_simulations()

    log("INFO", "Simulation done — waiting 8 s for trailing alerts...")
    time.sleep(8)

    divider("DEMO COMPLETE", GR)
    print(f"""
  {GR}{B}Results{R}
  {'─'*40}
  {CY}Alerts fired  :{R}  {B}{_alerts}{R}
  {CY}Dashboard     :{R}  {DASHBOARD}
  {CY}Rules loaded  :{R}  28  (PS · NET · PER · CRED · INJ)
  {'─'*40}
  {GY}EDR is still running.  Press Ctrl+C to stop.{R}
""")

    try:
        edr.wait()
    except KeyboardInterrupt:
        print(f"\n{YL}  Stopping EDR...{R}")
        edr.terminate()
        edr.wait()
        print(f"{GR}  Stopped. Goodbye.{R}\n")

if __name__ == "__main__":
    main()
