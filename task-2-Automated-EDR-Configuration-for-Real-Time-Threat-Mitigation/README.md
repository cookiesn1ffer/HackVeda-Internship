# Custom Automated EDR

> A fully custom Endpoint Detection & Response system built from scratch using **Sysmon**, **Python**, and **MITRE ATT&CK** — designed for learning, research, and portfolio demonstration.

---

## Overview

This project implements a working EDR pipeline in pure Python on top of Windows kernel telemetry. It reads raw Sysmon events, normalises them into typed dataclasses, runs them through a 28-rule detection engine, triggers automated responses, and streams everything to a live web dashboard — all in one terminal with a single command.

```
Sysmon (kernel) → log_reader.py → detection engine → response + alerts → dashboard
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Windows Kernel                           │
│   Process Create · Network Connect · Registry · DNS · etc.     │
└─────────────────────────┬───────────────────────────────────────┘
                          │  Event IDs 1,3,5,8,10,11,12,13,14,22,25
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Sysmon64 (sensor layer)                      │
│              sysmon_config.xml  ·  schema v4.91                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │  Windows Event Log channel
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│              log_reader.py  (event pipeline)                    │
│   EvtQuery/EvtRender  →  wevtutil  →  ReadEventLog fallback    │
│   Normalises raw XML into typed Python dataclasses              │
└─────────────────────────┬───────────────────────────────────────┘
                          │  BaseEvent subclasses
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│            detection engine  (engine.py + rules/)               │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ │
│  │ PS001-06 │ │ NET001-05│ │ PER001-07│ │CRED001-05│ │INJ   │ │
│  │PowerShell│ │ Network  │ │Persistence│ │Credential│ │001-05│ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────┘ │
│                                                                  │
│   Deduplication cache  ·  Severity scoring  ·  MITRE mapping   │
└────────────┬────────────────────────┬───────────────────────────┘
             │                        │
             ▼                        ▼
┌────────────────────┐    ┌───────────────────────────────────────┐
│   response.py      │    │            alerting.py                │
│  Kill process      │    │  Console (colour)  ·  Discord webhook │
│  Firewall block    │    │  JSONL file log    ·  In-memory store │
│  Network isolate   │    └──────────────────┬────────────────────┘
└────────────────────┘                       │
                                             ▼
                              ┌──────────────────────────┐
                              │   Flask dashboard         │
                              │   http://127.0.0.1:5000  │
                              │                          │
                              │  Events · Alerts · MITRE │
                              │  Severity chart · Rules  │
                              └──────────────────────────┘
```

---

## Detection Rules  (28 total)

### PowerShell  `PS001 – PS006`

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| PS001 | Encoded Command (`-Enc` flag) | HIGH | T1059.001 |
| PS002 | Download Cradle (`IEX`, `WebClient`) | HIGH | T1059.001 |
| PS003 | AMSI Bypass (`AmsiUtils`, `amsiInitFailed`) | CRITICAL | T1562.001 |
| PS004 | Suspicious Parent Spawning PowerShell | HIGH | T1059.001 |
| PS005 | Evasion Flags (`-NoP -NonI -W Hidden`) | MEDIUM | T1059.001 |
| PS006 | Reflection / In-Memory Assembly Loading | HIGH | T1620 |

### Network  `NET001 – NET005`

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| NET001 | LOLBin Network Abuse (`certutil`, `bitsadmin`) | HIGH | T1105 |
| NET002 | Suspicious Port Connection (4444, 1337, 6666…) | CRITICAL | T1071 |
| NET003 | Office App Outbound Connection | HIGH | T1071.001 |
| NET004 | Unexpected Process Makes Network Call | CRITICAL | T1055 |
| NET005 | Likely Reverse Shell (cmd/PS on non-standard port) | CRITICAL | T1059 |

### Persistence  `PER001 – PER007`

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| PER001 | Registry Run Key Write | HIGH | T1547.001 |
| PER002 | Scheduled Task Created via CLI | MEDIUM | T1053.005 |
| PER003 | New Windows Service Installed | HIGH | T1543.003 |
| PER004 | File Dropped in Startup Folder | HIGH | T1547.001 |
| PER005 | AppInit DLL Hijack | CRITICAL | T1546.010 |
| PER006 | IFEO Debugger Hijack | CRITICAL | T1546.012 |
| PER007 | Windows Defender Disabled via Registry | CRITICAL | T1562.001 |

### Credentials  `CRED001 – CRED005`

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| CRED001 | LSASS Memory Access (credential dumping masks) | CRITICAL | T1003.001 |
| CRED002 | Known Credential Dump Tool Executed | CRITICAL | T1003 |
| CRED003 | ProcDump Targeting LSASS | CRITICAL | T1003.001 |
| CRED004 | SAM Database Access Attempt | CRITICAL | T1003.002 |
| CRED005 | Credential Access via Volume Shadow Copy | CRITICAL | T1003.003 |

### Injection  `INJ001 – INJ005`

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| INJ001 | CreateRemoteThread Injection | CRITICAL | T1055.001 |
| INJ002 | Process Image Tampering (hollowing/herpaderping) | CRITICAL | T1055.012 |
| INJ003 | LOLBin Proxy Execution (mshta, regsvr32, msbuild) | HIGH | T1218 |
| INJ004 | WMI Remote Execution | HIGH | T1021.006 |
| INJ005 | Suspicious Process Ancestry Chain | HIGH | T1059 |

---

## Quick Start

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.11  →  [python.org](https://www.python.org/downloads/release/python-3119/) *(check "Add to PATH")*
- Administrator rights
- Sysmon64 already extracted to `Sysmon\` in this folder

### 1 — Install dependencies

```powershell
# Open PowerShell as Administrator
cd "C:\path\to\Automated edr"
pip install -r requirements.txt
```

### 2 — Install Sysmon

```powershell
cd Sysmon
.\Sysmon64.exe -accepteula -i
.\Sysmon64.exe -c ..\sysmon_config.xml
Get-Service Sysmon64   # should show: Running
```

### 3 — Run the demo

```powershell
# Back in the project root, as Administrator:
python run_demo.py
```

That's it. The script:
1. Confirms Sysmon is running (starts it if stopped)
2. Launches the EDR engine in the background
3. Waits for the dashboard, then opens it in your browser automatically
4. Fires all 10 attack simulations in sequence
5. Streams alerts live as they fire

---

## Project Structure

```
Automated edr/
│
├── run_demo.py                     ← ONE-SHOT LAUNCHER  (start here)
├── run_edr.py                      ← EDR entry point (used by run_demo)
├── config.yaml                     ← All tunable settings
├── requirements.txt                ← Python dependencies
├── sysmon_config.xml               ← Sysmon sensor config (schema 4.91)
├── CustomEDR.Sysmon.Events.yaml    ← Velociraptor VQL artifact (optional)
│
├── detection_engine/
│   ├── engine.py                   ← Main detection + response loop
│   ├── log_reader.py               ← Sysmon event reader (EvtQuery / wevtutil)
│   ├── event_schema.py             ← Normalised event dataclasses
│   ├── alerting.py                 ← Console · Discord · file alerts
│   ├── response.py                 ← Process kill · firewall block · isolation
│   └── rules/
│       ├── base_rule.py            ← BaseRule + RuleRegistry
│       ├── powershell_rules.py     ← PS001 – PS006
│       ├── network_rules.py        ← NET001 – NET005
│       ├── persistence_rules.py    ← PER001 – PER007
│       ├── credential_rules.py     ← CRED001 – CRED005
│       └── injection_rules.py      ← INJ001 – INJ005
│
├── dashboard/
│   ├── app.py                      ← Flask API routes
│   └── templates/index.html        ← Live dashboard UI (Chart.js)
│
├── test_scenarios/
│   └── attack_sim_mega_test.ps1    ← All 10 simulations in one script
│
└── Sysmon/
    ├── Sysmon64.exe                ← Sysmon binary
    └── sysmon_config.xml           ← Applied config
```

---

## Dashboard

Open `http://127.0.0.1:5000` after running `run_demo.py` (it opens automatically).

| Widget | Description |
|--------|-------------|
| Events Processed | Total Sysmon events read since startup |
| Alerts Fired | Total rule matches |
| Responses Taken | Automated actions (kills, firewall blocks) |
| Severity Chart | Doughnut breakdown: CRITICAL / HIGH / MEDIUM / LOW |
| MITRE Tactics | Bar chart of ATT&CK tactics triggered |
| Alert Feed | Live table with rule ID, process, command line, response |
| Loaded Rules | All 28 rules with severity and MITRE technique |

Auto-refreshes every 5 seconds.

---

## Configuration

Edit `config.yaml` — no code changes needed.

```yaml
engine:
  auto_response_enabled: true       # set false for monitor-only mode
  auto_response_min_severity: 7     # 7=HIGH, 9=CRITICAL
  alert_min_severity: 3

detection:
  dedup_window_seconds: 60
  suspicious_ports: [4444, 1337, 6666, 31337]

alerting:
  discord_webhook_url: ""           # paste your webhook URL here
  console_alerts: true
```

---

## Automated Response

When a rule fires above the severity threshold the EDR takes action automatically:

| Action | Trigger | How |
|--------|---------|-----|
| Kill process | Severity ≥ 7 (HIGH) | Win32 API → psutil → taskkill |
| Firewall block | Severity ≥ 7 | `netsh advfirewall` outbound rule |
| Network isolate | Manual flag | Blocks all outbound except EDR traffic |

Processes in `config.yaml → response.process_whitelist` are never touched.

---

## Attack Simulations

The mega test (`test_scenarios/attack_sim_mega_test.ps1`) fires 10 safe simulations — no real malware, all changes cleaned up:

| # | Simulation | Expected Rule |
|---|-----------|--------------|
| 1 | Encoded PowerShell (`-Enc`) | PS001 |
| 2 | Download Cradle (`IEX + WebClient`) | PS002 |
| 3 | AMSI Bypass string patterns | PS003 |
| 4 | Registry Run Key write + delete | PER001 |
| 5 | Scheduled task create + delete | PER002 |
| 6 | `certutil -urlcache` LOLBin | NET001 |
| 7 | TCP connect to port 4444 | NET002 |
| 8 | IFEO Debugger key write + delete | PER006 |
| 9 | Defender DisableAntiSpyware registry key | PER007 |
| 10 | DNS query to suspicious domain | NET005 |

---

## Extending the EDR

Add a new rule in under 20 lines:

```python
# detection_engine/rules/custom_rules.py
from detection_engine.rules.base_rule import BaseRule
from detection_engine.event_schema import ProcessCreateEvent, DetectionAlert
from typing import Optional

class MyRule(BaseRule):
    rule_id              = "CUS001"
    rule_name            = "My Custom Detection"
    description          = "Detects something suspicious"
    mitre_tactic         = "Execution"
    mitre_technique_id   = "T1059"
    mitre_technique_name = "Command and Scripting Interpreter"
    severity             = 7
    event_types          = (ProcessCreateEvent,)

    def evaluate(self, event: ProcessCreateEvent) -> Optional[DetectionAlert]:
        if "suspicious" in (event.command_line or "").lower():
            return self._make_alert(event, f"Suspicious command: {event.command_line}")
        return None

ALL_RULES = [MyRule]
```

Then register it in `detection_engine/rules/__init__.py`.

---

## Red Team Bypass Exercises

Use these to actively improve the EDR after seeing it work:

| Bypass | Gap | Fix |
|--------|-----|-----|
| Rename `powershell.exe` | PS001 checks image name | Add hash / OriginalFileName checks |
| Use XOR encoding instead of Base64 | PS001 only checks `-Enc` | Add entropy / hex decode detection |
| Inject into a whitelisted process | Process kill is blocked | Use Event ID 8 (RemoteThread) detection |
| C2 over HTTPS on port 443 | NET002 ignores 443 | Track PowerShell → external IP frequency |
| Time attacks after dedup window | 60 s dedup window | Lower `dedup_window_seconds`, add timeline correlation |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Sensor | Sysmon v15.20 (schema 4.91) |
| Event API | pywin32 — EvtQuery / ReadEventLog |
| Detection | Python 3.11 — dataclasses, threading |
| Dashboard | Flask 3 + Chart.js |
| Alerting | Discord webhooks + JSONL file log |
| Response | Win32 API, psutil, netsh |

---

## Disclaimer

This project is built for **educational and portfolio purposes only**. All attack simulations are safe and benign — no real malware is involved and every change is cleaned up automatically. Run only in a lab environment you own and control.
