# HackVeda Internship

This repository documents my cybersecurity internship at HackVeda, covering hands-on labs, detection engineering, and threat simulation projects.

---

## Tasks

### Task 1 — SIEM Threat Alerts with Wazuh
**Folder:** `task-1-siem-threat-alerts/`

Set up a full SIEM pipeline using Wazuh on a Ubuntu VM (VirtualBox), enrolled a Windows endpoint as an agent, enabled audit logging, simulated brute-force attacks, and monitored real-time alerts in the Wazuh dashboard.

**Key skills:** VirtualBox, Wazuh, Windows Agent enrollment, audit policy, attack simulation, log analysis.

---

### Task 2 — Automated EDR Configuration for Real-Time Threat Mitigation
**Folder:** `task-2-Automated-EDR-Configuration-for-Real-Time-Threat-Mitigation/`

Built a fully custom Endpoint Detection and Response (EDR) system in Python that ingests Sysmon events from the Windows Event Log in real time, evaluates them against 20+ MITRE ATT&CK-mapped detection rules, triggers automated responses (process kill, firewall block), and pushes live alerts to a web dashboard and Discord.

**Stack:** Python, Sysmon, Velociraptor, Flask, Server-Sent Events, Discord Webhooks, Win32 API.

**Detection categories:** Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Command & Control.

---

## Repository Structure

```
HackVeda-Internship/
├── task-1-siem-threat-alerts/
│   └── README.md                   ← Full SIEM lab walkthrough
│
├── task-2-Automated-EDR-Configuration-for-Real-Time-Threat-Mitigation/
│   ├── detection_engine/           ← Core EDR engine (rules, parser, alerting)
│   │   └── rules/                  ← 20+ MITRE-mapped detection rules
│   ├── dashboard/                  ← Flask real-time web dashboard (SSE)
│   ├── test_scenarios/             ← PowerShell attack simulations
│   ├── Sysmon/                     ← Sysmon setup instructions
│   ├── config.yaml                 ← Main configuration file
│   ├── sysmon_config.xml           ← Sysmon event capture config
│   ├── CustomEDR.Sysmon.Events.yaml← Velociraptor artifact definition
│   ├── run_edr.py                  ← Production entry point
│   ├── run_demo.py                 ← Demo/dry-run mode
│   └── requirements.txt
│
└── README.md
```

---

## About

This repository serves as both a practical portfolio and a reference for anyone interested in defensive security engineering — from SIEM setup to custom EDR development.

Useful for learners interested in: threat detection, Windows event log analysis, MITRE ATT&CK, Python security tooling, and automated incident response.
