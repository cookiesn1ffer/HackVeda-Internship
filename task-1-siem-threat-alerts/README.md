#  SIEM Lab Setup using Wazuh (VirtualBox)

---

## STEP 0 — Install VirtualBox

### Windows

* Download: https://www.virtualbox.org/
* Install normally (default settings are fine)

---

## STEP 1 — Create Ubuntu VM (SIEM Server)

###Download Ubuntu Server ISO

* https://ubuntu.com/download/server

---

### Create VM in VirtualBox

* **Name:** SIEM
* **Type:** Linux
* **Version:** Ubuntu (64-bit)
* **RAM:** 4GB minimum (6GB recommended)
* **CPU:** 2 cores
* **Storage:** 40GB

<img width="750" alt="1Create VM in VirtualBox" src="https://github.com/user-attachments/assets/f355326d-c149-428a-b119-9431bd1e5382" />

---

### Install Ubuntu Server

Follow installer:

* Language → English
* Keyboard → Default
* Type → Ubuntu Server (**NOT minimal**)
* Network → Auto (DHCP)
* Storage → Use entire disk

<img width="750" alt="2Follow installer" src="https://github.com/user-attachments/assets/e6933536-5fd3-4620-be7c-b8f6119da8fb" />

#### Profile Setup

* Username: `cookie`
* Password: `1234` *(lab only, keep simple)*

 Skip:

* Ubuntu Pro
* Snap packages

Finish installation → Reboot VM

<img width="750" alt="Server" src="https://github.com/user-attachments/assets/f274109b-bff4-4d2c-8c43-bd0eb22b870c" />

---

## STEP 2 — Install Wazuh (Main Setup)

Login to Ubuntu VM and run:

```bash
sudo apt update && sudo apt upgrade -y
```

### Install Wazuh

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a -i
```

Takes ~10–15 minutes

<img width="750" alt="Annotation 2026-03-19 212933" src="https://github.com/user-attachments/assets/c3660b96-c693-4e29-998a-e9cd0f32cda9" />

---

### After Installation

You’ll get:

* Username: `admin`
* Password: *(copy and save it)*

<img width="750" alt="Annotation 2026-03-19 213058" src="https://github.com/user-attachments/assets/b43ae28a-da24-44ae-a291-ec7989b9fdb3" />

---

### Get VM IP

```bash
ip a
```

Look for:

```
inet 192.168.x.x
```

<img width="750" alt="Server" src="https://github.com/user-attachments/assets/194c0f5d-7b09-4f3a-941d-d39f9b713d17" />

---

### Access Dashboard (from host browser)

```
https://<VM-IP>
```

Login:

```
admin / <password>
```

<img width="750" alt="Annotation 2026-03-19 213332" src="https://github.com/user-attachments/assets/1e602f33-a6d1-4243-8a88-750114a31393" />

---

## STEP 3 — Add Windows Agent

### Add Agent in Wazuh Dashboard

1. Go to **Agents**
2. Click **Add Agent**
3. Select:

   * OS → Windows
   * Name → win10 (or anything)
   * IP → your Windows machine IP

---

### Install Agent on Windows

During installation:

```
Manager IP = <Ubuntu VM IP>
```

---

### Start Agent

Open PowerShell (Admin):

```powershell
net start wazuh
```

<img width="750" alt="Annotation 2026-03-19 213505" src="https://github.com/user-attachments/assets/cecc79b3-9a88-4edf-86f3-62bc8d09164e" />

---

### Verify

* Agent should appear **green** in dashboard

<img width="750" alt="Annotation 2026-03-19 213640" src="https://github.com/user-attachments/assets/45dd7663-e9e1-4d63-b533-42e4dcec8b32" />

---

## ⚡ STEP 4 — Enable Windows Logging

Run in PowerShell (Admin):

```powershell
auditpol /set /category:* /success:enable /failure:enable
```

<img width="750" alt="Annotation 2026-03-19 213734" src="https://github.com/user-attachments/assets/035498ca-3a6b-4b45-9758-c3f924e44364" />

---

## STEP 5 — Simulate Attacks

---

### Attack 1: Failed Login

1. Open powershell
2. Enter the following command:
```
net use \\192.168.1.3\IPC$ /user:fakeuser wrongpass
```
3. Repeat this many times

<img width="750" alt="Annotation 2026-03-19 214057" src="https://github.com/user-attachments/assets/9f2bb193-04de-4d7d-9f28-5c315aacc3f0" />

---

## 🧪 STEP 6 — Monitor Alerts in Wazuh

Go to:

* **Discover**

---

### 📊 You should see:

* Failed login attempts
* PowerShell activity

<img width="750" alt="Annotation 2026-03-19 214149" src="https://github.com/user-attachments/assets/e6e33fc3-45e6-4ab4-9e9c-13c0d5fd7960" />

---


## 🎯 Done

You now have:

* Working SIEM (Wazuh)
* Windows endpoint logging
* Real attack simulation + detection

---
