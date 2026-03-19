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

---

### Install Ubuntu Server

Follow installer:

* Language → English
* Keyboard → Default
* Type → Ubuntu Server (**NOT minimal**)
* Network → Auto (DHCP)
* Storage → Use entire disk

#### Profile Setup

* Username: `cookie`
* Password: `1234` *(lab only, keep simple)*

 Skip:

* Ubuntu Pro
* Snap packages

Finish installation → Reboot VM

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

---

### After Installation

You’ll get:

* Username: `admin`
* Password: *(copy and save it)*

---

### Get VM IP

```bash
ip a
```

Look for:

```
inet 192.168.x.x
```

---

### Access Dashboard (from host browser)

```
https://<VM-IP>
```

Login:

```
admin / <password>
```
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

---

### Verify

* Agent should appear **green** in dashboard

---

## ⚡ STEP 4 — Enable Windows Logging

Run in PowerShell (Admin):

```powershell
auditpol /set /category:* /success:enable /failure:enable
```

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

---

## 🧪 STEP 6 — Monitor Alerts in Wazuh

Go to:

* **Discover**

---

### 📊 You should see:

* Failed login attempts
* PowerShell activity

---


## 🎯 Done

You now have:

* Working SIEM (Wazuh)
* Windows endpoint logging
* Real attack simulation + detection

---