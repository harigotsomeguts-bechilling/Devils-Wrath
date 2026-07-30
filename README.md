# Devil's Wrath 🚀

**Devil's Wrath** is a lightweight, automated Active Directory (AD) misconfiguration scanner written in Python. Designed to run natively from a Kali Linux machine, this tool helps penetration testers rapidly assess the security posture of a Windows Domain Controller via a structured, 3-step automated auditing process.

---

## ⚡ Key Features (The 3-Step Chain)

* **Step 1: SMB Null Session Validation** – Attempts an unauthenticated anonymous bind to target services to check for information disclosure flaws.
* **Step 2: Password Policy & SAMR Audit** – Remotely queries the Domain Password Policy using SAMR RPC interfaces to flag weak constraints.
* **Step 3: Network Share Enumeration** – Scans and extracts a list of accessible SMB shares, specifically highlighting high-risk zones.

---

## 🛠️ Prerequisites & Installation

```bash
git clone https://github.com
cd Devils-Wrath
pip3 install -r requirements.txt
```

---

## 🚀 Usage Guide

```bash
python3 devils_wrath.py -t <TARGET_IP> -d <DOMAIN_NAME> -u <USERNAME> -p <PASSWORD>
```
