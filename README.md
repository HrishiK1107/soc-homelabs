# SOC Home Lab

![Architecture](./lab1-wazuh-siem/findings/architecture.png)

A hands-on Blue Team home lab built to simulate real-world SOC analyst
workflows end-to-end — SIEM deployment, detection engineering, structured
ATT&CK coverage testing, and phishing triage with full incident case
management. Every detection rule in this repo was authored, tested, and
validated against a live attack, not copy-pasted from a ruleset.

**3 labs · 10 custom detection rules · 16 phishing/attack samples analyzed
· 10/10 MITRE ATT&CK technique coverage**

---

## 🧪 Lab Environment

| VM | Role | OS | IP |
|----|------|----|----|
| soc-core | Wazuh Manager + TheHive + Cortex | Ubuntu Server 22.04 | 192.168.234.141 |
| windows10-lab | Victim + Wazuh Agent | Windows 10 Pro | 192.168.234.140 |
| kali | Attacker | Kali GNU/Linux 2026.2 | 192.168.234.129 |

**Hypervisor:** VMware Workstation | **Host RAM:** 16GB | **Network:** NAT (192.168.234.0/24)

---

## 📁 Labs

### ✅ Lab 1 — Wazuh SIEM + Detection Engineering
Deployed Wazuh SIEM across 3 VMs, ingested Windows Event Logs and Sysmon
telemetry, simulated real attacks from Kali, and wrote custom XML detection
rules mapped to MITRE ATT&CK.

| Attack Simulated | Tool | Custom Rule | MITRE Technique | Tactic |
|-----------------|------|-------------|-----------------|--------|
| RDP Brute Force | Hydra | 100001 | T1110 — Brute Force | Credential Access |
| Credential Dumping Tool Drop | Mimikatz + PowerShell | 100002 | T1003.001 — LSASS Memory | Credential Access |
| Suspicious PowerShell Execution | PowerShell | 100003 | T1059.001 — PowerShell | Execution |

→ **[View Lab 1 →](./lab1-wazuh-siem/README.md)**

---

### ✅ Lab 2 — Atomic Red Team + ATT&CK Coverage
Systematically tested Wazuh's detection coverage across 10 MITRE ATT&CK
techniques using Atomic Red Team, spanning Discovery, Persistence, Defense
Evasion, Credential Access, and Command & Control. Identified 6 out-of-the-box
detection gaps, built an ATT&CK Navigator coverage heatmap, and authored
custom rules to close every gap — **10/10 final coverage.**

| ATT&CK ID | Technique | Tactic | OOB Coverage | Custom Rule |
|-----------|-----------|--------|--------------|-------------|
| T1082 / T1016 / T1049 | Discovery (system/network info) | Discovery | ✅ Detected | — |
| T1547.001 | Registry Run Keys | Persistence | ✅ Detected | — |
| T1053.005 | Scheduled Task Creation | Persistence | ⚠️ Partial | 100020 |
| T1136.001 | Local Account Creation | Persistence | ❌ Missed | 100025 |
| T1055 | Process Injection | Defense Evasion | ⚠️ Partial | 100021 |
| T1070.004 | File Deletion | Defense Evasion | ⚠️ Partial | 100022 |
| T1003.001 | LSASS Memory Dump | Credential Access | ⚠️ Partial | 100023 |
| T1105 | Ingress Tool Transfer | Command & Control | ⚠️ Partial | 100024 |

→ **[View Lab 2 →](./lab2-atomic-redteam/README.md)**

---

### ✅ Lab 3 — Phishing Analysis Pipeline
Deployed TheHive + Cortex for full phishing case management, analyzed 5
real-world phishing samples across distinct attack types (credential
harvesting, malware delivery, crypto drainers, advance-fee fraud), and
closed the loop by simulating a phishing delivery attempt and catching it
with a custom Wazuh rule — validating detection coverage end-to-end, not
just analyzing static samples.

| Sample | Campaign | Severity | Custom Rule |
|--------|----------|----------|-------------|
| sample-1000 | Brazilian IRPF tax phishing (malicious PDF) | High | — |
| sample-1001/1002 | Microsoft account spoofing (2-wave campaign, linked cases) | Medium | — |
| sample-1003 | Crypto drainer (CoinDesk impersonation) | High | — |
| sample-1004 | 419 advance fee fraud | Low | — |
| Simulated attack | swaks → custom SMTP listener | Low | 100026 (T1071.003) |

→ **[View Lab 3 →](./lab3-phishing-analysis/README.md)**

---

## 🛡️ Detection Rules

10 custom Wazuh rules authored across 3 labs, every one confirmed firing
against a live simulated or real-world artifact before being committed.

| Rule ID | Lab | Detection | MITRE Technique |
|---------|-----|-----------|------------------|
| 100001 | 1 | Brute Force (5+ failed logons, same source IP) | T1110 |
| 100002 | 1 | Mimikatz binary dropped to disk | T1003.001 |
| 100003 | 1 | Suspicious PowerShell (evasion flags / download cradle) | T1059.001 |
| 100020 | 2 | Scheduled task creation via CLI | T1053.005 |
| 100021 | 2 | Process injection (mavinject / CreateRemoteThread) | T1055 |
| 100022 | 2 | File deletion / indicator removal | T1070.004 |
| 100023 | 2 | LSASS memory dump via comsvcs.dll | T1003.001 |
| 100024 | 2 | Ingress tool transfer via PowerShell download cradle | T1105 |
| 100025 | 2 | Local account creation via net user | T1136.001 |
| 100026 | 3 | Inbound connection on non-standard SMTP port (phishing relay) | T1071.003 |

→ **[Lab 1 rules](./lab1-wazuh-siem/detections/local_rules.xml)** ·
**[Lab 2 rules](./lab2-atomic-redteam/detections/local_rules_lab2.xml)** ·
**[Lab 3 rules](./lab3-phishing-analysis/detections/local_rules_lab3.xml)**

---

## 📋 SOC Playbooks

| Playbook | Trigger | MITRE |
|----------|---------|-------|
| [Brute Force Response](./playbooks/brute-force-response.md) | 5+ failed logins in 120s | T1110 |
| [PowerShell Abuse Response](./playbooks/powershell-abuse-response.md) | Evasion flags or download cradle | T1059.001 |
| [Credential Dumping Response](./playbooks/credential-dumping-response.md) | Mimikatz binary on disk | T1003.001 |
| [Discovery Response](./lab2-atomic-redteam/playbooks/discovery-response.md) | Discovery technique detected | T1082, T1016, T1049 |
| [Persistence Response](./lab2-atomic-redteam/playbooks/persistence-response.md) | Persistence technique detected | T1053.005, T1136.001, T1547.001 |
| [Phishing Triage Response](./lab3-phishing-analysis/playbooks/phishing-triage-response.md) | New phishing case in TheHive | T1566, T1071.003 |

---

## 🧰 Tools & Stack

| Layer | Tool |
|-------|------|
| SIEM | Wazuh 4.7.5 |
| Case Management / Triage | TheHive 5.7.3, Cortex 3.1.8 |
| Windows Telemetry | Sysmon + SwiftOnSecurity config |
| Attack Simulation | Hydra, Mimikatz, Nmap, PowerShell, Atomic Red Team |
| Phishing Simulation | swaks, custom Python SMTP capture (aiosmtpd) |
| Detection Framework | MITRE ATT&CK, ATT&CK Navigator |
| Documentation | Markdown + draw.io |

---

## 📌 Skills Demonstrated

- Wazuh SIEM deployment and multi-agent management across Windows and Linux
- Windows log ingestion pipeline (Event Logs + Sysmon + Linux auth)
- Custom Wazuh XML detection rule authoring — 10 rules, all MITRE-mapped
  and validated against live test traffic
- Structured ATT&CK coverage testing using Atomic Red Team, including gap
  identification and closure (not just ad-hoc attack simulation)
- Phishing triage and case management using TheHive + Cortex, including
  IOC extraction, observable classification, and campaign correlation
- Email header forensics — Received-chain analysis, sender authentication
  review, Reply-To/Return-Path attribution
- End-to-end detection validation — simulating an attack and confirming
  SIEM coverage, rather than only analyzing pre-existing samples
- SOC investigation workflow and playbook writing

---

## 🔗 Other Work

- **TryHackMe:** LEGEND rank (Top 1%), 225-day streak, 220+ rooms completed
- **CTF writeups:** OverTheWire (Bandit/Leviathan/Krypton/Natas — complete), picoCTF, TryHackMe
- **Research:** *Are Real-World SBOMs Ready for the EU Cyber Resilience Act?* — empirical study of 5,000 SBOMs ([repo](https://github.com/HrishiK1107/sbom-cra-readiness-study))

---
