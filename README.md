# SOC Home Lab

A hands-on Blue Team home lab built to simulate real-world SOC analyst workflows — log ingestion, attack simulation, custom detection engineering, and MITRE ATT&CK mapping.

Built on VMware with Wazuh SIEM, Sysmon, and Kali Linux.

---

## Lab Environment

| VM | Role | OS | IP |
|----|------|----|----|
| soc-core | Wazuh Manager + Dashboard | Ubuntu Server 22.04 | 192.168.234.138 |
| windows10-lab | Victim + Wazuh Agent | Windows 10 Pro | 192.168.234.140 |
| kali | Attacker | Kali GNU/Linux 2026.2 | 192.168.234.129 |

---

## Labs

### ✅ Lab 1 — Wazuh SIEM + Detection Engineering
> Deployed Wazuh SIEM, ingested logs from Windows and Kali, simulated 3 real attacks, wrote custom XML detection rules mapped to MITRE ATT&CK.

| Attack | Tool | Rule ID | MITRE | Tactic |
|--------|------|---------|-------|--------|
| RDP Brute Force | Hydra | 100001 | T1110 | Credential Access |
| Mimikatz File Drop | PowerShell | 100002 | T1003.001 | Credential Access |
| Suspicious PowerShell | PowerShell | 100003 | T1059.001 | Execution |

→ [View Lab 1](./lab1-wazuh-siem/README.md)

---

### 🔜 Lab 2 — Atomic Red Team + ATT&CK Coverage
> Coming soon

### 🔜 Lab 3 — Phishing Analysis Pipeline
> Coming soon

---

## Detection Rules

All custom Wazuh rules: [`lab1-wazuh-siem/detections/local_rules.xml`](./lab1-wazuh-siem/detections/local_rules.xml)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wazuh 4.7.5 | SIEM + EDR |
| Sysmon + SwiftOnSecurity config | Windows telemetry |
| Hydra | Brute force simulation |
| Mimikatz | Credential dumping simulation |
| Nmap | Network reconnaissance |
| MITRE ATT&CK | Detection mapping framework |

---

## Skills Demonstrated

- SIEM deployment and agent management
- Log ingestion pipeline (Windows Event Logs + Sysmon + Linux auth logs)
- Custom Wazuh XML detection rule writing
- Attack simulation (brute force, credential dumping, PowerShell abuse)
- MITRE ATT&CK TTP mapping
- SOC investigation documentation