# SOC Home Lab

![Architecture](./lab1-wazuh-siem/findings/architecture.png)

A hands-on Blue Team home lab simulating real-world SOC analyst workflows — SIEM deployment, log ingestion, attack simulation, custom detection engineering, and MITRE ATT&CK mapping.

---

## 🧪 Lab Environment

| VM | Role | OS | IP |
|----|------|----|----|
| soc-core | Wazuh Manager + Dashboard | Ubuntu Server 22.04 | 192.168.234.138 |
| windows10-lab | Victim + Wazuh Agent | Windows 10 Pro | 192.168.234.140 |
| kali | Attacker | Kali GNU/Linux 2026.2 | 192.168.234.129 |

**Hypervisor:** VMware Workstation | **Host RAM:** 16GB | **Network:** NAT (192.168.234.0/24)

---

## 📁 Labs

### ✅ Lab 1 — Wazuh SIEM + Detection Engineering
Deployed Wazuh SIEM across 3 VMs, ingested Windows Event Logs and Sysmon telemetry, simulated real attacks from Kali, and wrote custom XML detection rules mapped to MITRE ATT&CK.

| Attack Simulated | Tool | Custom Rule | MITRE Technique | Tactic |
|-----------------|------|-------------|-----------------|--------|
| RDP Brute Force | Hydra | 100001 | T1110 — Brute Force | Credential Access |
| Credential Dumping Tool Drop | Mimikatz + PowerShell | 100002 | T1003.001 — LSASS Memory | Credential Access |
| Suspicious PowerShell Execution | PowerShell | 100003 | T1059.001 — PowerShell | Execution |

→ **[View Lab 1 →](./lab1-wazuh-siem/README.md)**

---

### 🔜 Lab 2 — Atomic Red Team + ATT&CK Coverage
> Planned — automated attack simulation mapped across ATT&CK matrix

### 🔜 Lab 3 — Phishing Analysis Pipeline
> Planned — TheHive + Cortex for email triage and IOC extraction

---

## 🛡️ Detection Rules

Custom Wazuh rules written for this lab:

```xml
<!-- Rule 100001 — Brute Force T1110 -->
<rule id="100001" level="12" frequency="5" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <same_source_ip />
  <description>Brute Force Attack Detected: Multiple failed logons (T1110)</description>
</rule>

<!-- Rule 100002 — Mimikatz T1003.001 -->
<rule id="100002" level="15">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)mimikatz</field>
  <description>Mimikatz Binary Detected: Credential dumping tool dropped (T1003.001)</description>
</rule>

<!-- Rule 100003 — PowerShell Abuse T1059.001 -->
<rule id="100003" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand|-nop|-noprofile|-windowstyle\s+hidden|downloadstring|iex|invoke-expression|bypass)</field>
  <description>Suspicious PowerShell Execution Detected (T1059.001)</description>
</rule>
```

→ **[Full rules file →](./lab1-wazuh-siem/detections/local_rules.xml)**

---

## 📋 SOC Playbooks

| Playbook | Trigger | MITRE |
|----------|---------|-------|
| [Brute Force Response](./playbooks/brute-force-response.md) | 5+ failed logins in 120s | T1110 |
| [PowerShell Abuse Response](./playbooks/powershell-abuse-response.md) | Evasion flags or download cradle | T1059.001 |
| [Credential Dumping Response](./playbooks/credential-dumping-response.md) | Mimikatz binary on disk | T1003.001 |

---

## 🧰 Tools & Stack

| Layer | Tool |
|-------|------|
| SIEM | Wazuh 4.7.5 |
| Windows Telemetry | Sysmon + SwiftOnSecurity config |
| Attack Simulation | Hydra, Mimikatz, Nmap, PowerShell |
| Detection Framework | MITRE ATT&CK |
| Documentation | Markdown + draw.io |

---

## 📌 Skills Demonstrated

- Wazuh SIEM deployment and multi-agent management
- Windows log ingestion pipeline (Event Logs + Sysmon + Linux auth)
- Custom Wazuh XML detection rule authoring
- Attack simulation — brute force, credential dumping, PowerShell abuse
- MITRE ATT&CK TTP mapping and documentation
- SOC investigation workflow and playbook writing