# Lab 1 — Wazuh SIEM + Detection Engineering

## Objective
Deploy a fully functional SIEM environment, ingest logs from Windows and Linux endpoints, simulate real-world attacks, and write custom detection rules mapped to MITRE ATT&CK.

---

## Environment

| VM | Role | OS | IP |
|----|------|----|----|
| soc-core | Wazuh Manager + Dashboard | Ubuntu Server 22.04 | 192.168.234.138 |
| windows10-lab | Victim + Wazuh Agent | Windows 10 Pro | 192.168.234.140 |
| kali | Attacker | Kali GNU/Linux 2026.2 | 192.168.234.129 |

![Architecture](./findings/architecture.png)
*Lab architecture — all VMs connected via VMware NAT network*

---

## Lab Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 — Setup | Wazuh manager + agent deployment | ✅ Complete |
| 2 — Log Ingestion | Sysmon + Windows Event Logs + Linux auth | ✅ Complete |
| 3 — Attack Simulation | Hydra, Mimikatz, PowerShell abuse | ✅ Complete |
| 4 — Detection Rules | Custom XML rules in Wazuh | ✅ Complete |
| 5 — MITRE Mapping | TTPs mapped to ATT&CK framework | ✅ Complete |

---

## Phase 1 — Setup

Deployed Wazuh all-in-one (manager + indexer + dashboard) on Ubuntu Server using the official quickstart installer. Deployed agents on Windows 10 and Kali.

![Agents Active](./findings/agents-active.png)
*Both agents active and reporting to soc-core — 100% agent coverage*

**Setup guides:**
- [Wazuh Manager Setup](./setup/wazuh-manager-setup.md)
- [Windows Agent Setup](./setup/windows-agent-setup.md)
- [Kali Agent Setup](./setup/kali-agent-setup.md)
- [Sysmon Setup](./setup/sysmon-setup.md)

---

## Phase 2 — Log Ingestion

Installed Sysmon on Windows with SwiftOnSecurity config for high-fidelity telemetry. Configured `ossec.conf` to ingest the Sysmon event channel. Verified Event ID 1 (process creation), Event ID 11 (file creation), and Linux PAM auth logs flowing into Wazuh.

**Key log sources ingested:**

| Source | Log Type | Key Event IDs |
|--------|----------|---------------|
| windows10-lab | Sysmon Operational | 1, 3, 10, 11 |
| windows10-lab | Windows Security | 4624, 4625 |
| kali | Linux auth | PAM, sudo, su |

---

## Phase 3 — Attack Simulation

Three attacks simulated from Kali against Windows10-lab and locally on Windows.

### Attack 1 — RDP Brute Force | T1110
- **Tool:** Hydra
- **Command:** `hydra -l testuser -P passwords.txt rdp://192.168.234.140`
- **Result:** Multiple Event ID 4625 (failed logon) generated
- **Detected:** Yes — rule 100001 fired

### Attack 2 — Credential Dumping Tool Drop | T1003.001
- **Tool:** Mimikatz
- **Method:** Mimikatz extracted via PowerShell to `C:\Tools\mimikatz`
- **Result:** Sysmon Event ID 11 logged file creation of `mimikatz.exe`, `mimilib.dll`, `mimispool.dll`
- **Detected:** Yes — rule 100002 fired

### Attack 3 — Suspicious PowerShell Execution | T1059.001
- **Tool:** PowerShell (native)
- **Method:** Encoded commands, download cradles, execution policy bypass flags
- **Result:** Sysmon Event ID 1 logged PowerShell process with malicious flags
- **Detected:** Yes — rule 100003 fired

![All Custom Rules Firing](./findings/all-custom-rules-firing.png)
*All 3 custom rules firing in Wazuh Discover — rule ID, MITRE technique and tactic columns visible*

---

## Phase 4 — Custom Detection Rules

Three custom Wazuh rules written in `/var/ossec/etc/rules/local_rules.xml`.

### Rule 100001 — Brute Force
```xml
<rule id="100001" level="12" frequency="5" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <same_source_ip />
  <description>Brute Force Attack Detected: Multiple failed logons from same source IP (T1110)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

![Brute Force Alert](./findings/rule-100001-brute-force.png)
*Rule 100001 firing — Event ID 4625 spike from Kali triggering brute force detection*

---

### Rule 100002 — Mimikatz File Drop
```xml
<rule id="100002" level="15">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)mimikatz</field>
  <description>Mimikatz Binary Detected: Credential dumping tool dropped on system (T1003.001)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_dumping,</group>
</rule>
```

![Mimikatz Alert](./findings/rule-100002-mimikatz.png)
*Rule 100002 firing — Sysmon Event ID 11 catching mimikatz.exe drop mapped to Lateral Tool Transfer*

---

### Rule 100003 — Suspicious PowerShell
```xml
<rule id="100003" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand|-nop|-noprofile|-windowstyle\s+hidden|downloadstring|iex|invoke-expression|bypass)</field>
  <description>Suspicious PowerShell Execution Detected: Evasion flags or download cradle observed (T1059.001)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
  <group>powershell_abuse,</group>
</rule>
```

![PowerShell Alert](./findings/rule-100003-powershell.png)
*Rule 100003 firing — Sysmon Event ID 1 catching PowerShell with encoded command and bypass flags*

→ **[Full rules file](./detections/local_rules.xml)**

---

## Phase 5 — MITRE ATT&CK Mapping

![Dashboard Overview](./findings/dashboard-overview.png)
*Wazuh Security Events dashboard — 2887 events, 103 high-severity alerts, MITRE ATT&CK wheel auto-populated*

→ **[Full MITRE mapping →](./detections/mitre-mapping.md)**

| Attack | Rule ID | MITRE Technique | Tactic | Severity |
|--------|---------|-----------------|--------|----------|
| RDP Brute Force | 100001 | T1110 | Credential Access | Level 12 |
| Mimikatz File Drop | 100002 | T1003.001 | Credential Access | Level 15 |
| PowerShell Abuse | 100003 | T1059.001 | Execution | Level 12 |

---

## Key Findings

- Wazuh caught Mimikatz **at the file drop stage** — earlier in the kill chain than lsass memory access, which is how production SOCs often first detect it
- SwiftOnSecurity Sysmon config filtered low-noise events while preserving high-fidelity process creation and file creation telemetry
- PowerShell evasion flags (`-enc`, `-nop`, `-windowstyle hidden`) reliably detected via Sysmon Event ID 1 command line inspection
- Custom rules chained off built-in Wazuh SIDs allow frequency-based correlation without rebuilding base detection logic

---

## Playbooks

| Playbook | Trigger | MITRE |
|----------|---------|-------|
| [Brute Force Response](../../playbooks/brute-force-response.md) | Rule 100001 fires | T1110 |
| [PowerShell Abuse Response](../../playbooks/powershell-abuse-response.md) | Rule 100003 fires | T1059.001 |
| [Credential Dumping Response](../../playbooks/credential-dumping-response.md) | Rule 100002 fires | T1003.001 |

---

## References
- [Wazuh Documentation](https://documentation.wazuh.com)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)