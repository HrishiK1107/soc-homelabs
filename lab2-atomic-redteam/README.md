# Lab 2 — Atomic Red Team + ATT&CK Coverage

## Status: ✅ Complete

## Objective
Use Atomic Red Team to systematically simulate 10 MITRE ATT&CK techniques,
measure Wazuh SIEM detection coverage, identify gaps, and write custom detection
rules to achieve full coverage across Credential Access, Persistence, Discovery,
Defense Evasion, and Command & Control tactics.

## Environment
- **Wazuh SIEM** — soc-core (Ubuntu 22.04)
- **Windows Victim** — windows10-lab (Windows 10, Sysmon + Wazuh agent)
- **Attacker** — Kali Linux (Lab 1 setup)
- **Framework** — Atomic Red Team v2.3.0 (Invoke-AtomicRedTeam)

## Techniques Tested

| ATT&CK ID | Technique | Tactic | Wazuh OOB | Custom Rule | Final Status |
|-----------|-----------|--------|-----------|-------------|--------------|
| T1082 | System Information Discovery | Discovery | ✅ Rule 92032 | — | Detected |
| T1016 | System Network Configuration Discovery | Discovery | ✅ Rule 92031 | — | Detected |
| T1049 | System Network Connections Discovery | Discovery | ✅ Rule 92031 | — | Detected |
| T1547.001 | Registry Run Keys | Persistence | ✅ Rule 92041 | — | Detected |
| T1053.005 | Scheduled Task Creation | Persistence | ⚠️ Partial | ✅ Rule 100020 | Fixed |
| T1136.001 | Local Account Creation | Persistence | ❌ Missed | ✅ Rule 100025 + auditpol | Fixed |
| T1055 | Process Injection | Defense Evasion | ⚠️ Partial | ✅ Rule 100021 | Fixed |
| T1070.004 | File Deletion | Defense Evasion | ⚠️ Partial | ✅ Rule 100022 | Fixed |
| T1003.001 | LSASS Memory Dump | Credential Access | ⚠️ Partial | ✅ Rule 100023 | Fixed |
| T1105 | Ingress Tool Transfer | Command & Control | ⚠️ Partial | ✅ Rule 100024 | Fixed |

## Results Summary
- **Techniques tested:** 10
- **Detected out of the box:** 4 (40%)
- **Gaps identified:** 6
- **Custom rules written:** 6 (Rule IDs 100020–100025)
- **Final coverage:** 10/10 (100%)

## Key Findings
1. Wazuh OOB rules cover Discovery techniques well via net.exe and systeminfo
2. Persistence techniques (scheduled tasks, local accounts) required custom rules
3. T1136.001 required Windows Security audit policy fix (`auditpol`) to enable Event ID 4720
4. Defense Evasion and C2 techniques only triggered generic PowerShell rules — not technique-specific
5. T1003.001 via comsvcs.dll MiniDump bypassed OOB LSASS detection rules

## Repository Structure
lab2-atomic-redteam/

├── README.md

├── setup/

│   └── atomic-redteam-setup.md

├── coverage/

│   ├── coverage-matrix.md

│   └── attck-navigator-heatmap.svg

├── detections/

│   ├── local_rules_lab2.xml

│   └── mitre-mapping.md

├── findings/

│   ├── atomic-test-results/      ← screenshots per technique

│   └── investigation-notes/

└── playbooks/

├── persistence-response.md

└── discovery-response.md

## Tools Used
- Atomic Red Team (Red Canary) — `Invoke-AtomicRedTeam` v2.3.0
- Wazuh SIEM v4.7.5
- Sysmon v15 with SwiftOnSecurity config
- MITRE ATT&CK Navigator (heatmap export)
- Windows Audit Policy (`auditpol`) for Security event logging