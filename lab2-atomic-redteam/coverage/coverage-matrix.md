# ATT&CK Coverage Matrix — Lab 2

## Summary
| Metric | Value |
|--------|-------|
| Techniques Tested | 10 |
| Detected OOB | 4 |
| Partial Detection | 5 |
| Missed | 1 |
| After Custom Rules | 10/10 |
| Final Coverage | 100% |

## Coverage Matrix

| ATT&CK ID | Technique | Tactic | Wazuh OOB | OOB Rule ID | Custom Rule | Final Status |
|-----------|-----------|--------|-----------|-------------|-------------|--------------|
| T1082 | System Information Discovery | Discovery | ✅ Yes | 92032 | — | Detected |
| T1016 | Network Configuration Discovery | Discovery | ✅ Yes | 92031 | — | Detected |
| T1049 | System Network Connections Discovery | Discovery | ✅ Yes | 92031 | — | Detected |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | ✅ Yes | 92041 | — | Detected |
| T1053.005 | Scheduled Task Creation | Persistence | ⚠️ Partial | 92032 | 100020 | Fixed |
| T1136.001 | Local Account Creation | Persistence | ❌ Missed | — | 100025 + auditpol | Fixed |
| T1055 | Process Injection | Defense Evasion | ⚠️ Partial | 92027 | 100021 | Fixed |
| T1070.004 | File Deletion | Defense Evasion | ⚠️ Partial | 92052 | 100022 | Fixed |
| T1003.001 | LSASS Memory Dump | Credential Access | ⚠️ Partial | 92027 | 100023 | Fixed |
| T1105 | Ingress Tool Transfer | Command & Control | ⚠️ Partial | 92027 | 100024 | Fixed |

## Detection Status Definitions
| Status | Meaning |
|--------|---------|
| ✅ Detected OOB | Wazuh fired a dedicated rule with correct tactic/technique mapping |
| ⚠️ Partial | Wazuh logged the event but only fired a generic rule (wrong tactic/technique) |
| ❌ Missed | No alert fired — complete blind spot |
| Fixed | Custom rule written and confirmed firing |

## Key Observations

### What Wazuh Catches OOB
- Discovery techniques via `net.exe`, `systeminfo.exe` — well covered by rules 92031/92032
- Registry modifications via `reg.exe` — covered by rule 92041

### What Wazuh Misses OOB
- Scheduled task creation via `schtasks` — only fires generic Execution rule
- Local account creation via `net user /add` — requires Security audit policy (auditpol) + Event ID 4720
- Process injection — only fires generic PowerShell rule, actual injection undetected
- File deletion via `cmd del` — only fires generic Execution rule
- LSASS dump via `comsvcs.dll MiniDump` — only fires generic PowerShell rule
- PowerShell download cradles — only fires generic PowerShell rule

### Root Cause of Gaps
Wazuh OOB rules focus on process execution (Sysmon Event ID 1) but lack
specific command line pattern matching for many ATT&CK techniques.
Custom rules using PCRE2 regex on `win.eventdata.commandLine` close these gaps.