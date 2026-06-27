# Investigation Note — Persistence Techniques (T1053.005 + T1136.001)

## Alert 1 — Scheduled Task Creation (T1053.005)

### Alert Details
| Field | Value |
|-------|-------|
| Rule ID | 100020 |
| Severity | Level 12 |
| Tactic | Persistence |
| Technique | T1053.005 — Scheduled Task |
| Host | windows10-lab |
| Time | 2026-06-27 17:37 UTC |

### What Triggered the Alert
cmd.exe /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon

/tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup"

/sc onstart /ru system /tr "cmd.exe /c calc.exe"

### Attack Breakdown
- Two scheduled tasks created — one triggered on logon, one on startup
- Both run as SYSTEM — high privilege persistence
- Payload is `calc.exe` (simulated — real attackers use malware)
- Tasks survive reboot — persistent across system restarts

### Response Steps
1. List all scheduled tasks — `schtasks /query /fo LIST /v`
2. Identify suspicious tasks — unusual names, SYSTEM privileges, odd triggers
3. Delete malicious tasks — `schtasks /delete /tn "TaskName" /f`
4. Check who created the task — review parent process in Sysmon logs
5. Determine initial access vector

---

## Alert 2 — Local Account Creation (T1136.001)

### Alert Details
| Field | Value |
|-------|-------|
| Rule ID | 100025 / 60109 |
| Severity | Level 12 |
| Tactic | Persistence |
| Technique | T1136.001 — Local Account |
| Host | windows10-lab |
| Time | 2026-06-27 17:45 UTC |

### What Triggered the Alert
cmd.exe /c net user /add "T1136.001_CMD" "T1136.001_CMD!"
Security Event ID 4720 also captured — `samAccountName: T1136.001_CMD`

### Attack Breakdown
- New local user account created via `net user /add`
- Account can be used for persistent access even if primary account is disabled
- Attacker can RDP or use the account for lateral movement
- Double detection — Sysmon process event + Windows Security audit log

### Detection Note
This technique required:
1. Custom Sysmon rule (100025) — catches `net user /add` process execution
2. Windows audit policy fix — `auditpol /set /subcategory:"User Account Management"`
3. Event ID 4720 — Windows Security log captures actual account creation

### Response Steps
1. Identify the new account — `net user`
2. Disable immediately — `net user "username" /active:no`
3. Delete the account — `net user "username" /delete`
4. Check if account was added to any groups — `net localgroup administrators`
5. Review who created the account and from which process
6. Check for RDP or remote login attempts using the new account

## MITRE ATT&CK References
- T1053.005 — Scheduled Task/Job: Scheduled Task
- T1136.001 — Create Account: Local Account