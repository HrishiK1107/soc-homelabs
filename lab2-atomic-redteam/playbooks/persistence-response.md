# Incident Response Playbook — Persistence Detection

## Applicable Techniques
- T1053.005 — Scheduled Task Creation
- T1136.001 — Local Account Creation
- T1547.001 — Registry Run Keys

## Triggering Alerts
| Rule ID | Technique | Severity |
|---------|-----------|----------|
| 100020 | Scheduled Task Creation | Level 12 |
| 100025 | Local Account Creation | Level 12 |
| 92041 | Registry Run Keys | Level varies |
| 60109 | Account Creation (Event 4720) | Level 8 |

---

## Phase 1 — Detection & Triage

### Step 1 — Confirm the Alert
- Open Wazuh dashboard → Security Events
- Filter by rule ID and agent name
- Expand the alert — review `data.win.eventdata.commandLine`
- Note: timestamp, user, parent process, process ID

### Step 2 — Assess Severity
| Indicator | Severity |
|-----------|----------|
| Task runs as SYSTEM | Critical |
| Account added to Administrators group | Critical |
| Registry key in HKLM Run | High |
| Task runs as current user | Medium |
| Account created with no group | Medium |

### Step 3 — Check for Related Alerts
Search Wazuh for activity from same host in last 30 minutes:
agent.name: "windows10-lab" AND @timestamp:[now-30m TO now]
Look for: lateral movement, credential access, discovery activity before persistence

---

## Phase 2 — Containment

### Scheduled Task (T1053.005)
```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v | findstr /i "task name\|status\|run as"

# Delete malicious task
schtasks /delete /tn "SuspiciousTaskName" /f

# Verify deletion
schtasks /query /tn "SuspiciousTaskName"
```

### Local Account (T1136.001)
```powershell
# List all local users
net user

# Disable suspicious account immediately
net user "suspicious-account" /active:no

# Check group memberships
net localgroup administrators

# Remove from admins if present
net localgroup administrators "suspicious-account" /delete

# Delete account
net user "suspicious-account" /delete
```

### Registry Run Key (T1547.001)
```powershell
# List Run keys
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Delete malicious entry
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MaliciousEntry" /f
```

---

## Phase 3 — Investigation

### Determine Initial Access
1. Check parent process of persistence command in Sysmon logs
2. Filter Wazuh for events 30-60 minutes before alert
3. Look for: phishing execution, exploit, remote access tool

### Scope Assessment
- Was this an isolated test or active intrusion?
- Are there other hosts with similar alerts?
- Was the persistence mechanism executed (task triggered, account used)?

### Evidence Collection
```powershell
# Export scheduled tasks
schtasks /query /fo CSV > C:\IR\scheduled-tasks.csv

# Export local users
net user > C:\IR\local-users.txt

# Export registry run keys
reg export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\IR\run-keys-hkcu.reg
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\IR\run-keys-hklm.reg
```

---

## Phase 4 — Eradication & Recovery

1. Remove all persistence mechanisms identified
2. Reset passwords for all local accounts
3. Audit all scheduled tasks — remove unknown entries
4. Review registry Run keys — remove unknown entries
5. Restore from clean snapshot if compromise is confirmed

---

## Phase 5 — Lessons Learned

- Document the persistence technique used
- Verify custom rules fired correctly
- Update detection rules if gaps found
- Add IOCs (task names, account names, registry values) to watchlist