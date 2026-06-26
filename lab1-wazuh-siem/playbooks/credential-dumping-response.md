# Playbook — Credential Dumping Response (T1003.001)

**Trigger:** Rule 100002 fires — Mimikatz binary detected on disk
**Severity:** Level 15 (Maximum)
**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory
**Tactic:** Credential Access

---

## ⚠️ This is a Critical Alert
Level 15 = maximum severity. Credential dumping tools on disk = assume breach posture.
Escalate immediately. Do not wait to investigate before containing.

---

## Triage (First 2 Minutes)

1. Confirm filename from `data.win.eventdata.targetFilename`
2. Identify who dropped it — `data.win.eventdata.image` (parent process)
3. Identify user context — `data.win.eventdata.user`
4. Check if Mimikatz was **executed** (Sysmon Event ID 1 — process creation)
5. Check if lsass was accessed (Sysmon Event ID 10 — target: lsass.exe)

**Key Questions:**
- Was it just dropped or actually executed?
- Was lsass.exe accessed? (credentials may be stolen)
- What account ran this? Admin? SYSTEM?
- Is this part of an authorized pentest?

---

## Containment — Do This First

```
□ Isolate host from network immediately
□ Do NOT reboot — memory forensics may be needed
□ Notify L2/IR team
□ Preserve disk and memory state
```

```powershell
# If Mimikatz process is still running — kill it
Get-Process mimikatz -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## Investigation
□ Was Mimikatz executed? (check Sysmon Event ID 1 for mimikatz.exe)

□ Was lsass.exe accessed? (check Sysmon Event ID 10)

□ What credentials may have been exposed?

Local admin hashes
Domain credentials (if domain-joined)
Cached credentials

□ How did attacker get to this point?
Trace back — how did they get code execution?
Check Event ID 4624 — who logged in before this?

□ Any lateral movement after? (Event ID 4624 from this host to others)

□ Any new accounts created? (Event ID 4720)

□ Any new scheduled tasks? (Event ID 4698)


---

## Eradication
□ Delete Mimikatz binary and all associated files

□ Assume all credentials on this host are compromised

□ Reset passwords for ALL accounts that were logged into this machine

□ Rotate service account credentials

□ Revoke and reissue any tokens/certificates if applicable

---

## Recovery
□ Rebuild host if execution confirmed (don't trust a compromised host)

□ If only file drop (no execution) — clean, patch, monitor

□ Force password resets for affected accounts

□ Enable Credential Guard if not already active

□ Review privileged access — enforce least privilege

---

## Severity Escalation

| Condition | Action |
|-----------|--------|
| File drop only, no execution | High — investigate, clean, monitor |
| Executed, no lsass access confirmed | Critical — escalate to L2 |
| lsass accessed, creds likely stolen | Critical — full IR response |
| Domain credentials exposed | Escalate to CISO — enterprise-wide reset |

---

## Hardening Recommendations
□ Enable Windows Credential Guard

□ Enable Protected Users security group for privileged accounts

□ Restrict debug privileges (SeDebugPrivilege)

□ Deploy EDR with lsass protection

□ Enable LSA protection: HKLM\SYSTEM\CurrentControlSet\Control\Lsa → RunAsPPL = 1