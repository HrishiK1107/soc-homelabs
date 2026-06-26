# Playbook — Suspicious PowerShell Execution Response (T1059.001)

**Trigger:** Rule 100003 fires — PowerShell launched with evasion flags or download cradle
**Severity:** Level 12
**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Tactic:** Execution

---

## Triage (First 5 Minutes)

1. Get full command line from `data.win.eventdata.commandLine`
2. Identify parent process from `data.win.eventdata.parentImage`
3. Identify user context from `data.win.eventdata.user`
4. Check process hash against VirusTotal
5. Determine if outbound network connection followed (Sysmon Event ID 3)

**Key Questions:**
- What flags were used? (`-enc` = encoded, `-nop` = no profile, `-bypass` = policy bypass)
- Was there a download? (`DownloadString`, `DownloadFile`, `IEX`)
- What was the parent process? (Word/Excel spawning PS = high severity)
- Did it make a network connection?

---

## Decode Encoded Commands

If `-enc` or `-EncodedCommand` flag present:

```powershell
# Decode base64 encoded command
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(''))
```

Always decode before determining severity.

---

## Containment

### If Active Execution
```powershell
# Kill suspicious PowerShell process
Stop-Process -Id  -Force
```

### If Download Cradle Detected
□ Block destination URL/IP at firewall immediately

□ Check if payload was written to disk (Sysmon Event ID 11)

□ Check if payload executed (Sysmon Event ID 1 — child process)

### If Malware Suspected
□ Isolate host from network

□ Do not reboot — preserve memory artifacts

□ Escalate to L2

---

## Investigation
□ Decode full command — what was it trying to do?

□ Parent process — how was PowerShell launched?

□ Network connections made? (Event ID 3)

□ Files created? (Event ID 11)

□ Child processes spawned? (Event ID 1)

□ Registry modifications? (Event ID 13)

□ Was this user expected to run PowerShell?

---

## Eradication
□ Delete any files dropped by the script

□ Remove scheduled tasks or registry run keys created

□ Scan host with AV/EDR

□ Check for persistence mechanisms

---

## Recovery
□ Verify malicious process terminated

□ Confirm no persistence remains

□ Monitor host for 24 hours

□ Re-enable any disabled services if false positive confirmed

---

## Common Parent Processes — Severity Guide

| Parent Process | Severity | Likely Scenario |
|----------------|----------|-----------------|
| cmd.exe | Medium | Script or manual execution |
| explorer.exe | Medium | User-initiated |
| winword.exe / excel.exe | Critical | Macro-based malware |
| wscript.exe / cscript.exe | High | Script-based dropper |
| mshta.exe | Critical | Living-off-the-land attack |
| svchost.exe | Critical | Fileless malware |

---

## Severity Escalation

| Condition | Action |
|-----------|--------|
| Evasion flags only, no network | Investigate — likely FP or red team |
| Download cradle, no execution | Contain + investigate |
| Payload downloaded and executed | Escalate to L2 immediately |
| Office app as parent process | Critical — escalate + isolate |