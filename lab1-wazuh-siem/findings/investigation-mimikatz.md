# Investigation Notes — Mimikatz Credential Dumping Tool (T1003.001)

**Date:** 2026-06-26
**Analyst:** Hrishi
**Rule Fired:** 100002 — Level 15
**MITRE:** T1003.001 — LSASS Memory → Credential Access

---

## Timeline

| Time | Event | Event ID | Source |
|------|-------|----------|--------|
| 17:50:56 | PowerShell began extracting Mimikatz archive | 1 | windows10-lab |
| 17:50:56 | mimikatz.exe created in C:\Tools\mimikatz\Win32 | 11 | windows10-lab |
| 17:50:57 | mimilib.dll created in C:\Tools\mimikatz\x64 | 11 | windows10-lab |
| 17:50:57 | mimispool.dll created in C:\Tools\mimikatz\x64 | 11 | windows10-lab |
| 17:50:57 | mimikatz.exe created in C:\Tools\mimikatz\x64 | 11 | windows10-lab |
| 17:50:57 | Rule 100002 fired — Mimikatz binary detected | — | Wazuh |
| 17:52:16 | Executable dropped in Windows root folder | 11 | windows10-lab |

---

## Findings

**Host:** windows10-lab (192.168.234.140)
**User Context:** NT AUTHORITY / local admin
**Files Detected:**
C:\Tools\mimikatz\Win32\mimikatz.exe

C:\Tools\mimikatz\Win32\mimilib.dll

C:\Tools\mimikatz\x64\mimikatz.exe

C:\Tools\mimikatz\x64\mimilib.dll

C:\Tools\mimikatz\x64\mimispool.dll
**Parent Process:** PowerShell (Invoke-WebRequest + Expand-Archive)
**Execution Confirmed:** Yes — mimikatz.exe launched, privilege::debug ran

---

## Alert Analysis

Rule 100002 fired on Sysmon Event ID 11 matching filename pattern `(?i)mimikatz`.
Detection occurred at **file drop stage** — before execution.

Wazuh auto-mapped to:
- MITRE Technique: Lateral Tool Transfer
- Tactic: Lateral Movement

Note: Detection at file drop is earlier in the kill chain than lsass memory access
(Event ID 10). This is the preferred detection point in production environments —
stopping the tool before it runs is better than detecting it mid-execution.

---

## Detection Verdict

**True Positive** — Mimikatz binaries confirmed on disk, execution confirmed.

---

## Recommendations

- Enable Windows Defender Credential Guard
- Set LSA protection: `RunAsPPL = 1` in registry
- Restrict PowerShell execution policy
- Monitor C:\Tools and user writeable directories for executable drops
- Enforce application whitelisting