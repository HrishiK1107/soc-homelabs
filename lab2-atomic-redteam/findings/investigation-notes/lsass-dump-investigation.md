# Investigation Note — LSASS Memory Dump (T1003.001)

## Alert Details
| Field | Value |
|-------|-------|
| Rule ID | 100023 |
| Severity | Level 15 (Critical) |
| Tactic | Credential Access |
| Technique | T1003.001 — LSASS Memory |
| Host | windows10-lab |
| Time | 2026-06-27 16:21 UTC |

## What Triggered the Alert
powershell.exe & {C:\Windows\System32\rundll32.exe

C:\windows\System32\comsvcs.dll, MiniDump

(Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full}

## Attack Breakdown
- `rundll32.exe` used to call `comsvcs.dll` — a built-in Windows DLL
- `MiniDump` function called with LSASS process ID as argument
- Output written to `$env:TEMP\lsass-comsvcs.dmp`
- This is a LOLBin technique — no external tools required
- Dump file contains credential material (NTLM hashes, Kerberos tickets)

## Why This Is Dangerous
- Credentials extracted offline from dump using Mimikatz
- No external tools needed — rundll32 and comsvcs.dll are built into Windows
- Defender may not block comsvcs.dll usage
- Dump file can be exfiltrated and cracked offline

## Detection Logic
Custom rule 100023 matches on:
- `comsvcs.*MiniDump` in commandLine
- `rundll32.*comsvcs` in commandLine

## Response Steps
1. Isolate the host immediately
2. Identify what process spawned the rundll32 command
3. Check if dump file exists at `$env:TEMP\lsass-comsvcs.dmp`
4. Delete dump file if present
5. Force password reset for all accounts on the host
6. Check for lateral movement using the compromised credentials
7. Review parent process — was PowerShell launched by a suspicious parent?

## MITRE ATT&CK Reference
- T1003.001 — OS Credential Dumping: LSASS Memory
- Sub-technique of T1003 — OS Credential Dumping