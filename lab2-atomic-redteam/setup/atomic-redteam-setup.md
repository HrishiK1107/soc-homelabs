# Atomic Red Team — Setup Guide

## Prerequisites
- Windows 10 VM with Sysmon + Wazuh Agent installed (from Lab 1)
- PowerShell 5.1+
- Internet access from Windows VM
- VMware snapshot taken before installation

## Installation Steps

### Step 1 — Set Execution Policy
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
```

### Step 2 — Install Required Modules
```powershell
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
```

### Step 3 — Import Module
```powershell
Import-Module invoke-atomicredteam
```

### Step 4 — Install Atomics Folder
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```
Atomics install to `C:\AtomicRedTeam\atomics\` (~500MB)

### Step 5 — Verify Installation
```powershell
Invoke-AtomicTest T1082 -TestNumbers 1 -ShowDetails
```
Expected output: technique details printed, no execution

## Execution Pattern
```powershell
# Show details before running
Invoke-AtomicTest T1053.005 -TestNumbers 1 -ShowDetails

# Run test
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Cleanup after test
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

## Notes
- Always run PowerShell as Administrator
- Take VM snapshot before installing
- Some techniques blocked by Windows Defender (ProcDump, certutil) — use alternative test numbers
- Run cleanup after each technique before proceeding to next
- Enable audit policy for account creation detection:
```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```