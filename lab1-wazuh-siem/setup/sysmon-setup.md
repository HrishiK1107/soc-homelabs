# Sysmon Setup — Windows 10 Pro

## Why Sysmon
Default Windows Event Logs are insufficient for SOC work — too noisy, too shallow.
Sysmon adds process creation, network connections, file creation, and registry events
with full command line and hash logging.

SwiftOnSecurity config applies a battle-tested ruleset that reduces noise while
preserving high-fidelity security events.

---

## Step 1 — Create Directory
```powershell
mkdir C:\Tools\Sysmon
cd C:\Tools\Sysmon
```

## Step 2 — Download Sysmon + Config
```powershell
# Sysmon binary
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon\Sysmon.zip"
Expand-Archive "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

## Step 3 — Install
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Expected output:
Sysmon64 installed.

SysmonDrv installed.

Starting SysmonDrv.

Starting Sysmon64.

## Step 4 — Verify Running
```powershell
Get-Service sysmon64
# Status: Running
```

## Step 5 — Verify Events in Event Viewer
Event Viewer → Applications and Services Logs

→ Microsoft → Windows → Sysmon → Operational

Key Event IDs to confirm:

| Event ID | Description |
|----------|-------------|
| 1 | Process creation (with full command line) |
| 3 | Network connection |
| 11 | File created |

---

## Updating Config
```powershell
# Apply updated config without reinstalling
.\Sysmon64.exe -c sysmonconfig.xml
```

## Uninstalling
```powershell
.\Sysmon64.exe -u force
```

---

## Result
Sysmon running with SwiftOnSecurity config. High-fidelity telemetry flowing into
Wazuh via the Microsoft-Windows-Sysmon/Operational event channel.