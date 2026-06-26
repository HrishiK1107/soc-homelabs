# Windows Agent Setup — Windows 10 Pro

## Prerequisites
- Windows 10 Pro VM
- Wazuh Manager running on 192.168.234.138
- PowerShell running as Administrator
- Both VMs on same VMware NAT network

---

## Step 1 — Deploy Agent via Dashboard

1. Open Wazuh Dashboard → **Agents → Deploy New Agent**
2. Select: **Windows**
3. Set Manager IP: `192.168.234.138`
4. Set Agent Name: `windows10-lab`
5. Copy the generated PowerShell command

## Step 2 — Install Agent on Windows

Open **PowerShell as Administrator** and run:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile $env:tmp\wazuh-agent.msi; msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER='192.168.234.138' WAZUH_AGENT_NAME='windows10-lab' WAZUH_REGISTRATION_SERVER='192.168.234.138'
```

## Step 3 — Start Agent
```powershell
NET START WazuhSvc
```

## Step 4 — Configure Sysmon Log Ingestion

Open `C:\Program Files (x86)\ossec-agent\ossec.conf` as Administrator.

Add before closing `</ossec_config>` tag:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart agent:
```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

## Step 5 — Verify Connection

Dashboard → **Agents** → `windows10-lab` should show **Active**.

---

## Result
Windows agent deployed, Sysmon event channel ingested, logs flowing to Wazuh manager.