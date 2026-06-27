# Incident Response Playbook — Discovery Detection

## Applicable Techniques
- T1082 — System Information Discovery
- T1016 — Network Configuration Discovery
- T1049 — System Network Connections Discovery

## Triggering Alerts
| Rule ID | Technique | Severity |
|---------|-----------|----------|
| 92032 | System Information Discovery | Level varies |
| 92031 | Network Configuration/Connections Discovery | Level varies |

---

## Phase 1 — Detection & Triage

### Step 1 — Confirm the Alert
- Open Wazuh → Security Events
- Filter: `agent.name: "windows10-lab" AND rule.id: 92031`
- Review commandLine — what exactly was run?
- Note: user context, parent process, time

### Step 2 — Assess Context
Discovery alone is not always malicious. Assess:

| Indicator | Assessment |
|-----------|------------|
| Run by SYSTEM or service account | Suspicious |
| Run by admin during business hours | Likely legitimate |
| Multiple discovery commands in sequence | High suspicion |
| Followed by lateral movement or C2 | Confirmed attack |
| Run from temp directory | Malicious |
| Parent process is cmd.exe or powershell.exe | Investigate further |

### Step 3 — Check for Discovery Chain
Attackers typically run multiple discovery commands in sequence.
Search for discovery activity in a 10-minute window:
agent.name: "windows10-lab" AND (rule.id: 92031 OR rule.id: 92032) AND @timestamp:[now-10m TO now]
Three or more hits in sequence = active reconnaissance

---

## Phase 2 — Containment

### If Active Intrusion Confirmed
1. Isolate the host from network immediately
2. Preserve memory if possible before shutdown
3. Do not reboot — volatile evidence will be lost

### If Uncertain
1. Increase monitoring on the host
2. Enable full command line logging
3. Watch for follow-on activity (lateral movement, C2 beaconing)

---

## Phase 3 — Investigation

### Key Questions
1. What user ran the discovery commands?
2. What process spawned the discovery commands?
3. Was this part of a legitimate admin task?
4. What happened immediately after discovery?

### Sysmon Queries in Wazuh
Find parent process of discovery command
agent.name: "windows10-lab" AND data.win.eventdata.commandLine: systeminfo
Check what ran before and after
agent.name: "windows10-lab" AND data.win.eventdata.user: suspicious-user

### Evidence to Collect
- Full Sysmon Event ID 1 logs for the discovery window
- Network connections around the same time (Sysmon Event ID 3)
- Any file creation events (Sysmon Event ID 11)

---

## Phase 4 — Eradication & Recovery

- If legitimate: whitelist the process/user combination
- If malicious: full IR process — isolate, investigate, restore
- Update Wazuh rules to reduce false positives for known admin tools

---

## Phase 5 — Lessons Learned

- Discovery is an early-stage indicator — correlate with other tactics
- Single discovery command = low priority
- Discovery chain (3+ commands) = high priority escalation
- Document which discovery tools are used legitimately in your environment