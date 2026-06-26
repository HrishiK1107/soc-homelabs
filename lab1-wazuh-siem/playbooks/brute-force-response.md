# Playbook — Brute Force Attack Response (T1110)

**Trigger:** Rule 100001 fires — 5+ failed logons from same source IP within 120 seconds
**Severity:** Level 12
**MITRE:** T1110 — Brute Force
**Tactic:** Credential Access

---

## Triage (First 5 Minutes)

1. Identify source IP from `agent.ip` field
2. Identify target account from `data.win.eventdata.targetUserName`
3. Check if any **Event ID 4624** (successful logon) followed the failures
4. Determine logon type — Type 3 (network) or Type 10 (remote interactive/RDP)
5. Check if source IP is internal or external

**Key Questions:**
- Did the attacker succeed? (4624 after 4625s = yes)
- Is this a known IP? (IT admin, pentest, or unknown?)
- Is the targeted account privileged?

---

## Containment

### If Attack is Ongoing
```powershell
# Block source IP via Windows Firewall (on victim machine)
netsh advfirewall firewall add rule name="Block Attacker" dir=in action=block remoteip=
```

### If Account was Compromised
```powershell
# Disable compromised account immediately
net user  /active:no

# Force password reset
net user  
```

### Isolate if Needed
- If attacker succeeded and lateral movement is suspected → isolate VM from network

---

## Investigation
□ How many failed attempts total?

□ What timeframe did the attack span?

□ Which ports targeted? (3389 = RDP, 22 = SSH, 445 = SMB)

□ Was the correct password found? (check 4624 events)

□ Any post-logon activity? (check process creation Event ID 4688/Sysmon 1)

□ Other machines targeted from same source IP?

---

## Eradication
□ Block source IP at network level

□ Disable or rename targeted account if compromised

□ Reset password — enforce complexity

□ Review and restrict RDP access (whitelist IPs if possible)

□ Enable account lockout policy (5 attempts → 30 min lockout)

---

## Recovery
□ Re-enable account after password reset

□ Verify no persistence mechanisms left (new accounts, scheduled tasks)

□ Monitor account for 24 hours post-incident

□ Confirm source IP blocked and no further attempts

---

## Lessons Learned
□ Document source IP, targeted account, timeframe

□ Was detection timely?

□ Was the rule threshold appropriate?

□ Recommend MFA on RDP if not already enabled

---

## Severity Escalation

| Condition | Action |
|-----------|--------|
| Attack ongoing, no success | Monitor + block IP |
| Attack succeeded, low-priv account | Contain + investigate |
| Attack succeeded, admin account | Escalate to L2 immediately |
| Lateral movement detected | Escalate to L2 + isolate host |