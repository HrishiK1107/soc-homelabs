# Investigation Notes — RDP Brute Force (T1110)

**Date:** 2026-06-26
**Analyst:** Hrishi
**Rule Fired:** 100001 — Level 12
**MITRE:** T1110 — Brute Force → Credential Access

---

## Timeline

| Time | Event | Event ID | Source |
|------|-------|----------|--------|
| 20:27:32 | Hydra brute force started from Kali | — | Kali |
| 20:27:33 | Failed logon attempt 1 — testuser | 4625 | windows10-lab |
| 20:27:34 | Failed logon attempt 2 — testuser | 4625 | windows10-lab |
| 20:27:35 | Failed logon attempts 3-5 — testuser | 4625 | windows10-lab |
| 20:27:35 | Rule 100001 fired — brute force threshold reached | — | Wazuh |
| 20:27:58 | Hydra found valid credentials — Password123 | 4624 | windows10-lab |

---

## Findings

**Source IP:** 192.168.234.129 (kali)
**Target IP:** 192.168.234.140 (windows10-lab)
**Target Account:** testuser
**Port Targeted:** 3389 (RDP)
**Tool Used:** Hydra v9.7
**Attack Duration:** ~26 seconds
**Total Attempts:** 5 failed + 1 success
**Outcome:** Valid credentials found — `testuser:Password123`

---

## Alert Analysis

Rule 100001 fired after 5 failed Event ID 4625 within 120 seconds from same source IP.
Wazuh auto-mapped to MITRE T1110 — Brute Force under Credential Access tactic.

A subsequent Event ID 4624 (logon success) confirmed the attacker found valid credentials.
Logon Type 3 (network logon) confirms RDP-based access.

---

## Detection Verdict

**True Positive** — Confirmed brute force attack from Kali against Windows RDP.

---

## Recommendations

- Enable account lockout policy (5 attempts → 30 min lockout)
- Restrict RDP access to specific IPs via firewall
- Enforce strong password policy — Password123 is trivially guessable
- Consider MFA on RDP