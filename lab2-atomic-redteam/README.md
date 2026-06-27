# Lab 2 — Detection Validation using Atomic Red Team

## Objective

Evaluate Wazuh SIEM detection coverage against the MITRE ATT&CK framework using Atomic Red Team. Identify detection gaps, engineer custom Wazuh detection rules, and validate improved coverage across Discovery, Persistence, Credential Access, Defense Evasion, and Command & Control techniques.

---

## Environment

| VM            | Role                          | OS                    | IP              |
| ------------- | ----------------------------- | --------------------- | --------------- |
| soc-core      | Wazuh Manager + Dashboard     | Ubuntu Server 22.04   | 192.168.234.138 |
| windows10-lab | Target + Wazuh Agent + Sysmon | Windows 10 Pro        | 192.168.234.140 |
| kali          | Lab Management                | Kali GNU/Linux 2026.2 | 192.168.234.129 |

![Architecture](./findings/architecture.png)

*Same virtual lab infrastructure reused from Lab 1.*

---

## Project Workflow

| Phase                     | Description                             | Status     |
| ------------------------- | --------------------------------------- | ---------- |
| 1 — Deployment            | Install and configure Atomic Red Team   | ✅ Complete |
| 2 — Attack Simulation     | Execute Atomic ATT&CK tests             | ✅ Complete |
| 3 — Coverage Assessment   | Measure native Wazuh detection coverage | ✅ Complete |
| 4 — Detection Engineering | Develop custom Wazuh rules              | ✅ Complete |
| 5 — Validation            | Re-run tests and verify detections      | ✅ Complete |
| 6 — ATT&CK Mapping        | Generate ATT&CK Navigator heatmap       | ✅ Complete |

---

# Phase 1 — Atomic Red Team Deployment

Atomic Red Team and Invoke-AtomicRedTeam were deployed on the Windows endpoint to simulate MITRE ATT&CK techniques in a controlled environment. Existing Wazuh and Sysmon telemetry from Lab 1 was reused to capture process creation, file creation, registry activity, and Windows Security events.

Configuration included:

* Invoke-AtomicRedTeam
* Sysmon v15
* SwiftOnSecurity Sysmon configuration
* Windows Audit Policy
* Wazuh Agent

![Atomic Setup](./findings/atomic-setup.png)

---

# Phase 2 — ATT&CK Technique Simulation

Ten Atomic Red Team tests were executed across five ATT&CK tactics to evaluate Wazuh's detection capability.

| ATT&CK ID | Technique                              | Tactic            |
| --------- | -------------------------------------- | ----------------- |
| T1082     | System Information Discovery           | Discovery         |
| T1016     | System Network Configuration Discovery | Discovery         |
| T1049     | System Network Connections Discovery   | Discovery         |
| T1547.001 | Registry Run Keys                      | Persistence       |
| T1053.005 | Scheduled Task Creation                | Persistence       |
| T1136.001 | Local Account Creation                 | Persistence       |
| T1055     | Process Injection                      | Defense Evasion   |
| T1070.004 | File Deletion                          | Defense Evasion   |
| T1003.001 | LSASS Memory Dump                      | Credential Access |
| T1105     | Ingress Tool Transfer                  | Command & Control |

![Atomic Tests](./findings/atomic-test-results/all-tests.png)

*Atomic Red Team executing ATT&CK simulations against the Windows endpoint.*

---

# Phase 3 — Detection Coverage Assessment

Each Atomic test was evaluated against Wazuh's native detection capability to identify visibility gaps before writing custom rules.

| ATT&CK Technique  | Native Detection | Gap                   |
| ----------------- | ---------------- | --------------------- |
| Discovery         | ✅ Complete       | None                  |
| Persistence       | ⚠️ Partial       | Custom rules required |
| Credential Access | ⚠️ Partial       | Custom rules required |
| Defense Evasion   | ⚠️ Partial       | Custom rules required |
| Command & Control | ⚠️ Partial       | Custom rules required |

![Coverage Matrix](./coverage/coverage-matrix.png)

### Coverage Summary

| Metric                    |              Value |
| ------------------------- | -----------------: |
| ATT&CK techniques tested  |                 10 |
| Detected out-of-the-box   |                  4 |
| Detection gaps identified |                  6 |
| Custom rules developed    |                  6 |
| Final validated coverage  | **10 / 10 (100%)** |

---

# Phase 4 — Detection Engineering

Six custom Wazuh rules were developed to improve ATT&CK coverage.

---

## Rule 100020 — Scheduled Task Creation

**MITRE Technique:** T1053.005

Detects suspicious scheduled task creation for persistence.

```xml
<rule id="100020">
    ...
</rule>
```

![Scheduled Task Detection](./findings/atomic-test-results/T1053-persistence.png)

---

## Rule 100021 — Process Injection

**MITRE Technique:** T1055

Detects indicators associated with process injection activity.

```xml
<rule id="100021">
    ...
</rule>
```

![Process Injection Detection](./findings/atomic-test-results/T1055-defense-evasion.png)

---

## Rule 100022 — File Deletion

**MITRE Technique:** T1070.004

Detects suspicious file deletion activity commonly used for defense evasion.

```xml
<rule id="100022">
    ...
</rule>
```

![File Deletion Detection](./findings/atomic-test-results/T1070-defense-evasion.png)

---

## Rule 100023 — LSASS Memory Dump

**MITRE Technique:** T1003.001

Detects LSASS dumping attempts using `comsvcs.dll` MiniDump.

```xml
<rule id="100023">
    ...
</rule>
```

![Credential Dump Detection](./findings/atomic-test-results/T1003-credential-access.png)

---

## Rule 100024 — Ingress Tool Transfer

**MITRE Technique:** T1105

Detects tool downloads and payload transfer activity.

```xml
<rule id="100024">
    ...
</rule>
```

![Ingress Tool Transfer Detection](./findings/atomic-test-results/T1105-command-control.png)

---

## Rule 100025 — Local Account Creation

**MITRE Technique:** T1136.001

Added Windows Audit Policy configuration to enable Event ID 4720 before creating a custom detection rule.

```xml
<rule id="100025">
    ...
</rule>
```

![Local Account Detection](./findings/atomic-test-results/T1136-persistence-security-log.png)

---

**Complete rule set:**
`detections/local_rules_lab2.xml`

---

# Phase 5 — ATT&CK Coverage Validation

After implementing the custom detection rules, every Atomic Red Team test was re-executed to validate successful detection.

| ATT&CK ID | Native Detection | Custom Rule | Final Status |
| --------- | ---------------- | ----------- | ------------ |
| T1082     | ✅                | —           | ✅            |
| T1016     | ✅                | —           | ✅            |
| T1049     | ✅                | —           | ✅            |
| T1547.001 | ✅                | —           | ✅            |
| T1053.005 | ⚠️               | Rule 100020 | ✅            |
| T1136.001 | ❌                | Rule 100025 | ✅            |
| T1055     | ⚠️               | Rule 100021 | ✅            |
| T1070.004 | ⚠️               | Rule 100022 | ✅            |
| T1003.001 | ⚠️               | Rule 100023 | ✅            |
| T1105     | ⚠️               | Rule 100024 | ✅            |

![ATT\&CK Heatmap](./coverage/attck-navigator-heatmap.svg)

*MITRE ATT&CK Navigator heatmap after validating all Atomic Red Team simulations.*

---

# Key Findings

* Increased validated ATT&CK detection coverage from **40% to 100%** through custom Wazuh detection engineering.
* Native Wazuh rules provided strong visibility into Discovery techniques but limited coverage for Persistence, Credential Access, Defense Evasion, and Command & Control.
* Enabling Windows Audit Policy generated Event ID 4720, allowing reliable detection of local account creation.
* LSASS dumping via `comsvcs.dll` MiniDump bypassed native detection but was successfully identified using a custom rule.
* Technique-specific detections significantly improved alert quality compared to relying solely on generic PowerShell detections.

---

# Repository Structure

```
lab2-atomic-redteam/
├── README.md
├── setup/
│   └── atomic-redteam-setup.md
├── coverage/
│   ├── coverage-matrix.md
│   └── attck-navigator-heatmap.svg
├── detections/
│   ├── local_rules_lab2.xml
│   └── mitre-mapping.md
├── findings/
│   ├── atomic-test-results/
│   └── investigation-notes/
└── playbooks/
    ├── persistence-response.md
    └── discovery-response.md
```

---

# Tools Used

* Atomic Red Team (Invoke-AtomicRedTeam v2.3.0)
* Wazuh SIEM v4.7.5
* Sysmon v15
* SwiftOnSecurity Sysmon Configuration
* MITRE ATT&CK Navigator
* Windows Audit Policy (`auditpol`)

---

# References

* https://atomicredteam.io/
* https://github.com/redcanaryco/invoke-atomicredteam
* https://documentation.wazuh.com/
* https://attack.mitre.org/
* https://github.com/SwiftOnSecurity/sysmon-config
