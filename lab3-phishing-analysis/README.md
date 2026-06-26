# Lab 3 — Phishing Analysis Pipeline

## Status: 🔜 In Progress

## Objective
Build an automated phishing email triage pipeline using TheHive and Cortex.
Analyze real phishing samples, extract IOCs, and document investigation workflow.

## Planned Components
| Component | Purpose | Status |
|-----------|---------|--------|
| TheHive | Case management | Planned |
| Cortex | Automated IOC enrichment | Planned |
| PhishTank | Phishing sample source | Planned |
| Any.run | Dynamic malware analysis | Planned |
| VirusTotal | Hash + URL reputation | Planned |

## Planned Workflow
```
Email received
      ↓
Header analysis (sender, SPF, DKIM, DMARC)
      ↓
URL extraction + reputation check (VirusTotal/Cortex)
      ↓
Attachment analysis (Any.run sandbox)
      ↓
IOC extraction + TheHive case creation
      ↓
Documentation
```