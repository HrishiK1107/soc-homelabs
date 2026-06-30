# Playbook — Phishing Triage Response Playbook

**Trigger:** New phishing case created in TheHive (manual analyst submission
or future automated alert/email-gateway integration)

**MITRE ATT&CK:** T1566 (Phishing), T1071.003 (Application Layer Protocol —
Mail)

---

## 1. Initial Triage

- [ ] Confirm the email is genuinely suspicious before deep analysis — check
      sender domain, subject line urgency/fear language, and presence of
      links or attachments
- [ ] Create a TheHive case immediately, even before full analysis —
      severity and tags can be updated later, but the case should exist as
      soon as triage begins
- [ ] Assign initial severity based on payload type as a starting point,
      to be refined after analysis:

| Indicator | Initial Severity |
|-----------|------------------|
| Attachment present (any type) | High |
| Link to credential-harvesting page | Medium |
| Link to financial/crypto action (wallet connect, payment) | High |
| Text-only, social-engineering ask (reply, call, wire transfer) | Low–Medium |

---

## 2. Header Analysis

- [ ] Extract and review the full `Received:` chain — identify the true
      originating IP vs. relay/forwarding hops
- [ ] Check sender authentication: SPF, DKIM, DMARC results if present in
      headers
- [ ] Identify Reply-To address — if different from the From address, this
      is almost always attacker-controlled and a high-confidence IOC
- [ ] Note the Return-Path — useful for tracking but often auto-generated
      infrastructure rather than something the attacker actively monitors;
      do not over-weight this as an IOC by itself
- [ ] Check for X-Mailer or other tooling fingerprints that reveal how the
      email was sent (legitimate ESP, spoofed header, scripted tool, etc.)

---

## 3. IOC Extraction

For every IOC identified, classify before adding to TheHive observables:

- [ ] **Attacker-controlled infrastructure** (typosquatted domains, drainer/
      phishing landing pages, attacker Reply-To addresses) → flag as IOC
- [ ] **Abused legitimate infrastructure** (ESP sending IPs like Mailgun/
      SendGrid, Google SMTP relays, legitimate but compromised mail relays)
      → do NOT flag as IOC at the infrastructure level; instead flag the
      specific abused account/subdomain if identifiable
- [ ] **Auto-generated artifacts** (bounce/Return-Path addresses) → usually
      not a meaningful IOC on their own; include for completeness but leave
      unflagged unless directly tied to the attacker

This distinction matters: flagging shared legitimate infrastructure as
malicious produces false positives and undermines IOC list credibility for
downstream blocking/correlation.

---

## 4. Case Documentation

- [ ] Set case title following the pattern: `Phishing Analysis — [Campaign
      Type] (sample-ID or short identifier)`
- [ ] Tag appropriately: always include `phishing`, plus campaign-specific
      tags (`credential-harvesting`, `malware-attachment`, `crypto-scam`,
      `419-fraud`, `brand-impersonation`)
- [ ] Write a 3–5 sentence description covering: what's impersonated, the
      ask (click/open/reply/wire), and a verdict
- [ ] If attachment present, upload as a **file observable** (not just
      filename) to enable Cortex file analysis
- [ ] Set TLP/PAP per organizational policy — TLP:AMBER is a reasonable
      default for internally-handled phishing triage

---

## 5. Campaign Correlation

- [ ] Before closing a case, check the IOC list against open/recent cases
      for overlap (shared domains, reused Reply-To addresses, similar
      subject-line patterns)
- [ ] If correlation is found, use TheHive's **Linked elements** feature to
      cross-reference cases — do **not** merge cases. Each email is a
      distinct analyzed artifact; merging destroys that record. Linking
      preserves both while documenting the relationship
- [ ] Note the correlation explicitly in both cases' descriptions, not just
      the link itself, so the reasoning is visible without cross-referencing

---

## 6. Cortex Enrichment (where available)

- [ ] Prioritize enrichment on the highest-value IOCs only — primary
      sending IP, malicious landing domain/URL, and any attachment hash.
      Avoid running analyzers against every observable indiscriminately,
      especially incidental/legitimate infrastructure
- [ ] Document analyzer results in the case (verdict, detection ratio if
      using VirusTotal-equivalent)
- [ ] Be aware that submitting files/URLs to third-party analyzers (e.g.
      VirusTotal) may make them publicly visible — avoid this for anything
      containing sensitive internal data

---

## 7. Detection Gap Check

- [ ] If the phishing vector involves any non-email-native delivery
      mechanism (e.g. an unusual port, a test mail relay, a novel C2
      channel), check whether existing SIEM rules would catch it
- [ ] If no detection exists, document the gap and author a custom rule
      rather than treating the case as closed once analysis is done —
      detection coverage matters as much as IOC documentation
- [ ] Validate any new rule by replaying the relevant traffic/technique and
      confirming the alert fires before considering the gap closed

---

## 8. Closeout

- [ ] Set final verdict (Safe / Suspicious / Malicious) at the case or
      observable level
- [ ] Confirm severity reflects final analysis, not just initial triage
      guess
- [ ] Close the case status once analysis, IOC documentation, and any
      detection follow-up are complete

---

## Reference: Lab 3 Case Examples

| Sample | Vector | Severity | Correlation |
|--------|--------|----------|-------------|
| sample-1000 | Malicious PDF attachment | High | — |
| sample-1001 | Credential harvesting | Medium | Linked to sample-1002 |
| sample-1002 | Credential harvesting (rotated infra) | Medium | Linked to sample-1001 |
| sample-1003 | Crypto wallet drainer | High | — |
| sample-1004 | Social-engineering fraud, no payload | Low | — |
| Simulated attack | Network relay simulation | Low | Detection gap → rule 100026 authored |

---

## References
- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1071.003 — Mail Protocols](https://attack.mitre.org/techniques/T1071/003/)
- [TheHive Documentation](https://docs.strangebee.com/thehive/)
- [Cortex Documentation](https://docs.strangebee.com/cortex/)