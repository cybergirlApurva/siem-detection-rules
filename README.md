# siem-detection-rules

Production-grade KQL detection rules for **Azure Sentinel / Microsoft Sentinel**, mapped to [MITRE ATT&CK](https://attack.mitre.org/) TTPs. Rules are written to minimize false positives through baseline comparison, allowlisting, and severity scoring — patterns applied at enterprise scale across 15,000–20,000 endpoint environments.

---

## Detection Rule Index

| # | Rule File | Tactic | Technique | Severity |
|---|-----------|--------|-----------|----------|
| 1 | `lateral-movement/lateral-movement-remote-services.kql` | Lateral Movement | T1021 – Remote Services | High |
| 2 | `lateral-movement/pass-the-hash-detection.kql` | Lateral Movement | T1550.002 – Pass the Hash | Critical |
| 3 | `lateral-movement/privilege-escalation-token.kql` | Privilege Escalation | T1134 – Token Impersonation | Critical |
| 4 | `credential-theft/lsass-memory-access.kql` | Credential Access | T1003.001 – LSASS Memory | Critical |
| 5 | `credential-theft/password-spray-detection.kql` | Credential Access | T1110.003 – Password Spray | High |
| 6 | `suspicious-powershell/suspicious-powershell-execution.kql` | Execution | T1059.001 – PowerShell | High |
| 7 | `suspicious-powershell/powershell-encoded-anomaly.kql` | Defense Evasion | T1027 + T1059.001 – Obfuscation | High |
| 8 | `persistence/scheduled-task-persistence.kql` | Persistence | T1053.005 – Scheduled Task | High |
| 9 | `persistence/registry-run-key-persistence.kql` | Persistence | T1547.001 – Registry Run Keys | High |
| 10 | `exfiltration/dns-tunneling-detection.kql` | Exfiltration | T1048.003 + T1071.004 – DNS Tunneling | High |
| 11 | `exfiltration/anomalous-outbound-transfer.kql` | Exfiltration | T1048 – Anomalous Data Transfer | High |

---

## Repository Structure

```
siem-detection-rules/
├── rules/
│   ├── lateral-movement/
│   │   ├── lateral-movement-remote-services.kql
│   │   ├── pass-the-hash-detection.kql
│   │   └── privilege-escalation-token.kql
│   ├── credential-theft/
│   │   ├── lsass-memory-access.kql
│   │   └── password-spray-detection.kql
│   ├── suspicious-powershell/
│   │   ├── suspicious-powershell-execution.kql
│   │   └── powershell-encoded-anomaly.kql
│   ├── persistence/
│   │   ├── scheduled-task-persistence.kql
│   │   └── registry-run-key-persistence.kql
│   └── exfiltration/
│       ├── dns-tunneling-detection.kql
│       └── anomalous-outbound-transfer.kql
└── README.md
```

---

## Rule Design Principles

**Baseline comparison** — Several rules (password spray, encoded PowerShell anomaly, outbound transfer) compute a historical baseline and alert on deviation rather than static thresholds. This approach was core to achieving a 70% false positive reduction in production environments.

**Severity scoring** — Every rule outputs a computed severity field (`Critical / High / Medium`) based on quantitative thresholds, enabling automated triage routing in SOAR platforms.

**Allowlisting** — Rules exclude known-good processes, machine accounts, internal IP ranges, and system accounts by default to reduce noise before the alert reaches an analyst.

**MITRE ATT&CK alignment** — Each rule includes the relevant technique ID as a field in output, enabling automatic TTP correlation in Sentinel incident timelines.

---

## Tools & Stack

- **SIEM:** Microsoft Sentinel (Azure Log Analytics)
- **Query Language:** KQL (Kusto Query Language)
- **Log Sources:** SecurityEvent, DnsEvents, CommonSecurityLog, DeviceProcessEvents
- **Framework:** MITRE ATT&CK v14
- **Tested on:** Azure Log Analytics Workspace (demo/lab data)

---

## Sample Rule Output

**Password spray detection** — `rules/credential-theft/password-spray-detection.kql`

```
Severity | IpAddress      | AccountsTargeted | TotalFailures | AttackDuration
---------|----------------|-----------------|---------------|---------------
High     | 203.0.113.42   | 23              | 287           | 00:18:34
Medium   | 198.51.100.17  | 12              | 64            | 00:07:12
```

**LSASS memory access** — `rules/credential-theft/lsass-memory-access.kql`

```
Severity | Computer    | Account       | ProcessNameShort | AccessCount | MitreAttack
---------|-------------|---------------|-----------------|-------------|------------
Critical | WS-FINANCE1 | jsmith        | procdump.exe    | 3           | T1003.001
```

---

## Background

These rules reflect detection patterns developed during 7 years of enterprise SOC operations — including MTTD/MTTR reduction initiatives and Azure Sentinel deployments at 15,000–20,000 endpoint scale. All rules are sanitized for public sharing; no client data or environment-specific identifiers are included.

---

## Related Projects

- [`soar-playbooks`](https://github.com/cybergirlApurva/soar-playbooks) — FortiSOAR automation playbooks for incident response
- [`threat-intel-automation`](https://github.com/cybergirlApurva/threat-intel-automation) — MISP/OTX IOC enrichment pipelines
- [`security-automation-toolkit`](https://github.com/cybergirlApurva/security-automation-toolkit) — Python utilities for SOC automation

---

*Apurva Tiwari · [LinkedIn](https://linkedin.com/in/apurva-tiwari) · MS Cybersecurity, George Washington University*
