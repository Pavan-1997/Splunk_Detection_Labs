# 🔍 Splunk Detection Lab

> A curated collection of production-ready SPL (Search Processing Language) detection queries for SOC analysts.  
> Mapped to **MITRE ATT&CK** framework with severity ratings and triage guidance.

---

## 📁 Repository Structure

```
splunk-detection-lab/
├── detections/
│   ├── detect_bruteforce_splunk.spl      # T1110  - Brute Force & Password Spray
│   ├── detect_mimikatz.spl               # T1003  - Credential Dumping
│   ├── detect_powershell_encoded.spl     # T1059.001 - PowerShell Abuse
│   └── detect_lateral_movement.spl       # T1021  - Lateral Movement
├── dashboards/
│   └── soc_overview.xml                  # Splunk Dashboard XML
└── docs/
    └── triage_guide.md                   # Alert triage & response guide
```

---

## 🎯 Detection Coverage

| File | MITRE Technique | Tactic | Severity |
|------|----------------|--------|----------|
| `detect_bruteforce_splunk.spl` | T1110, T1110.001, T1110.003 | Credential Access | MEDIUM–HIGH |
| `detect_mimikatz.spl` | T1003, T1003.001, T1003.006 | Credential Access | HIGH–CRITICAL |
| `detect_powershell_encoded.spl` | T1059.001, T1562.001 | Execution, Defense Evasion | MEDIUM–CRITICAL |
| `detect_lateral_movement.spl` | T1021, T1021.001/002/006, T1053, T1550 | Lateral Movement | MEDIUM–CRITICAL |

---

## ⚙️ Prerequisites

### Required Data Sources

| Detection | Required Index / Sourcetype |
|-----------|----------------------------|
| Brute Force | `index=windows_logs` — `WinEventLog:Security` (EID 4625, 4740) |
| Mimikatz | `index=windows_logs` — `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (EID 1, 10, 11, 17) |
| PowerShell | `index=windows_logs` — `WinEventLog:Microsoft-Windows-PowerShell/Operational` (EID 4104) |
| Lateral Movement | `index=windows_logs` — Security + Sysmon (EID 4624, 4698, 5140, 7045) |

### Recommended Sysmon Config
Use [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) or [Olaf Hartong's Sysmon Modular](https://github.com/olafhartong/sysmon-modular).

### Enable PowerShell Script Block Logging
```powershell
# Enable via Group Policy or directly:
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1
```

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourorg/splunk-detection-lab.git
```

### 2. Import Queries into Splunk
- Copy `.spl` content into Splunk Search bar
- Save as **Saved Searches** or **Alerts**

### 3. Configure Alerts
Recommended alert settings:

```
Trigger: Per Result or Number of Results > 0
Throttle: 1 hour per host/user
Action: Send email / Create JIRA ticket / Webhook to SOAR
```

---

## 🔍 Detection Details

### 🔴 Brute Force (`detect_bruteforce_splunk.spl`)
| Rule | Trigger | Event IDs |
|------|---------|-----------|
| Threshold Brute Force | ≥10 failed logins in 5 min | 4625 |
| Password Spray | ≥5 unique accounts, <20 failures | 4625 |
| SSH Brute Force | ≥10 failures in 5 min | linux_secure |
| Account Lockout Storm | ≥3 lockouts in 15 min | 4740 |

### 🔴 Mimikatz (`detect_mimikatz.spl`)
| Rule | Trigger | Event IDs |
|------|---------|-----------|
| LSASS Memory Access | Suspicious GrantedAccess values | Sysmon 10 |
| Mimikatz CLI Patterns | sekurlsa, logonpasswords, dcsync | Sysmon 1 |
| DCSync Attack | Directory replication rights abuse | 4662 |
| SAM/NTDS Access | Credential database file touched | Sysmon 11 |
| ProcDump on LSASS | comsvcs.dll MiniDump usage | Sysmon 1 |
| Mimikatz Named Pipe | \\mimikatz* pipe creation | Sysmon 17 |

### 🟠 PowerShell (`detect_powershell_encoded.spl`)
| Rule | Trigger | Event IDs |
|------|---------|-----------|
| Encoded Commands | -EncodedCommand/-enc/-ec flags | 4688, Sysmon 1 |
| Malicious Script Blocks | IEX, Invoke-Mimikatz, download cradles | 4104 |
| Download Cradles | Net.WebClient, Invoke-WebRequest | 4104, Sysmon 1 |
| Execution Policy Bypass | -ExecutionPolicy Bypass, -NoProfile | 4688, Sysmon 1 |
| Suspicious Parent | Word/Excel/mshta spawning PowerShell | Sysmon 1 |
| AMSI Bypass | AmsiUtils, amsiInitFailed patterns | 4104 |

### 🟠 Lateral Movement (`detect_lateral_movement.spl`)
| Rule | Trigger | Event IDs |
|------|---------|-----------|
| PsExec | PSEXESVC service creation | Sysmon 1, 4697 |
| WMI Remote Exec | wmic.exe /node: or WmiPrvSE child proc | Sysmon 1 |
| Pass-the-Hash | NTLM auth across multiple hosts | 4624 |
| RDP Hopping | RDP logons to 3+ hosts | 4624 |
| Admin Share Access | C$, ADMIN$, IPC$ unusual access | 5140 |
| SMB Multi-Host Auth | Network logon to 3+ hosts in 10 min | 4624 |
| Remote Sched. Tasks | Task created with suspicious command | 4698 |

---

## 📊 Severity Reference

| Level | Action Required |
|-------|----------------|
| **CRITICAL** | Immediate escalation — potential active compromise |
| **HIGH** | Investigate within 1 hour |
| **MEDIUM** | Investigate within 4 hours / business day |
| **LOW** | Review during regular threat hunting cycles |

---

## 🛡️ Tuning & Whitelisting

Each query includes `NOT` clauses for known-good processes. To add environment-specific exclusions:

```spl
| where NOT ComputerName IN ("jump-server-01", "patching-host")
| where NOT User IN ("svc_backup", "svc_patching")
```

---

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)

---

## 📄 License

MIT License — free to use, modify, and distribute.  
If you find this useful, ⭐ star the repo!
