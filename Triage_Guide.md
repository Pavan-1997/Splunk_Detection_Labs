# 🧭 SOC Alert Triage Guide — Splunk Detection Lab

## Triage Workflow

```
Alert Fires
    │
    ▼
1. Confirm True Positive
    │
    ├─ Review raw event logs
    ├─ Check asset criticality
    └─ Check user context (admin? service account?)
    │
    ▼
2. Scope the Incident
    │
    ├─ What other hosts/users are affected?
    ├─ Is this isolated or part of a campaign?
    └─ Timeline: When did it start?
    │
    ▼
3. Escalate or Remediate
    │
    ├─ CRITICAL/HIGH → Escalate to IR team
    └─ MEDIUM/LOW → Document + monitor
```

---

## Brute Force Triage

**Alert: `detect_bruteforce_splunk.spl`**

| Step | Action |
|------|--------|
| 1 | Is the source IP internal or external? |
| 2 | Is the targeted account privileged (admin, service)? |
| 3 | Did any attempt succeed? (Check EventCode=4624 from same IP) |
| 4 | Correlate with VPN logs — is the IP a known location? |
| 5 | If successful auth follows failures → **Escalate immediately** |

**Key Splunk follow-up query:**
```spl
| Check if brute force was followed by successful login
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4624
src_ip="<ATTACKER_IP>" | table _time, AccountName, ComputerName, LogonType
```

---

## Mimikatz Triage

**Alert: `detect_mimikatz.spl`**

| Step | Action |
|------|--------|
| 1 | Isolate the host immediately if LSASS access confirmed |
| 2 | Identify the parent process — was it from a user session or service? |
| 3 | Check for subsequent network logons from the host (pass-the-hash) |
| 4 | Review process tree around the event time |
| 5 | Rotate all credentials for users logged into that system |

**CRITICAL: DCSync alerts always warrant full IR engagement.**

---

## PowerShell Triage

**Alert: `detect_powershell_encoded.spl`**

| Step | Action |
|------|--------|
| 1 | Decode the base64 payload if encoded: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...'))` |
| 2 | Identify if the parent process is unusual (Office app, browser) |
| 3 | Check for any outbound network connections from PowerShell |
| 4 | Review Script Block logs (Event 4104) for full decoded script |
| 5 | Search for any dropped files around the same timestamp |

---

## Lateral Movement Triage

**Alert: `detect_lateral_movement.spl`**

| Step | Action |
|------|--------|
| 1 | Map the movement: Source → Destination hosts |
| 2 | Verify if the account performing movement is expected to do so |
| 3 | Check if tools like PsExec, WMI, or RDP are standard in the environment |
| 4 | Look for data staging or exfiltration on destination hosts |
| 5 | Determine initial access vector — how did attacker get in? |

---

## Escalation Matrix

| Scenario | Escalation Level |
|----------|-----------------|
| Brute force + successful login | **IR Team — P1** |
| Mimikatz / LSASS access confirmed | **IR Team — P1** |
| DCSync detected | **IR Team — P1** |
| PowerShell from Office app | **IR Team — P2** |
| Lateral movement to DC | **IR Team — P1** |
| Single failed brute force (external) | **SOC Monitor — P3** |
| Encoded PowerShell, no execution | **SOC Investigate — P2** |
