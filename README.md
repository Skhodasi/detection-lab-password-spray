# Detection Lab: Simulated Password Spray Attack Against Active Directory

**Author:** Selorm Hodasi ([GitHub: Skhodasi](https://github.com/Skhodasi))
**Category:** Home Lab / Blue Team / Detection Engineering
**Status:** Complete — attack simulated, logged, detected, and alerted on

## Summary

This project simulates a password spray attack against a domain-joined Windows environment, then detects and alerts on it using a self-hosted SIEM. The goal was to build hands-on experience with the full attack-to-detection lifecycle: standing up vulnerable infrastructure, attacking it like an adversary would, and then building the defensive visibility to catch it — the same workflow a SOC analyst works through daily.

## Lab Architecture

| Host | Role | OS | IP Address |
|---|---|---|---|
| **DC01** | Domain Controller | Windows Server 2025 Standard (Evaluation, Server Core) | 192.168.56.102 |
| **WIN10-01** | Domain-joined client + SIEM | Windows 11 Pro | 192.168.56.101 |
| **KALI-ATK** | Attacker machine | Kali Linux 2026.3 | 192.168.56.103 (host-only) |

- **Domain:** `lab.local`
- **Virtualization:** Oracle VirtualBox, host-only network for internal lab traffic
- **Log pipeline:** Sysmon + Windows Security Event Log → Splunk Universal Forwarder (DC01) → Splunk Enterprise (WIN10-01), port 9997
- **Attack tooling:** `netexec` (nxc) over SMB, from Kali

## Target Account

A deliberately weak Active Directory account was created to simulate a realistic spray target — the kind of account a real-world attacker would be hoping to find in an organization with weak password hygiene.

- **Username:** `wuser`
- **Password:** `Summer2024!` (weak, guessable, meets minimum complexity but follows a predictable seasonal pattern)
- **Settings:** `PasswordNeverExpires = True`, `Enabled = True`

## Attack Simulation

From the Kali attacker host, a password spray was run against DC01 over SMB using a small wordlist of plausible weak passwords, with the real password placed last to simulate a realistic multi-guess attack:

```bash
nxc smb 192.168.56.102 -u wuser -p wordlist.txt -d lab.local
```

**Wordlist used:**
```
Password1
Welcome1
Summer2023!
Password123!
Summer2024!
```

**Result:** 4 failed login attempts, followed by 1 successful login on the final (correct) password — exactly the signature of an automated password-guessing tool.

## Evidence: Windows Security Event Logs

All logon activity was captured in Windows Security Event Logs on DC01, forwarded to Splunk via the Universal Forwarder and Sysmon.

| Time | Event | EventCode |
|---|---|---|
| 12:03:40.560 PM | Failed logon (wuser) | 4625 |
| 12:03:42.118 PM | Failed logon (wuser) | 4625 |
| 12:03:43.870 PM | Failed logon (wuser) | 4625 |
| 12:03:45.238 PM | Failed logon (wuser) | 4625 |
| 12:03:46.708 PM | **Successful logon (wuser)** | **4624** |

**Key fields from the successful logon event (4624):**

```
Account_Name:            wuser
Account_Domain:          LAB
Logon_Type:               3 (Network)
Authentication_Package:  NTLM
Package_Name_NTLM_only:  NTLM V2
Source_Network_Address:  192.168.56.103   <-- attacker IP
Source_Port:              45646
```

`Source_Network_Address: 192.168.56.103` directly ties this successful authentication to the Kali attacker machine, and `Logon_Type: 3` confirms it came in over the network — not from someone physically at the keyboard. Combined with four rapid-fire failures immediately before it from the same source and account, this is a textbook password spray signature.

## Detection: Splunk Search

The following SPL query identifies the password-spray pattern — 3 or more failed logons from the same source IP, against the same account, within a 5-minute window:

```spl
index=* host=DC01 EventCode=4625
| bucket _time span=5m
| stats count by _time, Source_Network_Address, Account_Name
| where count >= 3
```

This search was validated against the real attack traffic generated during testing and consistently surfaced every spray attempt, correctly isolating `192.168.56.103` as the common source across multiple bursts.

## Detection: Splunk Alert

The search above was saved as a **real-time Splunk alert**, configured to:

- **Trigger condition:** Per-Result (fires as soon as the pattern matches)
- **Throttling:** Suppress repeat alerts for the same `Source_Network_Address` for 300 seconds, to avoid alert flooding during an ongoing attack
- **Action:** Add to Triggered Alerts

**Alert name:** `Password Spray Detection - SMB Failed Logons`

### Validation

The attack was re-run after the alert was deployed to confirm it fires correctly in practice, not just in testing:

```
Trigger History:
2026-11-01 13:05:46 Central Standard Time — Alert fired successfully
```

This confirms the full detection pipeline works end-to-end: **attack → log generation → forwarding → SIEM ingestion → correlation search → real-time alert.**

## Skills Demonstrated

- Active Directory setup and user/account management (PowerShell, `New-ADUser`, `Set-ADAccountPassword`)
- Sysmon deployment and Windows Event Log forwarding
- Splunk Universal Forwarder configuration (`inputs.conf`, custom log channels)
- SIEM log analysis and SPL (Search Processing Language)
- Building and tuning detection logic (thresholds, time windows, throttling)
- Offensive tooling fundamentals (SMB authentication attacks, `netexec`)
- Windows Firewall / network troubleshooting (NetBIOS, SMB ports, Windows Defender Firewall rule management)
- End-to-end incident detection lifecycle, from attack simulation to alert validation

## Lessons Learned / Troubleshooting Notes

A few real-world troubleshooting challenges came up during this project, each resolved through systematic diagnosis:

- **SMB/NetBIOS connectivity issues:** Initial password-spray attempts failed with NetBIOS timeout errors even after opening relevant firewall ports (TCP 139, TCP 445, UDP 137) and fully disabling the Windows Firewall. Testing with a second SMB client (`smbclient`) isolated the issue to the attack tool itself rather than the network — a good reminder to verify assumptions with an independent tool before chasing the wrong root cause.
- **Credential mismatch:** The account's actual password didn't match what was expected, surfaced via a clean `NT_STATUS_LOGON_FAILURE` from `smbclient`. Resetting the password directly resolved the issue.
- **Tool naming conventions:** `crackmapexec` has been succeeded by `netexec` (`nxc`) on current Kali releases — worth confirming tool names/versions before assuming a package is missing.

## Next Steps

- Expand detection coverage to include Kerberos-based authentication attacks
- Add a correlation rule tying failed→successful logon bursts into a single composite alert
- Build a lightweight dashboard visualizing logon activity by source IP over time
