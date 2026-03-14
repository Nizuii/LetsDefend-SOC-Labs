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
