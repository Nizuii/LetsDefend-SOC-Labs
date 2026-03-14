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
