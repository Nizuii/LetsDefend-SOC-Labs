# SOC338 - Lumma Stealer

Reported by: Nizamudheen KN  
Completed date: 10-03-2026  

---

**EventID**: 316  
**Event Time**: Mar, 13, 2025, 09:44 AM  
**Rule**: SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing  
**Level**: Security Analyst  
**SMTP Address**: 132.232.40.201  
**Source Address**: update@windows-update.site  
**Destination Address**: dylan@letsdefend.io  
**Email Subject**: Upgrade your system to Windows 11 Pro for FREE  
**Device Action**: Allowed  
**Triggered Reason**: Redirected site contains a click fix type script for Lumma Stealer distribution.  

This is a phishing email delivery Lumma Stealer malware using DDL sideloading.

## Immediate Red Flags

### 1. Sender email

```bash
update@windows-update.site
```

Its a red flag because microsoft does not send updates from random domains. Legitimate domains would look like:

```bash
microsoft.com
windows.com
office.com
```

This is spoofing microsoft branding.

### 2. SMTP IP Investigation.

IP: `132.232.40.201`. We have checked the IP reputation in Threat Intelligence Feeds.

Virus Total
<img width="1850" height="890" alt="image" src="https://github.com/user-attachments/assets/a4bcd965-102d-4108-989d-38c6adcc6ab6" />

Talos Intelligence
<img width="1849" height="901" alt="image" src="https://github.com/user-attachments/assets/958eccc6-7562-4cbf-b26f-06a8c5bea395" />

Letsdefend TI
<img width="1868" height="945" alt="image" src="https://github.com/user-attachments/assets/00aaa552-fd0d-4172-9dcf-7055d46113df" />

| Evidence       | Result                  |
| -------------- | ----------------------- |
| Detection rule | Lumma Stealer campaign  |
| Email lure     | Phishing                |
| Sender domain  | Fake Microsoft          |
| VirusTotal     | Some detections         |
| Talos          | Neutral (new infra)     |
| LetsDefend TI  | Lumma tag               |
| Trigger reason | ClickFix malware script |

### 3. URL Analysis Conclusion.

VirusTotal
<img width="1849" height="888" alt="image" src="https://github.com/user-attachments/assets/a216cea0-fee9-4ff0-83ff-8a736575ca3d" />

VirusTotal shows 9/95 vendors detected malicious. the URL is:
```bash
http://windows-update.site
```

| Indicator                  | Reason           |
| -------------------------- | ---------------- |
| HTTP not HTTPS             | No security      |
| Fake Microsoft domain      | Impersonation    |
| Malware detections         | Confirmed threat |
| Lumma campaign correlation | High confidence  |

