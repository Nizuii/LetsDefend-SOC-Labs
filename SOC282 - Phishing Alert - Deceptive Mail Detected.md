# SOC282 - Phishing Alert - Deceptive Mail Detected

**Reported by:** Nizamudheen KN  
**Completed date:** 13-03-2026  

---

## Executive Summary

On May 13, 2024 at 09:22 AM, a phishing email 
was delivered to Felix@letsdefend.io from a 
typosquatted domain free@coffeeshooop.com 
(note: 3 o's instead of 2).

The attacker attempted to social engineer Felix 
using a fake coffee voucher offer, luring him to 
click a "Redeem Now" button. The email used urgency 
tactics ("Hurry, this offer expires soon!") to 
pressure Felix into clicking without thinking. 
The malicious link led to a fake page designed 
to deliver malware to the victim's machine.

Log analysis confirmed that Felix did NOT click 
the link — no outbound connections to 
coffeeshooop.com were detected. The phishing 
email was caught by the SOC before any damage 
occurred.

Verdict   : True Positive  
Attack    : Phishing — Social Engineering  
Severity  : Medium  
Status    : Contained — No click detected  

## 2. Alert Details

| Field | Value |
|---|---|
| **Event ID** | 257 |
| **Rule Name** | SOC282 - Phishing Alert - Deceptive Mail Detected |
| **Date & Time** | May 13, 2024, 09:22 AM |
| **SMTP Address** | 103.80.134.63 |
| **Source Address** | free@coffeeshooop.com |
| **Destination** | Felix@letsdefend.io |
| **Email Subject** | Free Coffee Voucher |
| **Device Action** | Allowed ⚠️ (email reached inbox) |
| **Alert Type** | Phishing |
| **Severity** | Medium |

## 3. Analysis

### 3.1 SMTP IP Analysis — 103.80.134.63

#### VirusTotal
| Field | Value |
|---|---|
| **Detection Score** | 8/94 vendors flagged as malicious |
| **Threat Labels** | Phishing, Malicious |
| **Country** | South Korea 🇰🇷 |
| **ISP** | LG DACOM Corporation |
| **Community Score** | -3 (negative = suspicious) |

#### AbuseIPDB
| Field | Value |
|---|---|
| **Status** | Not found in database |
| **ISP** | HDTIDC LIMITED |
| **Country** | South Korea 🇰🇷 |
| **Abuse Reports** | None filed |

> **Analyst Note:** Although AbuseIPDB shows no 
> reports, the IP is confirmed malicious based on 
> 8/94 VirusTotal detections and a negative 
> community score of -3. Clean AbuseIPDB record 
> does not mean the IP is legitimate — context 
> and correlation always take priority over 
> reputation alone.

### 3.2 Email Analysis

#### Email Details
| Field | Value |
|---|---|
| **From** | free@coffeeshooop.com |
| **To** | Felix@letsdefend.io |
| **Subject** | Free Coffee Voucher |
| **Button** | "Redeem Now" |
| **Link Destination** | Fake malware delivery page disguised as voucher redemption |

#### Email Body
> "Dear Felix, Start your day off right with 
> a complimentary cup of coffee at our café! 
> Just click the link below to redeem your 
> voucher. Hurry, this offer expires soon!"

#### Social Engineering Techniques Used
| Technique | How It Was Used |
|---|---|
| **Luring with Free Offer** | Fake coffee voucher used to tempt Felix into clicking |
| **Urgency Tactics** | "Hurry, this offer expires soon!" — pressuring Felix to act without thinking |
| **Typosquatting** | coffeeshooop.com uses 3 o's instead of 2 to impersonate a legitimate domain |
| **Masquerading** | Email designed to look like a legitimate promotional offer |

#### Malicious Link Analysis
| Field | Value |
|---|---|
| **Sender Domain** | coffeeshooop.com — typosquatted domain |
| **Legitimate Domain** | coffeeshoop.com |
| **Difference** | Extra "o" — coffeesho**oo**p vs coffeesho**ooo**p |
| **Landing Page** | Fake page prompting malware download |
| **Page Content** | "INFECTED" stamp — Download File prompt |

### 3.3 Log Analysis

#### SMTP Delivery Log
| Field | Value |
|---|---|
| **Time** | May 13, 2024, 09:20 AM |
| **Source IP** | 103.80.134.63 (attacker) |
| **Destination IP** | 172.16.20.3 (Felix's mail server) |
| **Port** | 25 (SMTP — email delivery) |
| **Sender** | free@coffeeshooop.com |
| **Recipient** | Felix@letsdefend.io |

> This log confirms the attacker's server 
> successfully delivered the phishing email 
> to Felix's inbox via SMTP port 25.

#### Felix Click Analysis
| Field | Value |
|---|---|
| **Search Query** | Source Address = 172.16.20.3 |
| **Connections to coffeeshooop.com** | None found |
| **Outbound suspicious traffic** | None detected |
| **Conclusion** | Felix did NOT click the link |

> No outbound connections from Felix's machine 
> to coffeeshooop.com were detected in logs. 
> The phishing email bypassed email security 
> and reached Felix's inbox — however the SOC 
> detected and responded before Felix 
> clicked the malicious link.

## 4. Attack Timeline

| Time | Event |
|---|---|
| **09:20 AM** | Attacker sends phishing email from 103.80.134.63 via SMTP port 25 — email delivered to Felix's mail server (172.16.20.3) |
| **09:22 AM** | Phishing email reaches Felix@letsdefend.io inbox — Device Action: Allowed |
| **09:22 AM** | SOC alert fires — SOC282 Phishing Alert Deceptive Mail Detected |
| **After alert** | Log analysis confirms Felix did NOT click the malicious link — no outbound connections to coffeeshooop.com detected |
| **After alert** | SOC responds — email to be deleted, domain blocked before any damage occurs |
```
ATTACK CHAIN SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker registers coffeeshooop.com
(typosquatting)
        ↓
Sends phishing email to Felix
(free coffee voucher + urgency tactics)
        ↓
Email bypasses security — Allowed ⚠️
        ↓
SOC detects and alerts 🚨
        ↓
Felix did NOT click ✅
        ↓
Caught before infection! 🛡️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 5. Indicators of Compromise (IOCs)

### Malicious Email Details
| Field | Value | Notes |
|---|---|---|
| **Sender Address** | free@coffeeshooop.com | Typosquatted domain |
| **Sender Domain** | coffeeshooop.com | 3 o's — impersonating legitimate domain |
| **Subject Line** | Free Coffee Voucher | Social engineering lure |

### Malicious IP Addresses
| IP | Country | ISP | Detections | Role |
|---|---|---|---|---|
| **103.80.134.63** | 🇰🇷 South Korea | LG DACOM / HDTIDC | 8/94 VT | Phishing email delivery server |

### Malicious URLs & Domains
| Type | Value | Notes |
|---|---|---|
| **Domain** | coffeeshooop.com | Typosquatted attacker domain |
| **Malicious URL** | https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip | Malware delivery URL hidden behind "Redeem Now" button |

> **Analyst Notes:**
> - The malicious URL uses a redirect technique — 
>   it first goes through cyberlearn.academy 
>   then pulls a zip file from AWS S3
> - The zip file is named "free-coffee.zip" — 
>   masquerading as a legitimate voucher file
> - This is the same AWS S3 abuse technique 
>   we saw in SOC153!
