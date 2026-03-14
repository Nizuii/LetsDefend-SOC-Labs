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
