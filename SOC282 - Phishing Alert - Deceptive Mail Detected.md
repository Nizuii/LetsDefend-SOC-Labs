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

