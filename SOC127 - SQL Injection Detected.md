# SOC Incident Report
## SOC127 — SQL Injection Detected

---

## 1. Incident Overview

| Field            | Details                                          |
|------------------|--------------------------------------------------|
| Report Title     | SOC127 - SQL Injection Detected                  |
| Analyst Name     | Nizamudheen KN                                   |
| Date of Analysis | 16/03/2026                                       |
| Severity         | Medium                                           |
| Event ID         | 235                                              |
| Platforms Used   | LetsDefend, VirusTotal                           |
| Verdict          | True Positive                                    |

---

## 2. Alert Details

| Field                | Details                                                      |
|----------------------|--------------------------------------------------------------|
| Event ID             | 235                                                          |
| Rule Triggered       | SOC127 - SQL Injection Detected                              |
| Event Time           | Mar 07, 2024, 12:51 PM                                       |
| Source Address       | 118.194.247.28 (External Attacker)                           |
| Destination Address  | 172.16.20.12 (Internal Web Server)                           |
| Destination Hostname | WebServer10000                                               |
| HTTP Method          | GET                                                          |
| Device Action        | ⚠️ Allowed                                                   |

### Malicious URL Payload (Decoded)

```
douj=3034 AND 1=1
UNION ALL SELECT 1,NULL
'<script>alert("XSS")</script>'
table_name FROM information_schema.tables WHERE 2>1--
%2F%2A%2A%2F%3B EXEC xp_cmdshell('cat../../etc/passwd')#
```

### Payload Breakdown

| Component                                    | Attack Type          |
|----------------------------------------------|----------------------|
| AND 1=1                                      | SQL Injection test   |
| UNION ALL SELECT                             | UNION-based SQLi     |
| `<script>alert("XSS")</script>`              | XSS injection        |
| FROM information_schema.tables               | DB reconnaissance    |
| EXEC xp_cmdshell('cat../../etc/passwd')      | OS command injection |

---

## 3. Vulnerability Analysis

### SQL Injection — Overview

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| Attack Type    | SQL Injection + Blind SQL Injection                  |
| Target         | /index.php?id= parameter                             |
| Tool Used      | sqlmap/1.7.2 (automated exploitation tool)           |
| Technique      | Blind SQL Injection with CHAR() WAF bypass           |
| Secondary      | XSS, OS Command Injection, Port Scanning             |

### What is SQL Injection?
SQL Injection is an attack where malicious SQL commands are 
injected into input fields or URL parameters. When the web 
application fails to properly validate or sanitize input, 
the injected commands are executed directly against the 
database, potentially exposing or modifying sensitive data.

### What is Blind SQL Injection?
In Blind SQL Injection, no database output is visible on 
the page. Instead, the attacker asks thousands of TRUE/FALSE 
questions and measures how the page responds differently. 
sqlmap automates this entire process, extracting data one 
bit at a time without any visible output.

### CHAR() WAF Bypass Technique
Instead of sending readable SQL keywords like SELECT or WHERE
which WAF rules would detect, the attacker encoded them as 
character codes:
```
Normal:  SELECT
Encoded: CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
```
The WAF doesn't recognize the encoded form, allowing the 
payload to bypass detection while the database executes it.

### Why xp_cmdshell + cat Would Fail
The payload contained `EXEC xp_cmdshell('cat../../etc/passwd')`.
This would fail because:
- xp_cmdshell is a Microsoft SQL Server feature (Windows)
- cat is a Linux/Unix command
- They are incompatible — confirms automated scanner blindly
  throwing all payloads without checking compatibility
- Also missing space: cat../../etc/passwd should be
  cat ../../etc/passwd

---

## 4. Threat Intelligence

### Attacker IP Analysis — VirusTotal

| Field           | Details                                            |
|-----------------|----------------------------------------------------|
| IP Address      | 118.194.247.28                                     |
| VT Detection    | 9/94 vendors flagged as malicious                  |
| Community Score | -1 (suspicious)                                    |
| Country         | 🇨🇳 China                                          |
| ASN             | AS4808 — China Unicom Beijing Province Network     |

### Vendor Detections

| Vendor               | Verdict   |
|----------------------|-----------|
| ADMINUSLabs          | Malicious |
| alphaMountain.ai     | Malicious |
| BitDefender          | Phishing  |
| CyRadar              | Malicious |
| Forcepoint           | Malicious |
| Fortinet             | Malware   |
| G-Data               | Phishing  |
| SOCRadar             | Malware   |

### China Unicom — Significance
China Unicom is a major Chinese ISP commonly seen in 
automated scanning operations, bot networks, and mass 
vulnerability scanning campaigns. The IP being hosted 
on this network combined with automated sqlmap activity 
suggests a mass scanning operation targeting vulnerable 
web applications globally.

### Attack Tool — sqlmap/1.7.2
sqlmap is an open-source automated SQL injection tool. 
Its presence in the User-Agent field confirms:
- Attack was fully automated and scripted
- Not a manual human attack
- Attacker was running mass scans
- Multiple WAF bypass techniques built into the tool

---

## 5. Log Analysis & Attack Evidence

### Attack Volume
```
Total Events : 42 requests from 118.194.247.28
Time Range   : 11:56 AM → 12:53 PM (~1 hour)
Target       : 172.16.20.12 (WebServer10000)
```

### Attack Phases Identified

| Phase | Time       | Activity                          |
|-------|------------|-----------------------------------|
| 1     | 11:56 AM   | Port scanning begins              |
| 2     | 12:00 PM   | Continued reconnaissance          |
| 3     | 12:25 PM   | More port scanning activity       |
| 4     | 12:51 PM   | SQL injection attack launched     |
| 5     | 12:53 PM   | Continued automated SQLi attempts |

### Port Scanning Evidence
Attacker probed multiple random high ports on 172.16.20.12:
```
Ports observed: 33049, 45848, 61969, 12896, 50843,
                32362, 29905, 17604, 18766, 13240,
                55273, 53401, 18388, 12303, 34999
```
This confirms Phase 1 reconnaissance before exploitation.

### HTTP Response Analysis
```
Response Code : HTTP 200
Response Size : 865 bytes
Implication   : Server received and processed requests

NOTE: HTTP 200 confirms communication succeeded.
      It does NOT confirm SQL injection succeeded.
      Data exfiltration could not be confirmed
      from available log evidence.
```

### sqlmap Blind SQLi Payload (from logs)
```
GET /index.php?id=1'AND 5327' IN (SELECT 
(CHAR(113)+CHAR(107)+CHAR(107)+CHAR(118)+CHAR(113)+
(SELECT CASE WHEN (285327=5327) THEN CHAR(49)...
```
CHAR() encoding used to bypass WAF signature detection.

---

## 6. Attack Chain Reconstruction

### Visual Attack Chain

```
[Attacker — 118.194.247.28 — China Unicom, CN]
                ↓
[Phase 1: Port scanning on 172.16.20.12]
[Probing multiple ports for open services]
                ↓
[Phase 2: Web application identified on port 80]
[/index.php?id= parameter discovered]
                ↓
[Phase 3: sqlmap/1.7.2 automated tool launched]
[Blind SQL Injection with CHAR() WAF bypass]
                ↓
[Multiple attack types in single payload:]
[SQL Injection + XSS + DB Recon + OS Command Injection]
                ↓
[42 total requests over ~1 hour]
[Server responds HTTP 200 to requests]
                ↓
[Data exfiltration status: UNCONFIRMED]
[Investigation ongoing]
```

### Step-by-Step Breakdown

| Step | Action                          | Evidence                        |
|------|---------------------------------|---------------------------------|
| 1    | Port scanning begins            | Random high port connections    |
| 2    | Port 80 identified              | HTTP requests to WebServer10000 |
| 3    | sqlmap launched                 | User-Agent: sqlmap/1.7.2        |
| 4    | Blind SQLi with CHAR() bypass   | CHAR() encoded payload in logs  |
| 5    | XSS payload injected            | script tag in URL               |
| 6    | DB recon attempted              | information_schema.tables query |
| 7    | OS command injection attempted  | xp_cmdshell payload             |
| 8    | Server responds HTTP 200        | Log analysis                    |

### Attacker Techniques Used

| Technique            | Detail                                        |
|----------------------|-----------------------------------------------|
| Port Scanning        | Reconnaissance before exploitation            |
| Blind SQL Injection  | TRUE/FALSE based data extraction              |
| CHAR() Encoding      | WAF bypass technique                          |
| UNION Injection      | Database query manipulation                   |
| XSS                  | Cross-site scripting attempt                  |
| OS Command Injection | xp_cmdshell abuse attempt                     |
| Path Traversal       | ../../etc/passwd access attempt               |
| Automated Scanning   | sqlmap tool — mass automated attack           |

### IOC Summary

| IOC                  | Type          |
|----------------------|---------------|
| 118.194.247.28       | Attacker IP   |
| AS4808 China Unicom  | Attacker ASN  |
| 172.16.20.12         | Victim IP     |
| WebServer10000       | Victim host   |
| sqlmap/1.7.2         | Attack tool   |
| /index.php?id=       | Attack vector |

---

## 7. Verdict & Recommendations

### Final Verdict: TRUE POSITIVE ✅

This incident is confirmed as a True Positive. An attacker 
at 118.194.247.28 (China Unicom, CN) conducted a coordinated 
attack campaign against WebServer10000 (172.16.20.12) using 
the automated sqlmap tool. The attack included port scanning, 
blind SQL injection with WAF bypass techniques, XSS, database 
reconnaissance, and OS command injection — all within a single 
hour. The server responded HTTP 200 to requests, however data 
exfiltration could not be confirmed from available log evidence.

### Immediate Containment Actions

| Priority  | Action                                                       |
|-----------|--------------------------------------------------------------|
| 🔴 HIGH   | Block attacker IP 118.194.247.28 on firewall                 |
| 🔴 HIGH   | Isolate WebServer10000 for forensic investigation            |
| 🔴 HIGH   | Check database logs for successful data extraction           |
| 🔴 HIGH   | Check if any data was exfiltrated from the database          |
| 🟡 MEDIUM | Review all open ports on 172.16.20.12                        |
| 🟡 MEDIUM | Check for other IPs scanning the same server                 |
| 🟡 MEDIUM | Review web application logs for other attack attempts        |
| 🟢 LOW    | Implement input validation on all user-supplied parameters   |
| 🟢 LOW    | Deploy/tune WAF rules for sqlmap User-Agent detection        |

### Long-Term Recommendations

| # | Recommendation                                                       |
|---|----------------------------------------------------------------------|
| 1 | Implement parameterized queries / prepared statements in code        |
| 2 | Deploy WAF rule to block sqlmap User-Agent string                    |
| 3 | Implement input validation and sanitization on all parameters        |
| 4 | Enable rate limiting — 42 requests in 1 hour should auto-block      |
| 5 | Disable xp_cmdshell on all SQL Server instances                      |
| 6 | Implement geo-blocking for high-risk regions if not needed           |
| 7 | Regular web application penetration testing                          |
| 8 | Deploy database activity monitoring (DAM) solution                   |

### Lesson Learned
This attack demonstrated the danger of unvalidated user input 
in web applications. The `/index.php?id=` parameter accepted 
malicious SQL commands without any sanitization. The attacker 
used sqlmap — a freely available automated tool — meaning 
even low-skilled attackers can launch sophisticated SQL 
injection attacks. The most effective prevention is 
parameterized queries which separate SQL code from user data, 
making injection impossible regardless of what the attacker 
submits. Additionally, rate limiting would have detected and 
blocked 42 requests in one hour automatically.

### IOC Summary — For Threat Hunting

| IOC                  | Type         |
|----------------------|--------------|
| 118.194.247.28       | Attacker IP  |
| AS4808 China Unicom  | Attacker ASN |
| sqlmap/1.7.2         | User-Agent   |
| /index.php?id=       | Attack vector|
| WebServer10000       | Victim host  |
| 172.16.20.12         | Victim IP    |

---

*Report authored by Nizamudheen KN | Analyzed on LetsDefend & VirusTotal | Date: 16/03/2026*
