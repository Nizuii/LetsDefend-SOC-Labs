# SOC127 - SQL Injection Detected

Reported by: Nizamudheen KN  
Completed date: 10-03-2026  

---

**EventID** - 235  
**Event Time** - Mar, 07, 2024, 12:51 PM  
**Rule** - SOC127 - SQL Injection Detected  
**Level** - Security Analyst  
**Source Address** - 118.194.247.28  
**Destination Address** - 172.16.20.12  
**Destination Hostname** - WebServer10000  
**Requested URL** - GET /?douj=3034%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1 200 865  
