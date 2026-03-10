# 	SOC176 - RDP Brute Force Detected

Reported by: Nizamudheen KN  
Completed date: 10-03-2026  

---

**Event ID** - 234  
**Event Time** - Mar 07, 2024, 11:44 AM  
**Rule** - SOC176 - RDP Brute Force Detected  
**Level** - Security Analyst  
**Source IP Address** - 218.92.0.56  
**Destination IP Address** - 172.16.17.148  
**Destination Hostname** - Mathew  
**Protocol** - RDP  
**Firewall action** - Allowed  
**Alert Trigger Reason** - Login failure from a single source with different non existing accounts.  

## Step-1 Analyze whether the source IP address is malicious or not.

Inorder to check whether the source IP address is malicious or not we have to first check the IP reputation in the threat intelligence feeds.
