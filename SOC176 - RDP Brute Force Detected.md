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

Inorder to check whether the source IP address is malicious or not we have to first check the IP reputation in the threat intelligence feeds. And the result we got while checking the IP address in threat intelligence feeds indicates that the IP address is malicious.

<img width="1856" height="1018" alt="image" src="https://github.com/user-attachments/assets/15bb9a0c-16f4-40ba-84e9-0b2cb85ec7e9" />

## Step-2 Searching for the successful login

After confirming the IP is malicious our next objective is to sort out the successful login from the failed attempts. the query we used to filter the malicious IP address logs is `source_ip == 218.92.0.56`. After scrolling to these log we was able to detect one success ful login attempt.

<img width="1850" height="578" alt="image" src="https://github.com/user-attachments/assets/7cf063fb-738c-4c01-8f81-c0f670c169b1" />

And from the log investigation we observe that logs show many connections to port 3389 and this port is RDP.

```bash
source_port = 52316
source_port = 32029
source_port = 31454
source_port = 33376
source_port = 52534
```
This pattern strongely indicates automated bruteforce tool.

## Critical Finding
In the successful login log we opened:

```bash
EventID: 4624
Description: An account was successfully logged on
Logon Type: 10 (RemoteInteractive)
Username: Matthew
Source IP: 218.92.0.56
```

| Field         | Meaning              |
| ------------- | -------------------- |
| EventID 4624  | Successful login     |
| Logon Type 10 | Remote Desktop login |
| Source IP     | Attacker             |
| Username      | Compromised account  |

This means the attacker successfully logged into the system via RDP.

## Analysis Conclusion

Attack chain:
1. External IP starts brute force attempts.
1. Many attempts failed to login.
1. Eventually successful RDP login.

**Alert Classification**: True Positive because the IP is malicious, multiple brute force attempts, successful RDP login.
**SOC Analyst Investigation Note**: 
```bash
Multiple RDP login attempts were detected from external IP 218.92.0.56 against host 172.16.17.148.
Threat intelligence indicates the IP has malicious reputation.

Log analysis shows repeated connection attempts to port 3389.
Event ID 4624 confirms a successful RDP login for user "Matthew" using Logon Type 10.

This indicates the attacker successfully authenticated via RDP after brute force attempts.

The alert is classified as a True Positive.
```

## Actions and Response:

In a real company the next actions would be:
1. Disable compromised account
1. Force password reset
1. Block attacker IP on firewall
1. Investigate post-login activity
