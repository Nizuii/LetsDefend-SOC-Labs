# SOC257 - VPN from Unauthorized Country

Reported by: Nizamudheen KN  
Completed date: 13-03-2026  

---

<table>
  <tr>
    <td><strong>Field</strong></td>
    <td><strong>Value</strong></td>
    <td><strong>What it means</strong></td>
  </tr>
  <tr>
    <td><strong>Rule</strong></td>
    <td>SOC257 - VPN from Unauthorized Country</td>
    <td>A VPN login came from a country your org doesn't allow</td>
  </tr>
  <tr>
    <td><strong>Source IP</strong></td>
    <td>113.161.158.12</td>
    <td>Where the connection came from</td>
  </tr>
  <tr>
    <td><strong>Destination</strong></td>
    <td>33.33.33.33 (Monica)</td>
    <td>The internal machine being accessed</td>
  </tr>
  <tr>
    <td><strong>User</strong></td>
    <td>monica@letsdefend.io</td>
    <td>Whose account was used</td>
  </tr>
  <tr>
    <td><strong>Time</strong></td>
    <td>Feb 13, 2024, 02:04 AM</td>
    <td>2AM login — suspicious timing!</td>
  </tr>
  <tr>
    <td><strong>URL</strong></td>
    <td>https://vpn-letsdefend.io</td>
    <td>The VPN portal used</td>
  </tr>
</table>

Here the indicated 2 classic red flags that we found are:
1. **Geo-anomaly** - VPN login from an unauthorized/unexpected country
1. **Time anomaly** - 2:04 AM is outside normal business hours

## Step 2: Enrich - Source IP investigation.

This is the result we found about 113.161.158.12

Virustotal:
<img src="/Images/2026-03-13_10-03.png">

Abuseip:
<img src="/Images/abuseip.png">

Ipinfo:
<img src="/Images/ipinfo.png">

## Step 3: Analyze what does the evidence say

<table>
  <tr>
    <td><strong>Source</strong></td>
    <td><strong>Finding</strong></td>
    <td><strong>Severity</strong></td>
  </tr>
  <tr>
    <td><strong>VirusTotal</strong></td>
    <td>8/94 vendors flagged it — Malicious, Phishing, Malware</td>
    <td>Bad</td>
  </tr>
  <tr>
    <td><strong>AbuseIPDB</strong></td>
    <td>Reported 4,656 times from 910 sources</td>
    <td>Very Bad</td>
  </tr>
  <tr>
    <td><strong>IPInfo</strong></td>
    <td>Country: Vietnam</td>
    <td>Unauthorized</td>
  </tr>
  <tr>
    <td><strong>ISP</strong></td>
    <td>Vietnam Posts & Telecom (VNPT) — Fixed Line ISP</td>
    <td>Note</td>
  </tr>
</table>

## Step 4: Decide - Verdict Summary

- IP from Vietnam (Unauthorized country)
- IP flagged malicious on virustotal (8/94)
- 4,656 abuse reports - SSH bruteforce history.
- 02:04 AM login - Outside business hours.
- No prior indication Monica works from Vietnam.

**Verdict**: True Positive and unauthorized access. 

## Step 5: Respond

<table>
  <tr>
    <td><strong>Action</strong></td>
    <td><strong>Why</strong></td>
  </tr>
  <tr>
    <td>Disable Monica's account immediately</td>
    <td>Prevent further access</td>
  </tr>
  <tr>
    <td>Force password reset</td>
    <td>Account may be compromised</td>
  </tr>
  <tr>
    <td>Check if any data was accessed/exfiltrated</td>
    <td>Assess damage</td>
  </tr>
  <tr>
    <td>Escalate to Tier 2 / IR team</td>
    <td>Serious incident</td>
  </tr>
  <tr>
    <td>Document everything</td>
    <td>For the incident report</td>
  </tr>
</table>
