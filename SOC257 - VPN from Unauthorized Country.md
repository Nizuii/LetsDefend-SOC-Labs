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

