[CRITICAL] 802.1X logins failing at the Identity step on SSID-0e75838f
Detected at 14:25:28 (5 s after the first failed login)
*Observed*
  • 656 failed login attempts from 63 clients on 26 APs, 14:25:23-14:54:08, plus 12 cut off by the end of the capture - still failing when the capture ends
  • Of these: 502 ended by the AP's 802.1X timeout (reason 23), 139 cut short by the rejection wave (same clients) (reason 2: previous authentication no longer valid), 15 stalled with no disconnect seen
  • Every EAP request the APs send is an Identity request; no AP ever starts the login method
  • Clients answer when the sensors can hear them: 129 of 129
  • AP re-asks every 30 s, then deauths: reason 23 x502, reason 2 x139
  • No EAP-Success frame anywhere in the capture
*Most consistent with*: The APs get no answer from the authentication server path (RADIUS or the link to it)
*Not proven*
  • Whether the server is down, unreachable or misconfigured
  • Business impact (no payload or application data in the captures)
*Affected devices*
  • f0:18:98 (Apple): 33 clients
  • 3c:58:c2 (Intel): 30 clients
  • Workflow impact: join with asset inventory / WMS logs to confirm
*Owner*: Network identity / RADIUS team
*Next checks*
  1. RADIUS server health and request/timeout logs for the incident window
  2. Controller-to-RADIUS reachability and shared-secret/certificate changes
  3. Controller authentication logs for the affected APs
*Confidence*: High that logins fail at the auth-server step (641 of 656 attempts end in an explicit AP deauth); which component failed needs server-side logs
Example client to open in the dashboard: 3c:58:c2-6aa6450e39
------------------------------------------------------------------------------
[SERIOUS] APs start rejecting clients at 14:30:53
Detected at 14:31:51 (58 s after the first rejection)
*Observed*
  • 1317 disconnect frames with reason 2 (previous authentication no longer valid) from 14:30:53 to capture end
  • 18 / 18 clients / AP pairs, each client always rejected by the same AP
  • About 56 per minute across the site
*Most consistent with*: APs no longer hold valid authentication state for these clients (controller or AP-side change)
*Not proven*
  • What changed on the controller at the start time
  • Whether the clients notice
  • That the real APs sent these frames: no spoofing check is run (802.11 management frames are not authenticated unless PMF/802.11w is on)
*Affected devices*
  • 3c:58:c2 (Intel): 18 clients
  • Workflow impact: join with asset inventory / WMS logs to confirm
*Owner*: WLAN controller team
*Next checks*
  1. Controller and AP event logs around 14:30:53
  2. Config pushes, reboots or session-table events at that time
  3. Why only this client group is affected
*Confidence*: High that the APs send these rejections; cause needs controller logs
Example client to open in the dashboard: 3c:58:c2-1573a89e66
------------------------------------------------------------------------------
[WARNING] SSID-72f1f8be: 24 join attempts from 24 clients in 2 min
Detected at 14:26:47
*Observed*
  • Outside this wave SSID-72f1f8be averages 0.3 join attempts per minute; here 24 attempts from 24 clients hit 24 APs within 2 minutes (14:26:47). A reconnect wave like this usually follows an AP, controller or authentication event.
*Most consistent with*: Many clients reconnecting at once after an AP, controller or authentication event
*Not proven*
  • What triggered the reconnects
*Owner*: WLAN operations
*Next checks*
  1. Controller and AP events just before the burst
  2. Other findings in the same minutes
*Confidence*: High for what the sensors saw; the cause needs the owner's logs
------------------------------------------------------------------------------
[INFO] Channel 36: 5 APs share it
*Observed*
  • 5 APs (9 networks beaconing) are on channel 36, against a median of 3 on the other channels. Every client and AP on this channel contends for the same airtime, and beacons alone take a bigger share of it. A channel re-plan is a configuration change.
*Most consistent with*: Too many APs on one channel for the airtime available
*Not proven*
  • That users notice it today (no airtime or throughput data in header captures)
*Owner*: RF / WLAN design
*Next checks*
  1. Channel plan: move APs to quieter channels
  2. Transmit power and AP density in this area
*Confidence*: High for what the sensors saw; the cause needs the owner's logs
------------------------------------------------------------------------------
[INFO] Channel 40: 5 APs share it
*Observed*
  • 5 APs (9 networks beaconing) are on channel 40, against a median of 3 on the other channels. Every client and AP on this channel contends for the same airtime, and beacons alone take a bigger share of it. A channel re-plan is a configuration change.
*Most consistent with*: Too many APs on one channel for the airtime available
*Not proven*
  • That users notice it today (no airtime or throughput data in header captures)
*Owner*: RF / WLAN design
*Next checks*
  1. Channel plan: move APs to quieter channels
  2. Transmit power and AP density in this area
*Confidence*: High for what the sensors saw; the cause needs the owner's logs
------------------------------------------------------------------------------
[INFO] Probe storm on every channel
Detected at 14:26:00
*Observed*
  • Metrics flagged: retry (all), retry (mgmt), probe requests, probe responses
  • Sensors: 8 of 8
  • Failed attempts in window: 45 of 62
  • Retry, all frames: 4.5% to 9.5%
  • Retry, probe responses: 31.3% to 31.3% (flat)
*Most consistent with*: Many clients scanning for a new AP at once, e.g. after being kicked off
*Not proven*
  • A radio problem: probe-response retry stays flat, so the retry rise is a traffic-mix effect
*Owner*: WLAN operations (for information)
*Next checks*
  1. Line up with the other alerts: is this clients reacting to failed logins?
*Confidence*: High for the traffic change; no RF fault indicated
