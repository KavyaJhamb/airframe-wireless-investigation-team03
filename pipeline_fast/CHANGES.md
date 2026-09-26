# Fast pipeline: what changed since the reviewed upload

These scripts replace the patched copies that were here before. The originals the review looked at are still in
`../original_uploads/`. On the challenge data, all existing numbers are unchanged: the same 703 attempts, the same
outcomes, 1,317 + 141 reason-2 frames, 63 clients and 26 APs.

## Everything the review listed as still open is now covered

| Review item | Now |
|---|---|
| Only three alert types | `findings.csv` has one finding per problem and rolls up clients with the same problem at the same time under one parent. It covers 802.1X/EAP failures (EAP-Failure vs Identity loop, client answered vs AP side only), 4-way handshake failures (key trace such as `M1M2`, reason 15), join failures (e.g. AP full), deauth loops and floods, silent APs (beacon loss confirmed across sensors), congested channels and per-client probe storms. `airframe_alert.py` raises an alert for every warning-or-worse finding the narrated alerts don't already cover. |
| A client leaving counts as a failure | New outcome `client_left`: an early client deauth in a setup that was not stuck, unless the reason names a security failure. |
| "Try again later" (status 30) counts as a failure | New outcome `assoc_comeback`. It is not a failure. |
| Missed key messages followed by encrypted data | Encrypted data between client and AP closes the attempt as `success` with medium confidence. `timelines.csv` shows it as a `DATA_PROT` row, one per client/AP per 10 s. |
| WPA1 and WEP joins never reach "success" | WPA1 M4 (no Secure bit) is recognised. WEP joins succeed through the encrypted-data rule. |
| pcap only, no Prism | pcap, pcapng and gzipped versions of both. Link types 802.11, radiotap, Prism, AVS and PPI. |

## The same tests as the Wireshark-based pipeline

`python3 pipeline_fast/tests/check_fast.py` runs the fast engine through three sets of checks:

- the 16 generated scenarios;
- the same 16 scenarios with masking on: no raw MAC address or SSID may appear in any output;
- the 16 public captures.

Result: **48/48 pass** (`../results/fast_pipeline_tests.txt`). The public captures found five real gaps, all fixed:
- gzipped input;
- Prism headers;
- WPA1 M4;
- joins proven only by encrypted data;
- a client ending its own join with reason 1.

## Privacy

Identifiers are pseudonymised as they are parsed. This is the default; `--no-mask` keeps raw identifiers for internal debugging, and the report and dashboard then say so in their first line:
- MACs keep their vendor prefix, and the device half becomes a keyed hash of 40 bits. The earlier patch kept 24 bits, which risks two devices getting the same name at fleet size.
- SSIDs become `SSID-<hash>`.
- EAP identities are never read.

The salt comes from `$AIRFRAME_SALT` or `--salt-file`. With `--edge`, raw identifiers never leave the sensor stage. Every file in `../results/` is masked.

## Speed and scale

The 8 challenge captures (1,118,853 frames) take about 4.5 s on one core and 2.5 s on two, including the dashboard. That is about 250,000 frames/s per core, measured on a cloud VM; re-measure on the demo laptop.

The central stage is map/reduce, partitioned by client, so memory stays bounded at any fleet size:
- 96 sensors give the same result on 1 or 32 partitions;
- edge files are about 1,800x smaller than the captures (0.16 MB from 286 MB) and give identical results;
- worker processes also work under macOS's `spawn` start method.

## After the cross-check (`../CROSSCHECK_REPORT.md`)

| Cross-check item | Now |
|---|---|
| Masking off by default, and the report doesn't say so | Masked by default. `--no-mask` is the explicit opt-out, and the report's second line and the dashboard header then say "raw identifiers: do not share". `--mask` is still accepted by old scripts. |
| Two "cannot join" info findings are really the rejection wave | A join attempt ended before login by the same AP disconnect that is looping on that client now belongs to the loop finding. The wave finding says "2 further join attempts were cut short by the same disconnects before login started". |
| No co-channel-overlap or join-burst finding | Both are added with the Wireshark-based pipeline's rules. **Co-channel overlap:** BSSIDs are one AP only if they share a MAC block, a channel and not an SSID; a channel is flagged at 4 or more APs and at least 1.5x the median of the other channels. **Join burst:** at least 6 attempts per SSID per minute and at least 3x the usual rate. On the challenge data both engines now report channels 36 and 40 (5 APs each against 3) and the IoT-network burst (24 attempts from 24 clients in 2 minutes). The dashboard shows one channel-plan card; its alert is INFO because it is a re-plan item, not a page. |
| Probe-storm definitions differ | Kept on purpose: 10+ probe requests on one channel in 10 s is a misbehaving client. Clients rescanning after being kicked (up to 27 across all channels in 10 s here) are the fleet-level probe storm on the dashboard, not per-client findings. |
| Retry baseline 4.3% on the dashboard vs 4.5% in the pitch | The dashboard now takes the baseline from full minutes only, so it shows 4.5% to 9.5%, the same as the pitch. |

Re-run after these changes:
- 48/48 in `tests/check_fast.py`;
- 24/24 in the sample cases (`run_sample_cases.py` now runs the fast engine even when tshark isn't installed);
- all existing attempt, disconnect, incident, minute and client numbers identical on the challenge data.

Checked on a 2-core machine: 2.5 s on two cores, and 96 sensors (each real capture 12 times) give identical attempts and findings on 1 or 32 partitions, matching the 8-sensor run.
