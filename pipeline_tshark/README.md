# Airframe: header-only Wi-Fi fault finder

Three steps. Only step 1 ever sees raw MAC addresses or SSIDs.

```bash
pip install -r requirements.txt          # tshark must also be installed (it is on the hackathon image)

python extract.py --pcaps ./hackaton_airframe --out ./out   # ~2-3 min for the 8 sensors
python detect.py  --out ./out                               # ~10 s
streamlit run dashboard.py                                  # reads ./out
```

To find the masked label of a device you know: `python extract.py --lookup aa:bb:cc:dd:ee:ff`

## What each step does

**extract.py** runs tshark on every capture (.pcap, .pcapng, .cap, also gzipped) in parallel and keeps only 802.11 / 802.1X header
fields. Every MAC address and SSID is replaced with a salted SHA-256 hash (salt in
`.airframe_salt`; keep it private and out of the repo). EAP identities are never extracted.

**detect.py** merges all sensors per client, rebuilds every join attempt
(auth → assoc → EAP → key handshake → disconnect) and classifies it. Findings:

- 802.1X / EAP failures: client answered but never got EAP-Success, or no client reply captured
- 4-way handshake failures: stalled at M1 or M2 (M3 proves the AP accepted M2)
- Join failures: rejected, or stopped mid-flow
- Deauth / disassoc loops: repeated disconnects from the same AP; normal roams are recognised and never flagged
- Sticky clients: stays on a failing AP while other APs on the same network answer its probes
- Probe storms and join bursts (reconnect waves)
- Channel health: retries, beacon loss, silent APs, un-ACKed client frames, co-channel overlap
- Systemic roll-ups: the same failure on most clients of a network across many APs is reported
  once as a network-wide finding, with the individual clients grouped under it

**dashboard.py** shows the findings, a per-client timeline with one lane per sensor,
channel health and sensor coverage.

## Judgment calls built in

- One client is one finding per issue type, however many sensors saw it.
- A single deauth during a roam is normal. Loops need 4+ disconnects within 2 minutes.
- Retry share excludes beacons and probe responses. Probe responses are routinely retried
  when the scanning client has already left the channel, so counting them makes every channel
  look congested.
- Missing ACKs are only judged for client → AP frames. When a sensor cannot hear a client, the
  client's ACKs are invisible too, so "no ACK" would be a sensor blind spot, not a failure.
- Attempts where only the AP side was captured are tagged "AP side only".
- Encrypted data after a join proves the client got its keys, even if the sensor missed M3/M4.
- Not failures: a capture ending mid-join, a client that disconnects itself before login,
  and "come back later" (status 30, used by PMF-protected APs) followed by a successful join.
- Several disconnects per second is reported as a flood (typical of spoofed frames), not a loop.

All thresholds are constants at the top of `detect.py`.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests -v          # ~1 min, 56 tests
```

- **Real-world captures** (`test_public.py`): 16 public captures from the Wireshark and
  aircrack-ng test suites on GitHub, downloaded on first run (`python tests/public_captures.py`
  fetches them ahead of time). They cover radiotap, plain 802.11 and Prism headers; WEP, WPA2,
  PMF, WPA3-SAE, OWE, EAP-TLS and Suite-B; and quirks like invalid timestamps, missed key
  messages and a disassoc flood. Each has expectations based on its known content.
- **Synthetic scenarios** (`test_scenarios.py`, built by `tests/scenarios.py` with scapy): 16
  multi-sensor captures with exact ground truth, one per detector and judgment rule (roam vs
  loop, same event on two sensors, systemic roll-up, capture ending mid-join, ...).
- **Privacy** (`test_privacy.py`): no raw MAC address or SSID in any output file.
- **Dashboard** (`test_dashboard.py`): every tab renders on real and synthetic outputs.

Offline, the public tests skip themselves; without scapy, the scenario tests do.

## Outputs (in `out/`, all masked)

`findings.csv`, `attempts.csv`, `events.csv`, `channel_minutes.csv`, `aps.csv`, `clients.csv`,
`sensors.csv`, `roams.csv`, `summary.json`. `frames.csv.gz` and `addresses.csv` are the
masked extraction used by detect.py.
