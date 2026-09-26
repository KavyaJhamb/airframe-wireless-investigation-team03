"""
Eleven new sample cases for cross-checking both Airframe pipelines.

None of these is in either existing test suite. Each builds multi-sensor radiotap captures with scapy
(reusing the frame builders in pipeline_tshark/tests/scenarios.py) and returns the ground truth.

    python3 sample_cases.py OUT_DIR        # writes OUT_DIR/<case>/pcaps/*.pcap
"""
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "pipeline_tshark" / "tests"))

import scenarios as S  # noqa: E402
from scenarios import (Air, Node, beacon, beacons, deauth, join, key_msg, mgmt, protected_data,  # noqa: E402
                       probe_req, probe_resp)
from scapy.all import Dot11Beacon, Dot11Deauth, Dot11Elt  # noqa: E402

rng = random.Random(11)


class SkewAir(Air):
    """Like Air, but each sensor's clock can be offset (seconds) and can stop recording for a while."""

    def __init__(self, sensors, skew=None, gaps=None):
        super().__init__(sensors)
        self.skew, self.gaps = skew or {}, gaps or {}

    def emit(self, t, pkt, heard_by, rssi=-55):
        for s in heard_by:
            if any(a <= t < b for a, b in self.gaps.get(s, [])):
                continue
            super().emit(t + self.skew.get(s, 0.0), pkt, [s], rssi)


def ap(mac, ssid, ch):
    return Node(mac, ssid, ch)


# ------------------------------------------------------------------ 1
def partial_credential_reject(folder):
    """3 of 10 clients on an 802.1X network are refused (EAP-Failure), 7 log in. Not network-wide."""
    air = Air({"s36": 36, "s40": 40, "s44": 44})
    aps = [ap(f"00:0b:86:c1:00:0{i}", b"CorpNet", c) for i, c in enumerate([36, 40, 44])]
    for a in aps:
        beacons(air, a, [f"s{a.channel}"], 0, 200)
    bad = [Node(f"a4:83:e7:01:00:{i:02x}") for i in range(3)]
    good = [Node(f"a4:83:e7:01:01:{i:02x}") for i in range(7)]
    for i, c in enumerate(bad):
        a = aps[i % 3]
        for k in range(2):
            join(air, 5 + i * 2 + 60 * k, c, a, [f"s{a.channel}"], eap_mode="failure")
    for i, c in enumerate(good):
        a = aps[i % 3]
        join(air, 20 + i * 3, c, a, [f"s{a.channel}"], eap_mode="success")
    air.write(folder)
    return dict(bad=[c.mac for c in bad], good=[c.mac for c in good], ssids=[b"CorpNet"])


# ------------------------------------------------------------------ 2
def sensor_gap(folder):
    """Sensor sA stops recording from 120 s to 240 s. The APs keep beaconing (sB hears one of them)."""
    air = SkewAir({"sA": 1, "sB": 6}, gaps={"sA": [(120, 240)]})
    a1, a2, a3 = ap("00:0b:86:c2:00:01", b"Tools", 1), ap("00:0b:86:c2:00:02", b"Tools", 1), ap("00:0b:86:c2:00:03", b"Tools", 6)
    for a, s in [(a1, "sA"), (a2, "sA"), (a3, "sB")]:
        beacons(air, a, [s], 0, 360, interval=0.1024)
    air.write(folder)
    return dict(aps=[a1.mac, a2.mac, a3.mac], ssids=[b"Tools"])


# ------------------------------------------------------------------ 3
def clock_skew_same_channel(folder):
    """Two sensors on one channel hear the same EAP failures, but sB's clock runs 0.3 s behind."""
    air = SkewAir({"sA": 11, "sB": 11}, skew={"sB": 0.3})
    a = ap("00:0b:86:c3:00:01", b"CorpNet", 11)
    cl = Node("a4:83:e7:03:00:01")
    beacons(air, a, ["sA", "sB"], 0, 200)
    for k in range(3):
        join(air, 5 + 40 * k, cl, a, ["sA", "sB"], eap_mode="failure")
    air.write(folder)
    return dict(client=cl.mac, attempts=3, ssids=[b"CorpNet"])


# ------------------------------------------------------------------ 4
def spoofed_flood(folder):
    """200 deauths 'from the AP' in 10 s with random sequence numbers: an attacker, not the AP."""
    air = Air({"sA": 6})
    a = ap("00:0b:86:c4:00:01", b"Tools", 6)
    cl = Node("a4:83:e7:04:00:01")
    beacons(air, a, ["sA"], 0, 60)
    join(air, 2, cl, a, ["sA"])
    for i in range(200):
        pkt = mgmt(12, cl.mac, a.mac, a.mac, rng.randrange(4096) << 4) / Dot11Deauth(reason=7)
        air.emit(20 + i * 0.05, pkt, ["sA"])
    air.write(folder)
    return dict(client=cl.mac, ssids=[b"Tools"])


# ------------------------------------------------------------------ 5
def ping_pong_roam(folder):
    """A client roams back and forth between two APs every 20 s, always successfully. Not a failure."""
    air = Air({"sA": 36, "sB": 40})
    a1, a2 = ap("00:0b:86:c5:00:01", b"Tools", 36), ap("00:0b:86:c5:00:02", b"Tools", 40)
    beacons(air, a1, ["sA"], 0, 220)
    beacons(air, a2, ["sB"], 0, 220)
    cl = Node("a4:83:e7:05:00:01")
    join(air, 5, cl, a1, ["sA"])
    cur = a1
    for k in range(9):
        nxt = a2 if cur is a1 else a1
        join(air, 25 + 20 * k, cl, nxt, [f"s{'A' if nxt is a1 else 'B'}"], reassoc_from=cur)
        cur = nxt
    air.write(folder)
    return dict(client=cl.mac, roams=9, ssids=[b"Tools"])


# ------------------------------------------------------------------ 6
def hidden_ssid_wrong_psk(folder):
    """Hidden-SSID PSK network: one client joins, another keeps failing the key handshake (M2, no M3)."""
    air = Air({"sA": 44})
    a = ap("00:0b:86:c6:00:01", b"HiddenTools", 44)
    t = 0.0
    while t < 150:                          # hidden network: beacons carry an empty SSID
        air.emit(t, mgmt(8, S.BCAST, a.mac, a.mac, a.seq()) / Dot11Beacon(cap=0x0111) /
                 Dot11Elt(ID=0, info=b"") / Dot11Elt(ID=3, info=bytes([44])), ["sA"])
        t += 1.0
    ok, bad = Node("a4:83:e7:06:00:01"), Node("a4:83:e7:06:00:02")
    join(air, 5, ok, a, ["sA"])
    for k in range(3):
        te = join(air, 20 + 30 * k, bad, a, ["sA"], keys=(1, 2))
        air.emit(te + 1, deauth(a, bad, a, 15), ["sA"])
    air.write(folder)
    return dict(ok=ok.mac, bad=bad.mac, ssids=[b"HiddenTools"])


# ------------------------------------------------------------------ 7
def randomized_mac_timeout(folder):
    """A phone with a randomised (locally administered) MAC hits 802.1X timeouts."""
    air = Air({"sA": 48})
    a = ap("00:0b:86:c7:00:01", b"CorpNet", 48)
    cl = Node("da:a1:19:3c:4e:01")
    beacons(air, a, ["sA"], 0, 200)
    for k in range(2):
        join(air, 5 + 60 * k, cl, a, ["sA"], eap_mode="timeout")
    air.write(folder)
    return dict(client=cl.mac, ssids=[b"CorpNet"])


# ------------------------------------------------------------------ 8
def mixed_incident(folder):
    """Three problems at once: 802.1X outage on 4 APs, a loop on the PSK network, congestion on ch 44."""
    chans = [36, 40, 44, 48]
    air = Air({**{f"s{c}": c for c in chans}, "s149": 149})
    corp = [ap(f"00:0b:86:c8:00:0{i}", b"CorpNet", c) for i, c in enumerate(chans)]
    tools = ap("00:0b:86:c8:01:01", b"Tools", 149)
    for a in corp + [tools]:
        beacons(air, a, [f"s{a.channel}"], 0, 300)
    corp_clients = [Node(f"a4:83:e7:08:00:{i:02x}") for i in range(6)]
    for i, c in enumerate(corp_clients):
        a = corp[i % 4]
        for k in range(2):
            join(air, 5 + 3 * i + 100 * k, c, a, [f"s{a.channel}"], eap_mode="timeout", client_heard=False)
    looper = Node("b8:27:eb:08:00:01")
    join(air, 2, looper, tools, ["s149"])
    for k in range(15):
        air.emit(40 + 10 * k, deauth(tools, looper, tools, 2), ["s149"])
        join(air, 41 + 10 * k, looper, tools, ["s149"])
    iot = [Node(f"b8:27:eb:08:01:{i:02x}") for i in range(3)]
    for i, c in enumerate(iot):
        join(air, 10 + i, c, tools, ["s149"])
    busy = Node("a4:83:e7:08:02:01")
    join(air, 1, busy, corp[2], ["s44"], eap_mode="success")
    for i in range(360):
        air.emit(5 + 0.5 * i, protected_data(corp[2], busy, up=i % 2 == 0, retry=rng.random() < 0.4), ["s44"])
    air.write(folder)
    return dict(corp=[c.mac for c in corp_clients], looper=looper.mac, iot=[c.mac for c in iot],
                busy=busy.mac, congested=44, ssids=[b"CorpNet", b"Tools"])


# ------------------------------------------------------------------ 9
def eap_ok_handshake_timeout(folder):
    """802.1X login succeeds, then the key handshake stalls at M1 and the AP gives up (reason 15)."""
    air = Air({"sA": 36})
    a = ap("00:0b:86:c9:00:01", b"CorpNet", 36)
    cl = Node("a4:83:e7:09:00:01")
    beacons(air, a, ["sA"], 0, 120)
    for k in range(2):
        te = join(air, 5 + 40 * k, cl, a, ["sA"], eap_mode="success", keys=(1,))
        air.emit(te + 1.0, key_msg(a, cl, 1), ["sA"])
        air.emit(te + 2.0, deauth(a, cl, a, 15), ["sA"])
    air.write(folder)
    return dict(client=cl.mac, ssids=[b"CorpNet"])


# ------------------------------------------------------------------ 10
def already_connected_then_leaves(folder):
    """The client joined before the capture started: only encrypted data, then it leaves (reason 3)."""
    air = Air({"sA": 1})
    a = ap("00:0b:86:ca:00:01", b"Tools", 1)
    cl = Node("a4:83:e7:0a:00:01")
    beacons(air, a, ["sA"], 0, 90)
    for i in range(60):
        air.emit(1 + i, protected_data(a, cl, up=i % 2 == 0), ["sA"])
    air.emit(70, deauth(cl, a, a, 3), ["sA"])
    air.write(folder)
    return dict(client=cl.mac, ssids=[b"Tools"])


# ------------------------------------------------------------------ 11
def retry_mix_trap(folder):
    """Many clients scan at once. Probe responses are retried ~31% of the time (normal), data only ~1%.
    The all-frame retry rate jumps; nothing is wrong with the radio."""
    air = Air({"sA": 6})
    a = ap("00:0b:86:cb:00:01", b"Tools", 6)
    beacons(air, a, ["sA"], 0, 300, interval=0.1024)
    user = Node("a4:83:e7:0b:00:01")
    join(air, 2, user, a, ["sA"])
    for i in range(1100):
        air.emit(5 + 0.25 * i, protected_data(a, user, up=i % 2 == 0, retry=rng.random() < 0.01), ["sA"])
    scanners = [Node(f"a4:83:e7:0b:01:{i:02x}") for i in range(40)]
    for i in range(600):                     # a two-minute scan wave
        c = scanners[i % 40]
        t = 120 + i * 0.1
        air.emit(t, probe_req(c), ["sA"])
        r = probe_resp(a, c)
        if rng.random() < 0.31:
            r.FCfield |= S.RETRY
        air.emit(t + 0.002, r, ["sA"])
    air.write(folder)
    return dict(user=user.mac, ssids=[b"Tools"])


CASES = {f.__name__: f for f in [
    partial_credential_reject, sensor_gap, clock_skew_same_channel, spoofed_flood, ping_pong_roam,
    hidden_ssid_wrong_psk, randomized_mac_timeout, mixed_incident, eap_ok_handshake_timeout,
    already_connected_then_leaves, retry_mix_trap]}

if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample_pcaps")
    for name, fn in CASES.items():
        fn(out / name / "pcaps")
        print("wrote", out / name)
