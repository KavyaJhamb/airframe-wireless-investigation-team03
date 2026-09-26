"""
Synthetic multi-sensor captures with known ground truth.

Every scenario writes one folder of radiotap pcaps (one file per sensor) and returns the
MAC addresses / SSIDs it used, so tests can check exactly what the pipeline should find.
Requires scapy (pip install scapy).
"""
import random
import struct
from pathlib import Path

from scapy.all import (EAP, EAPOL, LLC, SNAP, Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth,
                       Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt, Dot11ProbeReq,
                       Dot11ProbeResp, Dot11ReassoReq, Dot11ReassoResp, PcapWriter, RadioTap, Raw)

BCAST = "ff:ff:ff:ff:ff:ff"
FREQ = {1: 2412, 6: 2437, 11: 2462, 36: 5180, 40: 5200, 44: 5220, 48: 5240, 149: 5745}
TO_DS, FROM_DS, RETRY, PROTECTED = 0x01, 0x02, 0x08, 0x40
T0 = 1_790_000_000.0
rng = random.Random(7)


class Node:
    def __init__(self, mac, ssid=b"", channel=None):
        self.mac, self.ssid, self.channel, self._seq = mac, ssid, channel, 0

    def seq(self):
        self._seq = (self._seq + 1) % 4096
        return self._seq << 4


class Air:
    """Collects the frames each sensor hears. emit() puts one transmission on the air."""

    def __init__(self, sensors: dict):
        self.sensors = sensors                   # name -> channel
        self.frames = {s: [] for s in sensors}

    def emit(self, t, pkt, heard_by, rssi=-55):
        for i, s in enumerate(heard_by):
            ch = self.sensors[s]
            rt = RadioTap(present="Flags+Channel+dBm_AntSignal", Flags=0,
                          ChannelFrequency=FREQ[ch], ChannelFlags=0x0140 if ch > 14 else 0x00A0,
                          dBm_AntSignal=rssi - 4 * i)
            p = rt / pkt
            p.time = T0 + t + i * 0.0012         # second sensor hears it 1.2 ms later
            self.frames[s].append(p)

    def write(self, folder: Path):
        folder.mkdir(parents=True, exist_ok=True)
        for s, frames in self.frames.items():
            frames.sort(key=lambda p: p.time)
            w = PcapWriter(str(folder / f"{s}.pcap"), linktype=127)
            for p in frames:
                w.write(p)
            w.close()


# ------------------------------------------------------------------ frame builders
def mgmt(sub, a1, a2, a3, sc, flags=0):
    return Dot11(type=0, subtype=sub, addr1=a1, addr2=a2, addr3=a3, SC=sc, FCfield=flags)


def beacon(ap):
    return mgmt(8, BCAST, ap.mac, ap.mac, ap.seq()) / Dot11Beacon(cap=0x0111) / \
        Dot11Elt(ID=0, info=ap.ssid) / Dot11Elt(ID=3, info=bytes([ap.channel]))


def probe_req(cl):
    return mgmt(4, BCAST, cl.mac, BCAST, cl.seq()) / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"")


def probe_resp(ap, cl):
    return mgmt(5, cl.mac, ap.mac, ap.mac, ap.seq()) / Dot11ProbeResp(cap=0x0111) / Dot11Elt(ID=0, info=ap.ssid)


def auth(frm, to, bssid, seqnum, status=0):
    return mgmt(11, to.mac, frm.mac, bssid.mac, frm.seq()) / Dot11Auth(algo=0, seqnum=seqnum, status=status)


def assoc_req(cl, ap):
    return mgmt(0, ap.mac, cl.mac, ap.mac, cl.seq()) / Dot11AssoReq(cap=0x0111, listen_interval=10) / \
        Dot11Elt(ID=0, info=ap.ssid)


def assoc_resp(ap, cl, status=0):
    return mgmt(1, cl.mac, ap.mac, ap.mac, ap.seq()) / Dot11AssoResp(cap=0x0111, status=status, AID=1)


def reassoc_req(cl, ap, old_ap):
    return mgmt(2, ap.mac, cl.mac, ap.mac, cl.seq()) / \
        Dot11ReassoReq(cap=0x0111, listen_interval=10, current_AP=old_ap.mac) / Dot11Elt(ID=0, info=ap.ssid)


def reassoc_resp(ap, cl, status=0):
    return mgmt(3, cl.mac, ap.mac, ap.mac, ap.seq()) / Dot11ReassoResp(cap=0x0111, status=status, AID=1)


def deauth(frm, to, bssid, reason):
    return mgmt(12, to.mac, frm.mac, bssid.mac, frm.seq()) / Dot11Deauth(reason=reason)


def disassoc(frm, to, bssid, reason):
    return mgmt(10, to.mac, frm.mac, bssid.mac, frm.seq()) / Dot11Disas(reason=reason)


def data_hdr(ap, cl, up, flags=0):
    if up:
        return Dot11(type=2, subtype=0, FCfield=TO_DS | flags, addr1=ap.mac, addr2=cl.mac,
                     addr3=ap.mac, SC=cl.seq())
    return Dot11(type=2, subtype=0, FCfield=FROM_DS | flags, addr1=cl.mac, addr2=ap.mac,
                 addr3=ap.mac, SC=ap.seq())


def eap(ap, cl, code, up):
    e = EAP(code=code, id=1, type=1) if code in (1, 2) else EAP(code=code, id=1)
    return data_hdr(ap, cl, up) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E) / \
        EAPOL(version=2, type=0) / e


def key_msg(ap, cl, n):
    """EAPOL-Key M1..M4 with the key-info bits Wireshark uses to number them."""
    info = {1: 0x008A, 2: 0x010A, 3: 0x13CA, 4: 0x030A}[n]
    nonce = bytes(rng.getrandbits(8) for _ in range(32)) if n in (1, 2, 3) else bytes(32)
    mic = bytes(16) if n == 1 else bytes(rng.getrandbits(8) for _ in range(16))
    kdata = b"" if n in (1, 4) else b"\x30\x14" + bytes(20)
    body = (struct.pack(">BHH", 2, info, 16) + struct.pack(">Q", 1 if n < 3 else 2) + nonce
            + bytes(16) + bytes(8) + bytes(8) + mic + struct.pack(">H", len(kdata)) + kdata)
    return data_hdr(ap, cl, up=n in (2, 4)) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / \
        SNAP(OUI=0, code=0x888E) / EAPOL(version=2, type=3, len=len(body)) / Raw(body)


def protected_data(ap, cl, up, retry=False):
    return data_hdr(ap, cl, up, PROTECTED | (RETRY if retry else 0)) / Raw(bytes(40))


def ack(ra):
    return Dot11(type=1, subtype=13, addr1=ra.mac)


# ------------------------------------------------------------------ building blocks
def beacons(air, ap, heard, start, end, interval=1.0, gaps=()):
    t = start
    while t < end:
        if not any(a <= t < b for a, b in gaps):
            air.emit(t, beacon(ap), heard, rssi=-50)
        t += interval


def join(air, t, cl, ap, heard, *, eap_mode=None, keys=(1, 2, 3, 4), assoc_status=0,
         client_heard=True, data=5, reassoc_from=None):
    """One join attempt. eap_mode: None (PSK), 'success', 'failure', 'timeout'.
    Returns the time the attempt ended."""
    up = heard if client_heard else []
    air.emit(t, auth(cl, ap, ap, 1), up)
    air.emit(t + 0.002, auth(ap, cl, ap, 2), heard)
    if reassoc_from:
        air.emit(t + 0.004, reassoc_req(cl, ap, reassoc_from), up)
        air.emit(t + 0.006, reassoc_resp(ap, cl, assoc_status), heard)
    else:
        air.emit(t + 0.004, assoc_req(cl, ap), up)
        air.emit(t + 0.006, assoc_resp(ap, cl, assoc_status), heard)
    t += 0.01
    if assoc_status != 0:
        return t
    if eap_mode:
        for i in range(3):
            air.emit(t, eap(ap, cl, 1, up=False), heard)
            if eap_mode != "timeout":
                air.emit(t + 0.002, eap(ap, cl, 2, up=True), up)
            t += 5 if eap_mode == "timeout" else 0.01
        if eap_mode == "failure":
            air.emit(t, eap(ap, cl, 4, up=False), heard)
        if eap_mode in ("failure", "timeout"):
            air.emit(t + 0.01, deauth(ap, cl, ap, 23), heard)
            return t + 0.01
        air.emit(t, eap(ap, cl, 3, up=False), heard)
        t += 0.01
    for n in keys:
        air.emit(t, key_msg(ap, cl, n), up if n in (2, 4) else heard)
        t += 0.003
    if 3 in keys:
        for i in range(data):
            air.emit(t + 0.05 * i, protected_data(ap, cl, up=i % 2 == 0), heard if i % 2 else up)
        t += 0.05 * data
    return t


def site(sensors, aps):
    """sensors: {name: channel}; aps: {name: (mac, ssid, channel)}"""
    air = Air(sensors)
    nodes = {k: Node(mac, ssid, ch) for k, (mac, ssid, ch) in aps.items()}
    return air, nodes


def ap_heard(air, ap):
    return [s for s, ch in air.sensors.items() if ch == ap.channel]


# ------------------------------------------------------------------ scenarios
def normal_roam(folder):
    air, n = site({"sA": 1, "sB": 6}, {"ap1": ("00:0b:86:10:00:00", b"Tools", 1),
                                      "ap2": ("00:0b:86:20:00:00", b"Tools", 6)})
    cl = Node("a4:83:e7:00:01:01")
    for ap in n.values():
        beacons(air, ap, ap_heard(air, ap), 0, 120)
    join(air, 5, cl, n["ap1"], ["sA"])
    air.emit(59.8, deauth(cl, n["ap1"], n["ap1"], 3), ["sA"])
    join(air, 60.0, cl, n["ap2"], ["sB"], reassoc_from=n["ap1"])
    air.write(folder)
    return dict(client=cl.mac, aps=[a.mac for a in n.values()], ssids=[b"Tools"])


def deauth_loop(folder):
    air, n = site({"sA": 36}, {"ap1": ("00:0b:86:30:00:00", b"Tools", 36)})
    cl = Node("a4:83:e7:00:02:01")
    beacons(air, n["ap1"], ["sA"], 0, 240)
    join(air, 2, cl, n["ap1"], ["sA"])
    for k in range(15):
        t = 30 + 10 * k
        air.emit(t, deauth(n["ap1"], cl, n["ap1"], 2), ["sA"])
        join(air, t + 1, cl, n["ap1"], ["sA"])
    air.write(folder)
    return dict(client=cl.mac, disconnects=15, aps=[n["ap1"].mac], ssids=[b"Tools"])


def single_deauth(folder):
    air, n = site({"sA": 36}, {"ap1": ("00:0b:86:31:00:00", b"Tools", 36)})
    cl = Node("a4:83:e7:00:03:01")
    beacons(air, n["ap1"], ["sA"], 0, 200)
    join(air, 2, cl, n["ap1"], ["sA"])
    air.emit(100, deauth(n["ap1"], cl, n["ap1"], 2), ["sA"])
    join(air, 101, cl, n["ap1"], ["sA"])
    air.write(folder)
    return dict(client=cl.mac, aps=[n["ap1"].mac], ssids=[b"Tools"])


def eap_failure(folder):
    air, n = site({"sA": 44}, {"ap1": ("00:0b:86:40:00:00", b"CorpNet", 44)})
    cl = Node("a4:83:e7:00:04:01")
    beacons(air, n["ap1"], ["sA"], 0, 200)
    for k in range(3):
        join(air, 5 + 40 * k, cl, n["ap1"], ["sA"], eap_mode="failure")
    air.write(folder)
    return dict(client=cl.mac, attempts=3, aps=[n["ap1"].mac], ssids=[b"CorpNet"])


def eap_timeout(folder):
    air, n = site({"sA": 44}, {"ap1": ("00:0b:86:41:00:00", b"CorpNet", 44)})
    cl = Node("a4:83:e7:00:05:01")
    beacons(air, n["ap1"], ["sA"], 0, 200)
    for k in range(3):
        join(air, 5 + 50 * k, cl, n["ap1"], ["sA"], eap_mode="timeout", client_heard=False)
    air.write(folder)
    return dict(client=cl.mac, attempts=3, aps=[n["ap1"].mac], ssids=[b"CorpNet"])


def wrong_psk(folder):
    air, n = site({"sA": 48}, {"ap1": ("00:0b:86:50:00:00", b"Tools", 48)})
    cl = Node("a4:83:e7:00:06:01")
    beacons(air, n["ap1"], ["sA"], 0, 120)
    for k in range(2):
        t = join(air, 5 + 30 * k, cl, n["ap1"], ["sA"], keys=(1, 2))
        air.emit(t + 1, key_msg(n["ap1"], cl, 1), ["sA"])
        air.emit(t + 1.003, key_msg(n["ap1"], cl, 2), ["sA"])
        air.emit(t + 2, deauth(n["ap1"], cl, n["ap1"], 15), ["sA"])
    air.write(folder)
    return dict(client=cl.mac, attempts=2, aps=[n["ap1"].mac], ssids=[b"Tools"])


def ap_full(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:60:00:00", b"Tools", 1)})
    cl = Node("a4:83:e7:00:07:01")
    beacons(air, n["ap1"], ["sA"], 0, 120)
    for k in range(3):
        join(air, 5 + 20 * k, cl, n["ap1"], ["sA"], assoc_status=17)
    air.write(folder)
    return dict(client=cl.mac, attempts=3, aps=[n["ap1"].mac], ssids=[b"Tools"])


def same_event_two_sensors(folder):
    """Two sensors on the same channel hear the same EAP failures: one client, one finding."""
    air, n = site({"sA": 11, "sB": 11}, {"ap1": ("00:0b:86:70:00:00", b"CorpNet", 11)})
    cl = Node("a4:83:e7:00:08:01")
    beacons(air, n["ap1"], ["sA", "sB"], 0, 200)
    for k in range(3):
        join(air, 5 + 40 * k, cl, n["ap1"], ["sA", "sB"], eap_mode="failure")
    air.write(folder)
    return dict(client=cl.mac, attempts=3, aps=[n["ap1"].mac], ssids=[b"CorpNet"])


def probe_storm(folder):
    air, n = site({"sA": 6}, {"ap1": ("00:0b:86:80:00:00", b"Tools", 6)})
    noisy, calm = Node("a4:83:e7:00:09:01"), Node("a4:83:e7:00:09:02")
    beacons(air, n["ap1"], ["sA"], 0, 60)
    for i in range(30):
        air.emit(10 + i * 0.16, probe_req(noisy), ["sA"])
        air.emit(10.01 + i * 0.16, probe_resp(n["ap1"], noisy), ["sA"])
    for i in range(3):
        air.emit(20 + i * 3, probe_req(calm), ["sA"])
    air.write(folder)
    return dict(noisy=noisy.mac, calm=calm.mac, aps=[n["ap1"].mac], ssids=[b"Tools"])


def silent_ap(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:90:00:00", b"Tools", 1),
                             "ap2": ("00:0b:86:91:00:00", b"Tools", 1)})
    beacons(air, n["ap1"], ["sA"], 0, 360, interval=0.1024)
    beacons(air, n["ap2"], ["sA"], 0, 360, interval=0.1024, gaps=[(120, 240)])
    air.write(folder)
    return dict(silent=n["ap2"].mac, healthy=n["ap1"].mac, aps=[n["ap1"].mac, n["ap2"].mac],
                ssids=[b"Tools"])


def congestion(folder):
    air, n = site({"sA": 6, "sB": 11}, {"ap1": ("00:0b:86:a0:00:00", b"Tools", 6),
                                       "ap2": ("00:0b:86:a1:00:00", b"Tools", 11)})
    c1, c2 = Node("a4:83:e7:00:0a:01"), Node("a4:83:e7:00:0a:02")
    for ap in n.values():
        beacons(air, ap, ap_heard(air, ap), 0, 200)
    join(air, 1, c1, n["ap1"], ["sA"])
    join(air, 1, c2, n["ap2"], ["sB"])
    for i in range(360):                      # 2 frames/s for 3 minutes
        t = 5 + i * 0.5
        air.emit(t, protected_data(n["ap1"], c1, up=i % 2 == 0, retry=rng.random() < 0.4), ["sA"])
        air.emit(t, protected_data(n["ap2"], c2, up=i % 2 == 0, retry=rng.random() < 0.02), ["sB"])
    air.write(folder)
    return dict(bad_channel=6, good_channel=11, aps=[a.mac for a in n.values()], ssids=[b"Tools"],
                clients=[c1.mac, c2.mac])


def systemic_8021x(folder):
    chans = [36, 40, 44, 48]
    air, n = site({f"s{c}": c for c in chans},
                  {**{f"corp{c}": (f"00:0b:86:b{i}:00:00", b"CorpNet", c) for i, c in enumerate(chans)},
                   "tools36": ("00:0b:86:b9:00:01", b"Tools", 36)})
    for ap in n.values():
        beacons(air, ap, ap_heard(air, ap), 0, 300)
    clients = [Node(f"a4:83:e7:00:0b:{i:02x}") for i in range(6)]
    for i, cl in enumerate(clients):
        ap = n[f"corp{chans[i % 4]}"]
        for k in range(2):
            join(air, 5 + i * 3 + 100 * k, cl, ap, ap_heard(air, ap), eap_mode="timeout",
                 client_heard=False)
    iot = [Node(f"b8:27:eb:00:0b:{i:02x}") for i in range(2)]
    for i, cl in enumerate(iot):
        join(air, 50 + i, cl, n["tools36"], ["s36"])
    air.write(folder)
    return dict(clients=[c.mac for c in clients], iot=[c.mac for c in iot],
                aps=[a.mac for a in n.values()], ssids=[b"CorpNet", b"Tools"])


def capture_ends_mid_join(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:c0:00:00", b"Tools", 1)})
    cl = Node("a4:83:e7:00:0c:01")
    beacons(air, n["ap1"], ["sA"], 0, 100)
    join(air, 95, cl, n["ap1"], ["sA"], keys=(1,))
    air.write(folder)
    return dict(client=cl.mac, aps=[n["ap1"].mac], ssids=[b"Tools"])


def client_left(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:d0:00:00", b"CorpNet", 1)})
    cl = Node("a4:83:e7:00:0d:01")
    beacons(air, n["ap1"], ["sA"], 0, 100)
    join(air, 5, cl, n["ap1"], ["sA"], keys=())
    air.emit(5.5, deauth(cl, n["ap1"], n["ap1"], 3), ["sA"])
    air.write(folder)
    return dict(client=cl.mac, aps=[n["ap1"].mac], ssids=[b"CorpNet"])


def assoc_comeback(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:e0:00:00", b"Tools", 1)})
    cl = Node("a4:83:e7:00:0e:01")
    beacons(air, n["ap1"], ["sA"], 0, 60)
    join(air, 5, cl, n["ap1"], ["sA"], assoc_status=30)
    join(air, 6, cl, n["ap1"], ["sA"], reassoc_from=n["ap1"])
    air.write(folder)
    return dict(client=cl.mac, aps=[n["ap1"].mac], ssids=[b"Tools"])


def disassoc_flood(folder):
    air, n = site({"sA": 1}, {"ap1": ("00:0b:86:f0:00:00", b"Tools", 1)})
    cl = Node("a4:83:e7:00:0f:01")
    beacons(air, n["ap1"], ["sA"], 0, 60)
    join(air, 2, cl, n["ap1"], ["sA"])
    for i in range(200):
        air.emit(10 + i * 0.1, disassoc(n["ap1"], cl, n["ap1"], 7), ["sA"])
    air.write(folder)
    return dict(client=cl.mac, aps=[n["ap1"].mac], ssids=[b"Tools"])


SCENARIOS = {f.__name__: f for f in [
    normal_roam, deauth_loop, single_deauth, eap_failure, eap_timeout, wrong_psk, ap_full,
    same_event_two_sensors, probe_storm, silent_ap, congestion, systemic_8021x,
    capture_ends_mid_join, client_left, assoc_comeback, disassoc_flood]}


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "scenario_pcaps")
    for name, fn in SCENARIOS.items():
        fn(out / name)
        print("wrote", out / name)
