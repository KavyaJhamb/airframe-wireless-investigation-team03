#!/usr/bin/env python3
"""
Airframe - step 2: detect.

Reads the masked table written by extract.py and produces findings:
  - 802.1X / EAP failures, 4-way handshake failures, join failures
  - deauth / disassoc loops (normal roams are recognised and NOT flagged)
  - probe storms, join bursts, sticky clients
  - co-channel overlap, congestion, beacon loss / silent APs
  - systemic roll-ups when one failure hits most of a network

Frames from all sensors are merged per client first, so one client is one
finding per issue type, with every sensor that saw part of it listed as evidence.

Usage:  python detect.py --out ./out
"""
import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

# ------------------------------------------------------------------ tunables
DEDUP_WINDOW_S = 1.0       # same frame (same addresses, type and sequence number) heard by 2 sensors or
                           # retransmitted; 1 s also absorbs clock skew between sensors
ROAM_WINDOW_S = 10         # disconnect + join to a different AP within this = roam
LOOP_MIN_EVENTS = 4        # >= this many disconnects ...
LOOP_WINDOW_S = 120        # ... within this window = loop
PROBE_WINDOW_S = 10
PROBE_STORM_MIN = 15       # probe requests from one client in PROBE_WINDOW_S
JOIN_BURST_MIN = 6         # join attempts per SSID per minute, lower bound
IN_PROGRESS_S = 60         # attempt still open this close to capture end = in progress
BEACON_INTERVAL_S = 0.1024
BEACON_LOSS_ALERT = 0.20
SILENT_AP_SHARE = 0.20     # < 20% of expected beacons in a minute = AP silent
RETRY_ALERT = 0.20
UNACKED_ALERT = 0.20
MIN_FRAMES_FOR_RATE = 20
SYSTEMIC_SHARE = 0.5       # share of an SSID's clients failing the same way
SYSTEMIC_MIN_APS = 3
GAP_S = 5.0                # a sensor that records nothing for this long has a capture gap
AUTH_FAIL_REASONS = {14, 15, 23}  # counted as login failures, not as loops

REASON = {1: "unspecified", 2: "previous authentication no longer valid",
          3: "station leaving", 4: "inactivity", 5: "AP overloaded",
          6: "class 2 frame from non-authenticated station",
          7: "class 3 frame from non-associated station", 8: "station leaving BSS",
          14: "MIC failure", 15: "4-way handshake timeout",
          16: "group key handshake timeout", 23: "802.1X authentication failed",
          34: "too many unacknowledged frames (poor channel)"}
STATUS = {1: "unspecified failure", 12: "denied, other reason", 13: "auth algorithm not supported",
          15: "challenge failure", 17: "AP full", 30: "temporarily rejected", 53: "invalid PMKID"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FAILURE_OUTCOMES = {
    "auth_rejected": "Join failure", "assoc_rejected": "Join failure",
    "stalled_after_auth": "Join failure", "stalled_after_assoc": "Join failure",
    "incomplete": "Join failure",
    "eap_failed": "802.1X / EAP failure", "eap_no_response": "802.1X / EAP failure",
    "handshake_failed": "4-way handshake failure",
}
STR_COLS = ["sensor", "ta", "ra", "bssid", "ssid"]
ATT_COLS = ["attempt_id", "client", "bssid", "start", "end", "outcome", "auth_ok", "auth_fail",
            "assoc_ok", "assoc_fail", "eap_req", "eap_resp", "eap_success", "keys", "end_type",
            "end_reason", "end_dir", "client_heard", "sensors", "reassoc"]
DIS_COLS = ["client", "bssid", "ts", "kind", "reason", "direction", "sensors", "attempt_id"]
FINDING_COLS = ["id", "severity", "category", "title", "explanation", "client", "ap", "ssid",
                "sensors", "channels", "start_ts", "end_ts", "count", "parent", "tags", "related"]
DATA_EVIDENCE_MIN = 3      # protected data frames after a join = the client got its keys


def reason_text(code) -> str:
    if code is None or (isinstance(code, float) and math.isnan(code)):
        return "no reason code"
    code = int(code)
    return f"reason {code}: {REASON.get(code, 'other')}"


def fmt_dur(seconds: float) -> str:
    return f"{seconds:.0f} s" if seconds < 120 else f"{seconds / 60:.1f} min"


def isnum(x) -> bool:
    return x is not None and not (isinstance(x, float) and math.isnan(x))


# ------------------------------------------------------------------ loading
def load(out: Path):
    f = pd.read_csv(out / "frames.csv.gz", dtype={c: "object" for c in STR_COLS})
    for c in STR_COLS:
        f[c] = f[c].fillna("").astype(str)
    addresses = pd.read_csv(out / "addresses.csv", dtype={"addr": str, "radio": str})
    addresses["vendor"] = addresses["vendor"].fillna("")
    return f, addresses


def is_unicast(s: pd.Series) -> pd.Series:
    return (s != "") & (s != "BROADCAST") & (s != "MULTICAST")


# ------------------------------------------------------------------ inventory
def build_inventory(f: pd.DataFrame, addresses: pd.DataFrame):
    """APs = addresses that transmit as their own BSSID. Everything else unicast = client."""
    ap_tx = f[(f.ta != "") & (f.ta == f.bssid)]
    ap_set = set(ap_tx.bssid) | set(f.loc[f.subtype == 8, "bssid"])
    ap_set -= {"", "BROADCAST", "MULTICAST"}
    cand = set(f.ta[is_unicast(f.ta)]) | set(f.ra[is_unicast(f.ra)])
    clients = cand - ap_set

    radio = addresses.set_index("addr")["radio"].to_dict()
    vendor = addresses.set_index("addr")["vendor"].to_dict()
    rand = addresses.set_index("addr")["randomized"].to_dict()

    # SSIDs, labelled by how common they are; auth type from what we see on them
    bss_ssid = (f[(f.subtype.isin([5, 8])) & (f.ssid != "") & f.bssid.isin(ap_set)]
                .groupby("bssid").ssid.agg(lambda s: s.value_counts().index[0]))
    ssid_rank = f[f.subtype == 8].ssid.value_counts()
    ssid_label = {s: f"SSID-{i + 1}" for i, s in enumerate(ssid_rank.index) if s}
    eap_bss = set(f.loc[(f.eapol_type == 0) | f.eap_code.notna(), "bssid"])
    key_bss = set(f.loc[f.key_msg.notna(), "bssid"])
    ssid_auth = {}
    for s in ssid_label:
        members = set(bss_ssid[bss_ssid == s].index)
        ssid_auth[s] = "802.1X" if members & eap_bss else ("PSK" if members & key_bss else "open/unknown")

    # AP inventory, one row per BSS; physical AP = same radio token
    ap_frames = f[f.bssid.isin(ap_set)]
    inv = (ap_frames.groupby("bssid")
           .agg(channel=("channel", lambda s: s.mode().iloc[0] if s.notna().any() else np.nan),
                sensors=("sensor", lambda s: ";".join(sorted(s.unique()))),
                beacons=("subtype", lambda s: int((s == 8).sum())),
                rssi_median=("rssi", "median"), first_ts=("ts", "min"), last_ts=("ts", "max"))
           .reset_index())
    inv["ssid"] = inv.bssid.map(bss_ssid).fillna("")
    # BSSIDs are grouped into one physical radio only if they share a MAC block (first 5 bytes) AND a channel
    # AND advertise different SSIDs. Consecutive MACs on different channels are different APs.
    chan_txt = inv.channel.map(lambda c: "?" if pd.isna(c) else str(int(c)))  # NaN-safe on pandas 2 and 3
    inv["radio"] = inv.bssid.map(radio).fillna(inv.bssid).astype(str) + "|" + chan_txt
    dup = inv.duplicated(["radio", "ssid"], keep=False)
    inv.loc[dup, "radio"] = inv.loc[dup, "bssid"]
    radios = (inv.groupby("radio").channel.min().sort_values(kind="stable").index)
    ap_label = {r: f"AP-{i + 1:02d}" for i, r in enumerate(radios)}
    inv["ap"] = inv.radio.map(ap_label)
    inv["ssid_label"] = inv.ssid.map(ssid_label).fillna("hidden")
    inv["auth"] = inv.ssid.map(ssid_auth).fillna("unknown")
    inv["bss"] = inv.ap + "/" + inv.ssid_label

    client_label = {c: f"C-{c[:6]}" for c in clients}
    meta = dict(ap_set=ap_set, clients=clients, client_label=client_label,
                bss_label=inv.set_index("bssid").bss.to_dict(),
                bss_ap=inv.set_index("bssid").ap.to_dict(),
                bss_ssid=inv.set_index("bssid").ssid_label.to_dict(),
                bss_channel=inv.set_index("bssid").channel.to_dict(),
                ssid_label=ssid_label, ssid_auth=ssid_auth,
                ssid_auth_by_label={ssid_label[s]: a for s, a in ssid_auth.items()},
                vendor=vendor, randomized=rand)
    return inv, meta


# ------------------------------------------------------------------ events
def client_events(f: pd.DataFrame, meta) -> pd.DataFrame:
    """Join / login / key / disconnect / probe frames per client, merged across sensors."""
    clients = meta["clients"]
    ta_c, ra_c = f.ta.isin(clients), f.ra.isin(clients)
    f = f.assign(client=np.where(ta_c, f.ta, np.where(ra_c, f.ra, "")),
                 direction=np.where(ta_c, "up", np.where(ra_c, "down", "")))
    relevant = (f.subtype.isin([0, 1, 2, 3, 4, 10, 11, 12]) | (f.eapol_type == 0)
                | f.eap_code.notna() | f.key_msg.notna())
    ev = f[relevant & (f.client != "")].copy()
    for c in ["seq", "key_msg", "eap_code"]:
        ev[c + "_k"] = ev[c].fillna(-1)
    keys = ["client", "ta", "ra", "subtype", "seq_k", "key_msg_k", "eap_code_k"]
    ev = ev.sort_values(keys + ["ts"], kind="stable")
    same = (ev[keys].shift() == ev[keys]).all(axis=1) & (ev.ts.diff() < DEDUP_WINDOW_S)
    ev["gid"] = (~same).cumsum()
    first_cols = ["client", "direction", "ta", "ra", "bssid", "subtype", "seq", "reason",
                  "status", "auth_seq", "eapol_type", "eap_code", "key_msg", "channel", "ssid"]
    g = ev.groupby("gid")
    merged = g[first_cols].first()
    merged["ts"] = g.ts.min()
    merged["rssi"] = g.rssi.max()
    merged["retry_seen"] = g.retry.any()
    merged["sensors"] = g.sensor.agg(lambda s: ";".join(sorted(s.unique())))
    merged["copies"] = g.size()
    return merged.sort_values(["client", "ts"], kind="stable").reset_index(drop=True)


# ------------------------------------------------------------------ attempts
def new_attempt(aid, client, r):
    return dict(attempt_id=aid, client=client, bssid=r.bssid, start=r.ts, end=r.ts, stage=0,
                auth_req=0, auth_ok=False, auth_fail=None, assoc_req=0, assoc_ok=False,
                assoc_fail=None, eap_req=0, eap_resp=0, eap_success=False, eap_failure=False,
                keys=set(), end_type="capture_end", end_reason=None, end_dir="",
                sensors=set(), client_heard=False, reassoc=False)


def update_attempt(a, r):
    a["end"] = r.ts
    a["sensors"].update(r.sensors.split(";"))
    if r.direction == "up":
        a["client_heard"] = True
    st = r.subtype
    if st == 11:
        a["stage"] = max(a["stage"], 1)
        if r.direction == "up":
            a["auth_req"] += 1
        elif isnum(r.status):
            if r.status == 0:
                a["auth_ok"] = True
            else:
                a["auth_fail"] = int(r.status)
    elif st in (0, 2):
        a["stage"] = max(a["stage"], 2)
        a["assoc_req"] += 1
        a["reassoc"] |= st == 2
    elif st in (1, 3):
        a["stage"] = max(a["stage"], 2)
        a["reassoc"] |= st == 3
        if isnum(r.status):
            if r.status == 0:
                a["assoc_ok"] = True
            else:
                a["assoc_fail"] = int(r.status)
    if isnum(r.eap_code):
        a["stage"] = max(a["stage"], 3)
        code = int(r.eap_code)
        if code == 1:
            a["eap_req"] += 1
        elif code == 2:
            a["eap_resp"] += 1
        elif code == 3:
            a["eap_success"] = True
        elif code == 4:
            a["eap_failure"] = True
    if isnum(r.key_msg):
        a["stage"] = 4
        a["keys"].add(int(r.key_msg))


def classify(a, capture_end, auth_type):
    if a["auth_fail"] is not None:
        return "auth_rejected"
    if a["assoc_fail"] is not None:
        return "assoc_rejected"
    keys, reason = a["keys"], a["end_reason"]
    if 3 in keys or 4 in keys:
        return "connected"      # AP only sends M3 after a valid M2
    if (a["end_type"] == "capture_end" and capture_end - a["end"] < IN_PROGRESS_S
            and not a["eap_failure"]):
        return "in_progress"    # capture ended mid-flow: no verdict possible
    if (a["end_type"] in ("deauth", "disassoc") and a["end_dir"] == "up"
            and reason in (None, 3, 8) and a["stage"] < 3):
        return "client_left"    # the client ended it before login started: not a failure
    if a["eap_failure"] or reason == 23:
        return "eap_failed" if a["eap_resp"] else "eap_no_response"
    if keys or reason in (14, 15) or a["eap_success"]:
        return "handshake_failed"
    if a["eap_req"]:
        return "eap_failed" if a["eap_resp"] else "eap_no_response"
    if a["assoc_ok"]:
        return "connected" if auth_type == "open/unknown" else "stalled_after_assoc"
    if a["auth_ok"]:
        return "stalled_after_auth"
    return "incomplete"


def reconstruct(ev: pd.DataFrame, meta, capture_end: float):
    attempts, disconnects = [], []
    aid = 0
    join_ev = ev[ev.subtype != 4]
    for client, g in join_ev.groupby("client", sort=False):
        cur = None
        for r in g.itertuples(index=False):
            st = r.subtype
            is_login = isnum(r.eap_code) or isnum(r.key_msg)
            if st in (10, 12):
                disconnects.append(dict(client=client, bssid=r.bssid, ts=r.ts,
                                        kind="deauth" if st == 12 else "disassoc",
                                        reason=r.reason, direction=r.direction,
                                        sensors=r.sensors,
                                        attempt_id=cur["attempt_id"] if cur and cur["bssid"] == r.bssid else None))
                if cur and cur["bssid"] == r.bssid:
                    update_attempt(cur, r)
                    cur["end_type"] = disconnects[-1]["kind"]
                    cur["end_reason"] = int(r.reason) if isnum(r.reason) else None
                    cur["end_dir"] = r.direction
                    attempts.append(cur)
                    cur = None
                continue
            start_new = False
            if cur is None or cur["bssid"] != r.bssid:
                start_new = st in (0, 1, 2, 3, 11) or is_login
            elif st == 11 and cur["stage"] >= 2:
                start_new = True
            elif st in (0, 2) and cur["stage"] >= 2:
                start_new = True
            elif st in (1, 3) and cur["assoc_ok"] and cur["stage"] >= 2:
                start_new = True
            if start_new:
                if cur:
                    cur["end_type"] = "superseded"
                    attempts.append(cur)
                aid += 1
                cur = new_attempt(aid, client, r)
            if cur is not None:
                update_attempt(cur, r)
        if cur:
            attempts.append(cur)

    rows = []
    for a in attempts:
        auth_type = meta["ssid_auth_by_label"].get(meta["bss_ssid"].get(a["bssid"], ""), "unknown")
        outcome = classify(a, capture_end, auth_type)
        keys = "".join(f"M{k}" for k in sorted(a["keys"]))
        rows.append(dict(attempt_id=a["attempt_id"], client=a["client"], bssid=a["bssid"],
                         start=a["start"], end=a["end"], outcome=outcome,
                         auth_ok=a["auth_ok"], auth_fail=a["auth_fail"], assoc_ok=a["assoc_ok"],
                         assoc_fail=a["assoc_fail"], eap_req=a["eap_req"], eap_resp=a["eap_resp"],
                         eap_success=a["eap_success"], keys=keys, end_type=a["end_type"],
                         end_reason=a["end_reason"], end_dir=a["end_dir"],
                         client_heard=a["client_heard"], sensors=";".join(sorted(a["sensors"])),
                         reassoc=a["reassoc"]))
    att = pd.DataFrame(rows, columns=ATT_COLS)
    dis = pd.DataFrame(disconnects, columns=DIS_COLS)
    return att, dis


def apply_data_evidence(att: pd.DataFrame, f: pd.DataFrame, meta, capture_end: float):
    """Sensors miss frames. If protected (encrypted) data flows between client and AP after an
    attempt, the client obviously has keys, whatever key messages the sensor missed."""
    att = att.copy()
    att["data_frames"] = 0
    if att.empty:
        return att
    data = f[f.subtype.between(0x20, 0x2F) & f.protected]
    if data.empty:
        return att
    cl = meta["clients"]
    data = data.assign(client=np.where(data.ta.isin(cl), data.ta, np.where(data.ra.isin(cl), data.ra, "")))
    data = data[data.client != ""]
    times = {k: np.sort(g.ts.values) for k, g in data.groupby(["client", "bssid"])}
    att = att.sort_values(["client", "start"])
    nxt = att.groupby("client").start.shift(-1).fillna(capture_end)
    for i, r in att.iterrows():
        t = times.get((r.client, r.bssid))
        if t is None:
            continue
        end = r.end if r.end_type in ("deauth", "disassoc") else nxt[i]
        n = int(np.searchsorted(t, end, side="right") - np.searchsorted(t, r.start, side="left"))
        att.at[i, "data_frames"] = n
        if n >= DATA_EVIDENCE_MIN and r.outcome not in ("connected", "auth_rejected", "assoc_rejected"):
            att.at[i, "outcome"] = "connected"
    return att.sort_index()


def mark_comebacks(att: pd.DataFrame, window: float = 30) -> pd.DataFrame:
    """Status 30 ('temporarily rejected, try later') is how PMF-protected APs make a client
    wait for an SA Query. Followed by a successful join it is expected behaviour."""
    att = att.copy()
    for i, r in att[(att.assoc_fail == 30) | (att.auth_fail == 30)].iterrows():
        later = att[(att.client == r.client) & (att.bssid == r.bssid) & (att.start > r.start)
                    & (att.start - r.start <= window) & (att.outcome == "connected")]
        if len(later):
            att.at[i, "outcome"] = "assoc_comeback"
    return att


def mark_roams(att: pd.DataFrame, dis: pd.DataFrame):
    """A disconnect followed (or preceded) by a join to a different AP within
    ROAM_WINDOW_S is a roam: expected behaviour, never flagged as a failure."""
    dis = dis.copy()
    dis["roam"] = False
    att = att.copy()
    att["roamed_to"] = ""
    if att.empty:
        return att, dis, pd.DataFrame(columns=["client", "ts", "from_bssid", "to_bssid", "via", "sensors"])
    starts = att.groupby("client")
    roams = []
    for i, d in dis.iterrows():
        if d.client not in starts.groups:
            continue
        a = starts.get_group(d.client)
        near = a[(a.bssid != d.bssid) & (abs(a.start - d.ts) <= ROAM_WINDOW_S)]
        if len(near):
            dis.at[i, "roam"] = True
            roams.append(dict(client=d.client, ts=d.ts, from_bssid=d.bssid,
                              to_bssid=near.iloc[0].bssid, via=d.kind, sensors=d.sensors))
    # AP change between two attempts without any disconnect frame
    for client, a in starts:
        a = a.sort_values("start")
        for prev, nxt in zip(a.itertuples(), a.iloc[1:].itertuples()):
            if (prev.bssid != nxt.bssid and prev.outcome == "connected"
                    and (nxt.start - prev.end <= ROAM_WINDOW_S or nxt.reassoc)
                    and prev.end_type == "superseded"):
                att.loc[att.attempt_id == prev.attempt_id, "roamed_to"] = nxt.bssid
                roams.append(dict(client=client, ts=nxt.start, from_bssid=prev.bssid,
                                  to_bssid=nxt.bssid, via="reassociation",
                                  sensors=f"{prev.sensors};{nxt.sensors}"))
    return att, dis, pd.DataFrame(roams)


# ------------------------------------------------------------------ findings helpers
class Findings:
    def __init__(self):
        self.rows = []

    def add(self, severity, category, title, explanation, client="", ap="", ssid="",
            sensors="", channels="", start=np.nan, end=np.nan, count=0, parent="", tags=""):
        fid = f"F{len(self.rows) + 1:03d}"
        self.rows.append(dict(id=fid, severity=severity, category=category, title=title,
                              explanation=explanation, client=client, ap=ap, ssid=ssid,
                              sensors=sensors, channels=channels, start_ts=start, end_ts=end,
                              count=count, parent=parent, tags=tags))
        return fid

    def frame(self):
        df = pd.DataFrame(self.rows)
        if df.empty:
            return pd.DataFrame(columns=FINDING_COLS)
        # link every finding to the other findings about the same client
        by_client = df[df.client != ""].groupby("client").id.agg(list).to_dict()
        df["related"] = [";".join(i for i in by_client.get(c, []) if i != fid) if c else ""
                         for c, fid in zip(df.client, df.id)]
        df["sev_rank"] = df.severity.map(SEVERITY_ORDER)
        return df.sort_values(["sev_rank", "category", "count"], ascending=[True, True, False]).drop(columns="sev_rank")


def join_sensors(values) -> str:
    out = set()
    for v in values:
        if v:
            out.update(str(v).split(";"))
    return ";".join(sorted(out))


def other_aps(meta, probe_answers, client, bssids) -> set:
    """APs (not this one) broadcasting the same SSID that answered the client's probes."""
    ssids = {meta["bss_ssid"].get(b) for b in bssids}
    mine = {meta["bss_ap"].get(b) for b in bssids}
    return {meta["bss_ap"].get(b) for b in probe_answers.get(client, set())
            if meta["bss_ssid"].get(b) in ssids} - mine


def windows(t: np.ndarray, window: float, min_events: int):
    """Episodes of >= min_events within `window` seconds. Returns list of index arrays."""
    t = np.sort(t)
    marked = np.zeros(len(t), dtype=bool)
    for i in range(len(t)):
        j = np.searchsorted(t, t[i] + window, side="right")
        if j - i >= min_events:
            marked[i:j] = True
    episodes, cur = [], []
    for i in np.where(marked)[0]:
        if cur and t[i] - t[cur[-1]] > window:
            episodes.append(np.array(cur))
            cur = []
        cur.append(i)
    if cur:
        episodes.append(np.array(cur))
    return t, episodes


def max_in_window(t: np.ndarray, window: float) -> int:
    t = np.sort(t)
    if len(t) == 0:
        return 0
    j = np.searchsorted(t, t + window, side="left")
    return int((j - np.arange(len(t))).max())


# ------------------------------------------------------------------ detectors
def detect_client_failures(att, meta, F: Findings, probe_answers):
    lab, apl, ssl = meta["client_label"], meta["bss_ap"], meta["bss_ssid"]
    ids = {}
    fails = att[att.outcome.isin(FAILURE_OUTCOMES)]
    for (client, cat), g in fails.groupby(["client", fails.outcome.map(FAILURE_OUTCOMES)]):
        mine = att[att.client == client]
        n_ok = int((mine.outcome == "connected").sum())
        aps = sorted({apl.get(b, "?") for b in g.bssid})
        ssids = sorted({ssl.get(b, "?") for b in g.bssid})
        sensors = join_sensors(g.sensors)
        heard = g.client_heard.any()
        n = len(g)
        c = lab[client]
        where = f"{', '.join(aps)} ({', '.join(ssids)})"
        if cat == "802.1X / EAP failure":
            answered = int((g.outcome == "eap_failed").sum())
            if answered:
                why = (f"The client answered the AP's EAP requests in {answered} of them but never got "
                       "EAP-Success, and the AP ended with reason 23 (802.1X authentication failed). "
                       "The radio link works; the login itself is rejected or never completes "
                       "(credentials, certificate or authentication server).")
            else:
                why = ("The AP kept sending EAP identity requests, no reply from the client was captured, "
                       "and the AP gave up with reason 23 (802.1X authentication failed). Either the "
                       "client's supplicant is not answering, or the sensors cannot hear this client "
                       "(only the AP side of the exchange was captured).")
            title = f"{c}: 802.1X login failed {n}x on {where}"
        elif cat == "4-way handshake failure":
            stalls = g["keys"].value_counts().to_dict()
            detail = ", ".join(f"{k or 'no key msgs'} x{v}" for k, v in stalls.items())
            reasons = {int(x) for x in g.end_reason.dropna()}
            why = (f"Key handshake stalled before M3 ({detail}"
                   f"{'; ' + ', '.join(reason_text(x) for x in sorted(reasons)) if reasons else ''}). "
                   "M1 without M2 = client never answered (or not heard); M2 without M3 = AP rejected "
                   "the client's key (wrong passphrase / MIC failure).")
            title = f"{c}: 4-way handshake failed {n}x on {where}"
        else:
            parts = g.outcome.value_counts().to_dict()
            codes = [STATUS.get(int(s), f"status {int(s)}") for s in
                     pd.concat([g.auth_fail, g.assoc_fail]).dropna().unique()]
            why = (f"Join attempts stopped mid-flow ({', '.join(f'{k.replace('_', ' ')} x{v}' for k, v in parts.items())})"
                   f"{'; AP answered: ' + ', '.join(codes) if codes else ''}.")
            title = f"{c}: {n} join attempts failed on {where}"
        tags = []
        if not heard:
            tags.append("AP side only")
            if cat != "802.1X / EAP failure":
                why += " Only AP-side frames were captured for this client."
        others = other_aps(meta, probe_answers, client, set(g.bssid))
        tried_other = att[(att.client == client) & ~att.bssid.isin(g.bssid)].shape[0] > 0
        if n_ok == 0 and others and not tried_other and cat != "802.1X / EAP failure":
            why += (f" Sticky: it never tried any of the {len(others)} other APs on the same "
                    "network that answered its probes.")
            tags.append("sticky")
        sev = "high" if n_ok == 0 else "medium"
        fid = F.add(sev, cat, title, f"{n} failed attempt(s), {n_ok} successful. " + why,
                    client=c, ap=", ".join(aps), ssid=", ".join(ssids), sensors=sensors,
                    start=g.start.min(), end=g.end.max(), count=n, tags=";".join(tags))
        ids[(client, cat)] = fid
    return ids


def detect_loops(dis, meta, F: Findings, probe_answers, att):
    lab, apl = meta["client_label"], meta["bss_ap"]
    loops, interrupted = [], set()
    if dis.empty:
        return loops, interrupted
    cand = dis[~dis.roam & ~dis.reason.isin(list(AUTH_FAIL_REASONS))]
    for (client, bssid), g in cand.groupby(["client", "bssid"]):
        g = g.sort_values("ts")
        t, eps = windows(g.ts.values, LOOP_WINDOW_S, LOOP_MIN_EVENTS)
        for idx in eps:
            sub = g.iloc[idx]
            dur = sub.ts.max() - sub.ts.min()
            period = float(np.median(np.diff(sub.ts.values))) if len(sub) > 1 else 0
            kinds = sub.kind.value_counts().to_dict()
            reasons = sorted({int(x) for x in sub.reason.dropna()})
            rtxt = ", ".join(reason_text(x) for x in reasons) or "no reason code"
            from_ap = (sub.direction == "down").mean() >= 0.5
            c, a = lab[client], apl.get(bssid, "?")
            tried_other = att[(att.client == client) & (att.bssid != bssid)].shape[0] > 0
            others = other_aps(meta, probe_answers, client, {bssid})
            interrupted.update(int(x) for x in sub.attempt_id.dropna())
            expl = (f"{'The AP sent' if from_ap else 'The client sent'} "
                    f"{' + '.join(f'{v} {k}' for k, v in kinds.items())} ({rtxt}) "
                    f"over {fmt_dur(dur)}, about every {period:.1f} s. A single disconnect (e.g. during a "
                    "roam) is normal; this repetition is a loop.")
            if period < 1:
                expl += (" Several disconnects per second is typical of a deauth/disassoc flood "
                         "(spoofed frames from an attack or test tool), not of normal AP behaviour.")
            elif 2 in reasons or 6 in reasons or 7 in reasons:
                expl += (" Reason 2/6/7 means the AP no longer recognises the client's session while the "
                         "client still behaves as if connected: a state mismatch between client and AP.")
            sticky = not tried_other and len(others) >= 1
            if sticky:
                expl += (f" Sticky: the client never tried any of the {len(others)} other APs on the same "
                         "network that answered its probe requests.")
            fid = F.add("high", "Deauth / disassoc loop",
                        f"{c}: disconnect loop on {a} ({len(sub)}x, every ~{period:.0f} s)" if period >= 1
                        else f"{c}: disconnect flood on {a} ({len(sub)}x in {fmt_dur(dur)})", expl,
                        client=c, ap=a, ssid=meta["bss_ssid"].get(bssid, ""),
                        sensors=join_sensors(sub.sensors), start=sub.ts.min(), end=sub.ts.max(),
                        count=len(sub), tags="sticky" if sticky else "")
            loops.append(dict(client=client, bssid=bssid, fid=fid, count=len(sub), start=sub.ts.min(),
                              end=sub.ts.max(), reasons=reasons))
    return loops, interrupted


def detect_probe_storms(ev, meta, F: Findings):
    pr = ev[ev.subtype == 4]
    rows = []
    for client, g in pr.groupby("client"):
        peak = max_in_window(g.ts.values, PROBE_WINDOW_S)
        rows.append(dict(client=client, probes=len(g), peak_10s=peak,
                         sensors=join_sensors(g.sensors),
                         channels=",".join(str(int(c)) for c in sorted(g.channel.dropna().unique()))))
        if peak >= PROBE_STORM_MIN:
            c = meta["client_label"][client]
            F.add("low", "Probe storm", f"{c}: {peak} probe requests in {PROBE_WINDOW_S} s",
                  f"{c} sent {len(g)} probe requests in total, peaking at {peak} within "
                  f"{PROBE_WINDOW_S} s, heard on channels {rows[-1]['channels']}. Aggressive scanning "
                  "usually means the client cannot hold a connection; it also adds airtime load on "
                  "every channel it scans.", client=c, sensors=rows[-1]["sensors"],
                  channels=rows[-1]["channels"], start=g.ts.min(), end=g.ts.max(), count=peak)
    return pd.DataFrame(rows)


def detect_join_bursts(att, meta, F: Findings, t0):
    if att.empty:
        return
    a = att.assign(minute=((att.start - t0) // 60).astype(int),
                   ssid=att.bssid.map(meta["bss_ssid"]).fillna("?"))
    for ssid, g in a.groupby("ssid"):
        per_min = g.groupby("minute").size()
        full = per_min.reindex(range(int(a.minute.max()) + 1), fill_value=0)
        thresh = max(JOIN_BURST_MIN, 3 * full.median() + 1)
        hot = full[(full >= thresh) & (full.index > 0)]  # minute 0 = capture warm-up
        if hot.empty:
            continue
        # merge consecutive minutes
        groups, cur = [], [hot.index[0]]
        for m in hot.index[1:]:
            if m - cur[-1] <= 1:
                cur.append(m)
            else:
                groups.append(cur)
                cur = [m]
        groups.append(cur)
        for mins in groups:
            sub = g[g.minute.isin(mins)]
            F.add("medium", "Join burst",
                  f"{ssid}: {len(sub)} join attempts from {sub.client.nunique()} clients "
                  f"in {len(mins)} min",
                  f"Outside this wave {ssid} averages {full.drop(mins).mean():.1f} join attempts per minute; here "
                  f"{len(sub)} attempts from {sub.client.nunique()} clients hit "
                  f"{sub.bssid.map(meta['bss_ap']).nunique()} APs within {len(mins)} minute(s). "
                  "A reconnect wave like this usually follows an AP, controller or authentication "
                  "event rather than individual client problems.",
                  ssid=ssid, sensors=join_sensors(sub.sensors), start=sub.start.min(),
                  end=sub.end.max(), count=len(sub))


def channel_health(f, meta, F: Findings, t0, t1):
    """Per sensor/channel/minute: retries, beacon loss, un-ACKed client frames, load."""
    f = f.assign(minute=((f.ts - t0) // 60).astype(int))
    expected_per_s = 1 / BEACON_INTERVAL_S
    rows = []
    silent = []
    gaps_found = []
    for sensor, g in f.groupby("sensor"):
        g = g.sort_values("ts")
        ch = int(g.channel.mode().iloc[0]) if g.channel.notna().any() else -1  # -1 = no radio header
        # only judge beacon loss for APs this sensor normally hears beaconing (captures that
        # filter or sample beacons would otherwise look like 100% loss)
        bea_all = g[g.subtype == 8]
        bss_here = set()
        for b, gb in bea_all.groupby("bssid"):
            span = gb.ts.max() - gb.ts.min()
            if span >= 10 and len(gb) >= 0.5 * span * expected_per_s:
                bss_here.add(b)
        acks_captured = int((g.subtype == 0x1D).sum()) > 0
        ts_all = g.ts.values
        gi = np.where(np.diff(ts_all) > GAP_S)[0]
        gaps = [(ts_all[i], ts_all[i + 1]) for i in gi]
        if gaps and bss_here:
            gaps_found.append((sensor, gaps))
        # ACK check for client->AP unicast frames (the AP's ACK is audible to the sensor)
        acks = g[g.subtype == 0x1D]
        at, ara = acks.ts.values, acks.ra.values
        up = g[g.ta.isin(meta["clients"]) & g.ra.isin(meta["ap_set"]) & (g.subtype != 0x1D)]
        acked = []
        idx = np.searchsorted(at, up.ts.values, side="right")
        for i, t, ta in zip(idx, up.ts.values, up.ta.values):
            ok, j = False, i
            while j < len(at) and at[j] - t < 0.002:
                if ara[j] == ta:
                    ok = True
                    break
                j += 1
            acked.append(ok)
        up = up.assign(acked=acked)
        # a sensor that misses most ACKs all the time has a visibility/timing problem, not a
        # channel problem: only judge un-ACKed frames where the sensor's own baseline is good
        ack_measurable = acks_captured and len(up) >= 10 and up.acked.mean() >= 0.5
        # retries: exclude beacons, probes and control frames (probe responses are routinely
        # retried when the scanning client has already left the channel: not congestion)
        rt = g[~g.subtype.isin([4, 5, 8]) & ~g.subtype.between(0x10, 0x1F)]
        beacons = g[g.subtype == 8].groupby(["minute", "bssid"]).size().unstack(fill_value=0)
        for m in range(int(g.minute.max()) + 1):
            seconds = min(60.0, t1 - (t0 + m * 60))
            if seconds <= 5:
                continue
            gm = g[g.minute == m]
            m0, m1 = t0 + m * 60, t0 + m * 60 + seconds
            seconds_rec = seconds - sum(max(0.0, min(b, m1) - max(a, m0)) for a, b in gaps)
            exp_each = seconds_rec * expected_per_s
            b = beacons.loc[m] if m in beacons.index else pd.Series(dtype=float)
            recv = b.reindex(sorted(bss_here), fill_value=0)
            loss = 1 - recv.sum() / (exp_each * len(bss_here)) if bss_here and seconds_rec >= 30 else np.nan
            for bssid, cnt in recv.items():
                if seconds_rec >= 30 and cnt < SILENT_AP_SHARE * exp_each:
                    silent.append(dict(sensor=sensor, bssid=bssid, minute=m))
            rm, um = rt[rt.minute == m], up[up.minute == m]
            rows.append(dict(sensor=sensor, channel=ch, minute=m, t=t0 + m * 60, seconds=round(seconds_rec, 1),
                             frames=len(gm), frames_per_s=len(gm) / seconds,
                             bss_beaconing=int((recv > 0).sum()),
                             beacon_loss=round(max(loss, 0), 4) if not np.isnan(loss) else np.nan,
                             retry_frames=len(rm),
                             retry_share=round(rm.retry.mean(), 4) if len(rm) else np.nan,
                             client_frames=len(um),
                             unacked_share=(round(1 - um.acked.mean(), 4)
                                            if len(um) and ack_measurable else np.nan),
                             active_clients=len(set(gm.ta[gm.ta.isin(meta["clients"])])
                                                | set(gm.ra[gm.ra.isin(meta["clients"]) & (gm.subtype != 5)]))))
    cm = pd.DataFrame(rows, columns=["sensor", "channel", "minute", "t", "seconds", "frames", "frames_per_s",
                                     "bss_beaconing", "beacon_loss", "retry_frames", "retry_share",
                                     "client_frames", "unacked_share", "active_clients"])
    for sensor, gaps in gaps_found:
        total = sum(b - a for a, b in gaps)
        F.add("info", "Sensor gap", f"{sensor}: recorded nothing for {fmt_dur(total)}",
              f"{sensor} captured no frames at all in {len(gaps)} window(s) totalling {fmt_dur(total)}, while it "
              "normally hears APs beaconing every 0.1 s. That is the sensor, not the air: beacon loss, silent-AP "
              "and congestion verdicts are not made for that time.",
              sensors=sensor, start=gaps[0][0], end=gaps[-1][1], count=len(gaps))
    if cm.empty:
        cm["flagged"] = pd.Series(dtype=bool)
        return cm

    # congestion episodes
    flag = (((cm.retry_share >= RETRY_ALERT) & (cm.retry_frames >= MIN_FRAMES_FOR_RATE))
            | ((cm.beacon_loss >= BEACON_LOSS_ALERT) & (cm.seconds >= 30))
            | ((cm.unacked_share >= UNACKED_ALERT) & (cm.client_frames >= 10)))
    cm["flagged"] = flag
    for sensor, g in cm[cm.flagged].groupby("sensor"):
        mins = list(g.minute)
        groups, cur = [], [mins[0]]
        for m in mins[1:]:
            if m - cur[-1] <= 1:
                cur.append(m)
            else:
                groups.append(cur)
                cur = [m]
        groups.append(cur)
        for ms in groups:
            sub = g[g.minute.isin(ms)]
            ch = int(sub.channel.iloc[0])
            chname = f"Channel {ch}" if ch >= 0 else f"Sensor {sensor}"
            F.add("medium", "Congestion / channel health",
                  f"{chname}: degraded for {len(ms)} min",
                  f"On {chname.lower() if ch >= 0 else 'the channel heard by ' + sensor} retry share peaked at "
                  f"{np.nanmax(sub.retry_share.fillna(0)) * 100:.0f}%, beacon loss at "
                  f"{np.nan_to_num(sub.beacon_loss.max()) * 100:.0f}%, un-ACKed client frames at "
                  f"{np.nanmax(sub.unacked_share.fillna(0)) * 100:.0f}% "
                  f"with up to {sub.active_clients.max()} active clients.",
                  sensors=sensor, channels=str(ch), start=sub.t.min(), end=sub.t.max() + 60,
                  count=len(ms))

    # silent APs (beaconing stopped while the sensor kept hearing others)
    if silent:
        s = pd.DataFrame(silent)
        for (sensor, bssid), g in s.groupby(["sensor", "bssid"]):
            if len(g) >= 1 and len(g) < cm[cm.sensor == sensor].shape[0]:
                ap = meta["bss_label"].get(bssid, "?")
                F.add("high", "AP silent / beacon loss", f"{ap}: beacons missing for {len(g)} min",
                      f"{ap} (channel {meta['bss_channel'].get(bssid)}) sent less than "
                      f"{SILENT_AP_SHARE * 100:.0f}% of its expected beacons in {len(g)} minute(s) "
                      f"while {sensor} kept hearing other APs: the AP went off-air or was drowned out.",
                      ap=ap, sensors=sensor, start=t0 + g.minute.min() * 60,
                      end=t0 + (g.minute.max() + 1) * 60, count=len(g))
    return cm


def detect_channel_overlap(inv, F: Findings):
    per = (inv.dropna(subset=["channel"]).groupby("channel")
           .agg(aps=("ap", "nunique"), bss=("bssid", "nunique"),
                sensors=("sensors", lambda s: join_sensors(s))))
    if per.empty:
        return per
    med = per.aps.median()
    for ch, r in per.iterrows():
        if r.aps >= max(4, 1.5 * med):
            F.add("medium", "Co-channel overlap", f"Channel {int(ch)}: {r.aps} APs share it",
                  f"{r.aps} APs ({r.bss} networks beaconing) are on channel {int(ch)}, versus a median of "
                  f"{med:.0f} on the other channels. Every client and AP on this channel contends for the "
                  "same airtime, and beacons alone take a larger share of it. Candidate for re-planning.",
                  sensors=r.sensors, channels=str(int(ch)), count=int(r.aps))
    return per.reset_index()


def systemic_rollups(att, loops, meta, F: Findings, client_ids):
    """Same failure on most clients of an SSID across many APs = not a radio problem."""
    if att.empty:
        return
    a = att.assign(ssid=att.bssid.map(meta["bss_ssid"]).fillna("?"),
                   cat=att.outcome.map(FAILURE_OUTCOMES))
    for ssid, g in a.groupby("ssid"):
        clients = g.client.unique()
        ok = set(g.loc[g.outcome == "connected", "client"])
        for cat, gc in g.dropna(subset=["cat"]).groupby("cat"):
            never_ok = set(gc.client) - ok
            aps = gc.bssid.map(meta["bss_ap"]).nunique()
            share = len(never_ok) / max(len(clients), 1)
            if share < SYSTEMIC_SHARE or aps < SYSTEMIC_MIN_APS:
                continue
            sensors = join_sensors(gc.sensors)
            n_sens = len(sensors.split(";"))
            expl = (f"{len(never_ok)} of {len(clients)} clients on {ssid} "
                    f"({meta['ssid_auth_by_label'].get(ssid, '?')}) never got through, across {aps} APs "
                    f"and {n_sens} sensors/channels ({len(gc)} failed attempts, "
                    f"{len(ok)} clients succeeded). ")
            if cat == "802.1X / EAP failure":
                answered = gc[gc.outcome == "eap_failed"].client.nunique()
                silent = gc[gc.outcome == "eap_no_response"].client.nunique()
                expl += (f"{answered} clients answered EAP but never got EAP-Success; for {silent} "
                         "clients no EAP reply was captured. A failure this uniform across every AP and "
                         "channel is not radio: check the authentication path (RADIUS server reachability, "
                         "server certificate, shared secret, policy) first.")
            else:
                expl += "A failure this uniform points to a shared cause (configuration, controller or backend) rather than individual clients."
            fid = F.add("critical", cat, f"{cat} across the whole {ssid} network", expl,
                        ssid=ssid, sensors=sensors, start=gc.start.min(), end=gc.end.max(),
                        count=len(never_ok))
            for client in never_ok:
                key = (client, cat)
                if key in client_ids:
                    for row in F.rows:
                        if row["id"] == client_ids[key]:
                            row["parent"] = fid
                            row["severity"] = "medium"
    if loops and len({l["client"] for l in loops}) >= 3:
        L = pd.DataFrame(loops)
        aps = L.bssid.map(meta["bss_ap"]).nunique()
        reasons = sorted({r for rs in L.reasons for r in rs})
        fid = F.add("critical", "Deauth / disassoc loop",
                    f"Disconnect loops on {aps} APs affecting {L.client.nunique()} clients",
                    f"{L['count'].sum()} repeated disconnects ({', '.join(reason_text(r) for r in reasons)}) "
                    f"hit {L.client.nunique()} clients on {aps} different APs, starting "
                    f"{(L.start.min() - F.t0) / 60:.0f} min into the capture. The same pattern on many "
                    "APs at once points to an AP/controller-side cause rather than individual clients.",
                    start=L.start.min(), end=L.end.max(), count=int(L.client.nunique()))
        for row in F.rows:
            if row["id"] in set(L.fid):
                row["parent"] = fid


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("out"))
    args = ap.parse_args()
    out = args.out

    print("Loading masked frames...")
    f, addresses = load(out)
    t0, t1 = f.ts.min(), f.ts.max()
    inv, meta = build_inventory(f, addresses)
    print(f"  {len(f):,} frames, {f.sensor.nunique()} sensors, {inv.ap.nunique()} APs "
          f"({len(inv)} networks), {len(meta['clients'])} clients")

    ev = client_events(f, meta)
    att, dis = reconstruct(ev, meta, t1)
    att = apply_data_evidence(att, f, meta, t1)
    att = mark_comebacks(att)
    att, dis, roams = mark_roams(att, dis)
    print(f"  {len(att)} join attempts, {len(dis)} disconnects, {len(roams)} roams")

    probe_answers = (f[(f.subtype == 5) & f.ra.isin(meta["clients"])]
                     .groupby("ra").bssid.agg(set).to_dict())

    F = Findings()
    F.t0 = t0
    loops, interrupted = detect_loops(dis, meta, F, probe_answers, att)
    # an attempt cut short by a loop disconnect is part of the loop, not a separate login failure
    cut = (att.attempt_id.isin(interrupted) & ~att.end_reason.isin(list(AUTH_FAIL_REASONS))
           & (att.outcome != "connected"))
    att.loc[cut, "outcome"] = "interrupted_by_loop"
    client_ids = detect_client_failures(att, meta, F, probe_answers)
    probes = detect_probe_storms(ev, meta, F)
    detect_join_bursts(att, meta, F, t0)
    cm = channel_health(f, meta, F, t0, t1)
    detect_channel_overlap(inv, F)
    systemic_rollups(att, loops, meta, F, client_ids)
    if len(roams):
        F.add("info", "Normal roam", f"{len(roams)} roams recognised (not failures)",
              "Disconnect followed by a join to a different AP within "
              f"{ROAM_WINDOW_S} s. Expected behaviour, listed so it is not mistaken for a failure.",
              sensors=join_sensors(roams.sensors), count=len(roams))
    findings = F.frame()

    # ---------------- label + write outputs (masked labels only)
    lab = meta["client_label"]
    for df in (att, dis):
        if not df.empty:
            df["client"] = df.client.map(lab)
            df["ap"] = df.bssid.map(meta["bss_ap"])
            df["network"] = df.bssid.map(meta["bss_label"])
    if not roams.empty:
        roams["client"] = roams.client.map(lab)
        roams["from_ap"] = roams.from_bssid.map(meta["bss_label"])
        roams["to_ap"] = roams.to_bssid.map(meta["bss_label"])

    names = {0: "Assoc req", 1: "Assoc resp", 2: "Reassoc req", 3: "Reassoc resp", 4: "Probe req",
             10: "Disassoc", 11: "Auth", 12: "Deauth"}

    def ev_name(r):
        if isnum(r.key_msg):
            return f"Key M{int(r.key_msg)}"
        if isnum(r.eap_code):
            return {1: "EAP request", 2: "EAP response", 3: "EAP success", 4: "EAP failure"}.get(int(r.eap_code), "EAP")
        return names.get(r.subtype, f"type {r.subtype}")

    def ev_detail(r):
        if r.subtype in (10, 12):
            return reason_text(r.reason)
        if r.subtype in (1, 3, 11) and isnum(r.status) and r.status != 0:
            return STATUS.get(int(r.status), f"status {int(r.status)}")
        return ""

    events = ev.copy()
    events["event"] = [ev_name(r) for r in events.itertuples()]
    events["detail"] = [ev_detail(r) for r in events.itertuples()]
    events["client"] = events.client.map(lab)
    events["ap"] = events.bssid.map(meta["bss_label"]).fillna("")
    events["t"] = (events.ts - t0).round(3)
    events = events[["client", "ts", "t", "event", "detail", "direction", "ap", "channel",
                     "sensors", "copies", "rssi", "retry_seen"]]

    clients = pd.DataFrame({"token": sorted(meta["clients"])})
    clients["client"] = clients.token.map(lab)
    clients["vendor"] = clients.token.map(meta["vendor"]).fillna("")
    clients["randomized_mac"] = clients.token.map(meta["randomized"]).fillna(False)
    if not att.empty:
        s = att.groupby("client").agg(attempts=("attempt_id", "size"),
                                      connected=("outcome", lambda o: int((o == "connected").sum())),
                                      failed=("outcome", lambda o: int(o.isin(FAILURE_OUTCOMES).sum())),
                                      heard_directly=("client_heard", "any"))
        clients = clients.merge(s, left_on="client", right_index=True, how="left")
    seen = ev.groupby("client").sensors.agg(join_sensors) if len(ev) else pd.Series(dtype=str)
    clients["sensors"] = clients.token.map(seen).fillna("")
    if not probes.empty:
        clients = clients.merge(probes[["client", "probes", "peak_10s"]].assign(client=probes.client.map(lab)),
                                on="client", how="left")
    clients = clients.drop(columns="token")

    sensors = pd.read_csv(out / "sensors_raw.csv")
    ap_heard = inv.assign(s=inv.sensors.str.split(";")).explode("s").groupby("s").ap.nunique()
    sensors["aps_heard"] = sensors.sensor.map(ap_heard).fillna(0).astype(int)
    cl_heard = (ev.assign(s=ev.sensors.str.split(";")).explode("s").groupby("s").client.nunique()
                if len(ev) else pd.Series(dtype=int))
    sensors["clients_heard"] = sensors.sensor.map(cl_heard).fillna(0).astype(int)
    if not att.empty:
        a2 = att.assign(s=att.sensors.str.split(";")).explode("s")
        sensors["one_sided_attempts"] = sensors.sensor.map(
            a2.groupby("s").client_heard.apply(lambda x: round(1 - x.mean(), 3))).fillna(0)

    inv_out = (inv.drop(columns=["radio", "ssid"])
               .rename(columns={"ssid_label": "ssid", "bssid": "token"}))  # token = masked BSSID
    findings.to_csv(out / "findings.csv", index=False)
    att.drop(columns=["bssid"], errors="ignore").to_csv(out / "attempts.csv", index=False)
    events.to_csv(out / "events.csv", index=False)
    cm.to_csv(out / "channel_minutes.csv", index=False)
    inv_out.to_csv(out / "aps.csv", index=False)
    clients.to_csv(out / "clients.csv", index=False)
    sensors.to_csv(out / "sensors.csv", index=False)
    roams.drop(columns=["from_bssid", "to_bssid"], errors="ignore").to_csv(out / "roams.csv", index=False)
    summary = dict(capture_start=t0, capture_end=t1, frames=int(len(f)),
                   sensors=int(f.sensor.nunique()), aps=int(inv.ap.nunique()),
                   networks=int(len(inv)), clients=int(len(meta["clients"])),
                   attempts=int(len(att)), roams=int(len(roams)),
                   ssids={v: meta["ssid_auth"][k] for k, v in meta["ssid_label"].items()},
                   findings={k: int(v) for k, v in findings.severity.value_counts().items()} if len(findings) else {})
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\n{len(findings)} findings:")
    top = findings[findings.parent.fillna("") == ""] if len(findings) else findings
    for r in top.itertuples():
        print(f"  [{r.severity:8}] {r.category:28} {r.title}")
    print(f"\nOutputs in {out}/ - start the dashboard with:  streamlit run dashboard.py")


if __name__ == "__main__":
    main()
