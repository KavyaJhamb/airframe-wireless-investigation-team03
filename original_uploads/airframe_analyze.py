#!/usr/bin/env python3
"""
airframe_analyze.py - header-only 802.11 / 802.1X analysis across multiple sensors.

Reads every *.pcap in a folder (one file per sensor), and produces:
  minute_metrics.csv   per-sensor, per-minute health metrics (retry rate over unicast frames only)
  incidents.csv        anomalies detected from the data itself (no hardcoded window),
                       grouped into cross-sensor incidents when several sensors flag the same minutes
  attempts.csv         every client connection attempt, reconstructed as a state machine:
                       auth -> assoc -> EAP -> 4-way handshake, with where/why it broke
  clients.csv          per-client roll-up: attempts, failures, roams, sensors/channels seen on
  frame_overlap.csv    how many identical frames each pair of sensors both heard (same air or not)
  summary.json         everything above in one file for a dashboard
  report.txt           human-readable summary (also printed)

Usage:
  python3 airframe_analyze.py /path/to/pcap_folder --out results --tz Europe/Paris

Only header fields are read. Nothing is transmitted. Encrypted (Protected) frames are counted but not inspected.
Standard library only (Python 3.9+).
"""
import argparse, collections, csv, glob, json, math, os, statistics, struct, datetime
from zoneinfo import ZoneInfo

# ----------------------------------------------------------------------------- pcap reading
PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}
LINKTYPE_80211, LINKTYPE_RADIOTAP = 105, 127


def read_pcap(path, q):
    with open(path, 'rb') as f:
        gh = f.read(24)
        if gh[:4] == b'\x0a\x0d\x0d\x0a':
            raise ValueError(f'{path}: pcapng not supported - convert with: editcap -F pcap in.pcapng out.pcap')
        if len(gh) < 24 or gh[:4] not in PCAP_MAGICS:
            raise ValueError(f'{path}: not a pcap file')
        endian, scale = PCAP_MAGICS[gh[:4]]
        linktype = struct.unpack(endian + 'I', gh[20:24])[0] & 0x0FFFFFFF
        if linktype not in (LINKTYPE_80211, LINKTYPE_RADIOTAP):
            raise ValueError(f'{path}: unsupported link type {linktype} (need 802.11 or radiotap)')
        while True:
            h = f.read(16)
            if not h:
                break
            if len(h) < 16:
                q['truncated_records'] += 1
                break
            sec, frac, caplen, origlen = struct.unpack(endian + 'IIII', h)
            d = f.read(caplen)
            if len(d) < caplen:
                q['truncated_records'] += 1
                break
            yield sec + frac * scale, linktype, d, origlen


# ----------------------------------------------------------------------------- radiotap
# bit -> (alignment, size), namespace 0 only (radiotap.org defined fields)
RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1), 7: (2, 2),
             8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2),
             16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3), 20: (4, 8), 21: (2, 12), 22: (8, 12),
             23: (2, 12), 24: (2, 12), 25: (2, 6), 26: (1, 1), 27: (2, 4)}


def parse_radiotap(d):
    """Returns (header_len, freq_mhz, signal_dbm, rt_flags) or None if malformed."""
    if len(d) < 8:
        return None
    rtlen = struct.unpack_from('<H', d, 2)[0]
    if rtlen < 8 or rtlen > len(d):
        return None
    words, pos = [], 4
    while True:
        if pos + 4 > rtlen:
            return None
        w = struct.unpack_from('<I', d, pos)[0]
        words.append(w)
        pos += 4
        if not w & 0x80000000:
            break
    freq = signal = None
    flags = 0
    # Fields are laid out in bit order; the ones we need (1,3,5) live in the first word,
    # so parse word 0 only and stop at the first field we cannot size.
    w0 = words[0]
    for bit in range(29):
        if not w0 & (1 << bit):
            continue
        if bit not in RT_FIELDS:
            break
        align, size = RT_FIELDS[bit]
        pos = (pos + align - 1) // align * align
        if pos + size > rtlen:
            break
        if bit == 1:
            flags = d[pos]
        elif bit == 3:
            freq = struct.unpack_from('<H', d, pos)[0]
        elif bit == 5:
            signal = struct.unpack_from('<b', d, pos)[0]
        pos += size
    return rtlen, freq, signal, flags


def freq_to_channel(f):
    if not f:
        return None
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f <= 5900:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return None


# ----------------------------------------------------------------------------- 802.11 / 802.1X
def mac(b):
    return ':'.join(f'{x:02x}' for x in b)


def is_group(m):
    return m is not None and int(m[:2], 16) & 1 == 1


REASON = {1: 'unspecified', 2: 'previous auth no longer valid', 3: 'leaving (deauth)', 4: 'inactivity',
          5: 'AP overloaded', 6: 'class 2 frame from unauthenticated STA', 7: 'class 3 frame from unassociated STA',
          8: 'leaving (disassoc)', 9: 'not authenticated', 13: 'invalid IE', 14: 'MIC failure',
          15: '4-way handshake timeout', 16: 'group key handshake timeout', 17: 'IE mismatch in 4-way',
          23: '802.1X authentication failed', 24: 'cipher suite rejected', 34: 'poor channel conditions',
          39: 'requested from peer QSTA'}
STATUS = {0: 'success', 1: 'unspecified failure', 10: 'capabilities not supported', 12: 'denied, other reason',
          13: 'auth algorithm not supported', 14: 'auth sequence error', 15: 'challenge failure',
          16: 'auth timeout', 17: 'AP cannot handle more STAs', 18: 'basic rates not supported',
          30: 'try again later', 37: 'request declined', 53: 'invalid PMKID', 72: 'invalid RSNE'}
EAP_TYPES = {1: 'Identity', 3: 'NAK', 4: 'MD5', 13: 'EAP-TLS', 21: 'TTLS', 25: 'PEAP', 43: 'FAST'}


def parse_frame(b):
    """Parse an 802.11 MAC header (+ the bits of body we care about). Returns dict or None."""
    if len(b) < 10:
        return None
    fc = struct.unpack_from('<H', b, 0)[0]
    ftype, sub, fl = (fc >> 2) & 3, (fc >> 4) & 0xF, fc >> 8
    tods, fromds, retry, prot, order = fl & 1, (fl >> 1) & 1, (fl >> 3) & 1, (fl >> 6) & 1, (fl >> 7) & 1
    a1 = mac(b[4:10])
    a2 = mac(b[10:16]) if len(b) >= 16 and not (ftype == 1 and sub in (12, 13)) else None
    a3 = mac(b[16:22]) if len(b) >= 22 and ftype != 1 else None
    seq = struct.unpack_from('<H', b, 22)[0] >> 4 if len(b) >= 24 and ftype != 1 else None
    fr = dict(ftype=ftype, sub=sub, retry=retry, prot=prot, a1=a1, a2=a2, a3=a3, seq=seq,
              tods=tods, fromds=fromds, kind=None, info={})

    if ftype == 0 and len(b) >= 24:                           # management
        off = 24 + (4 if order else 0)
        body = b[off:]
        if sub == 11 and len(body) >= 6:                     # authentication
            alg, aseq, status = struct.unpack_from('<HHH', body, 0)
            fr['info'] = dict(alg=alg, auth_seq=aseq, status=status)
        elif sub in (1, 3) and len(body) >= 4:               # (re)assoc response
            fr['info'] = dict(status=struct.unpack_from('<H', body, 2)[0])
        elif sub in (10, 12) and len(body) >= 2:             # disassoc / deauth
            fr['info'] = dict(reason=struct.unpack_from('<H', body, 0)[0])
        elif sub in (8, 5) and len(body) >= 14:              # beacon / probe resp -> SSID
            p = 12
            if body[p] == 0 and p + 2 + body[p + 1] <= len(body):
                fr['info'] = dict(ssid=body[p + 2:p + 2 + body[p + 1]].decode('utf-8', 'replace'))
        elif sub == 13 and len(body) >= 1:
            fr['info'] = dict(category=body[0])

    elif ftype == 2 and len(b) >= 24 and not prot:           # data: look for EAPOL
        off = 24 + (6 if tods and fromds else 0)
        if sub & 0x8:
            off += 2 + (4 if order else 0)
        if len(b) >= off + 12 and b[off:off + 6] == b'\xaa\xaa\x03\x00\x00\x00' \
                and b[off + 6:off + 8] == b'\x88\x8e':
            e = off + 8
            etype = b[e + 1]
            info = dict(eapol_type=etype)
            if etype == 0 and len(b) >= e + 8:               # EAP packet
                code, eid = b[e + 4], b[e + 5]
                info.update(eap_code=code, eap_id=eid)
                if code in (1, 2) and len(b) >= e + 9:
                    info['eap_type'] = b[e + 8]
            elif etype == 3 and len(b) >= e + 7:             # EAPOL-Key
                ki = struct.unpack_from('>H', b, e + 5)[0]
                ack, mic, inst, sec = bool(ki & 0x80), bool(ki & 0x100), bool(ki & 0x40), bool(ki & 0x200)
                pairwise = bool(ki & 0x08)
                # key data length sits at EAPOL offset 97; header-only captures may cut it off
                kdl = struct.unpack_from('>H', b, e + 97)[0] if len(b) >= e + 99 else None
                certain = True
                if not pairwise:
                    m = None                                   # group-key handshake, not the 4-way
                elif ack and not mic:
                    m = 1
                elif ack and mic and inst:
                    m = 3
                elif mic and not ack and sec:
                    m = 4
                    if kdl:                                     # M4 carries no key data
                        certain = False
                elif mic and not ack:
                    m = 2
                    if kdl == 0:                                # M2 normally carries the RSN IE
                        certain = False
                else:
                    m, certain = None, False
                info.update(key_msg=m, key_info=f'0x{ki:04x}', key_certain=certain)
            fr['info'] = info
    return fr


def roles(fr, known_aps=frozenset()):
    """(bssid, client, from_ap). Data frames: DS bits. Management frames: an address that has sent a
    beacon/probe response is an AP; otherwise fall back to TA==BSSID. 4-address (mesh/WDS) frames and
    control frames are not attributed. client is None when the role cannot be determined."""
    a1, a2, a3 = fr['a1'], fr['a2'], fr['a3']
    if fr['ftype'] == 0:
        if a2 is None or a3 is None:
            return None, None, None
        if a2 in known_aps or (a2 == a3 and a1 not in known_aps):
            return a2 if a2 in known_aps else a3, (None if is_group(a1) else a1), True
        if a1 in known_aps or a3 in known_aps or not is_group(a3):
            return (a1 if a1 in known_aps else a3), a2, False
        return None, None, None
    if fr['ftype'] == 2:
        if fr['tods'] and not fr['fromds']:
            return a1, a2, False
        if fr['fromds'] and not fr['tods']:
            return a2, (None if is_group(a1) else a1), True
    return None, None, None


def classify_event(fr, from_ap):
    """Map a parsed frame to a connection-lifecycle event name (or None)."""
    t, s, i = fr['ftype'], fr['sub'], fr['info']
    if t == 0:
        if s == 11 and 'status' in i:
            if from_ap:
                return 'AUTH_RESP'
            return 'AUTH_REQ'
        if s in (0, 2):
            return 'ASSOC_REQ'
        if s in (1, 3) and 'status' in i:
            return 'ASSOC_RESP'
        if s == 12:
            return 'DEAUTH'
        if s == 10:
            return 'DISASSOC'
    if t == 2 and 'eapol_type' in i:
        et = i['eapol_type']
        if et == 1:
            return 'EAPOL_START'
        if et == 2:
            return 'EAPOL_LOGOFF'
        if et == 0:
            return {1: 'EAP_REQ', 2: 'EAP_RESP', 3: 'EAP_SUCCESS', 4: 'EAP_FAILURE'}.get(i.get('eap_code'))
        if et == 3 and i.get('key_msg'):
            return f"KEY_M{i['key_msg']}"
        if et == 3:
            return 'KEY_OTHER'
    return None


# ----------------------------------------------------------------------------- ingest
GAP_S = 5.0            # no frame at all for this long on a sensor = capture gap (beacons alone are ~10/s)
def new_minute():
    return dict(frames=0, mgmt=0, ctrl=0, data=0, protected=0, bad_fcs=0, uni=0, uni_retry=0, retry=0,
                mgmt_retry=0, data_retry=0, bcast_retry=0, presp=0, presp_retry=0,
                beacon=0, probe_req=0, auth=0, auth_fail=0, assoc_req=0, assoc_fail=0, deauth=0, disassoc=0,
                eapol=0, eap_success=0, eap_failure=0, key_msgs=0, clients=set(), signals=[])


def scan_aps(paths):
    aps = set()
    for path in paths:
        q = collections.Counter()
        for ts, lt, d, origlen in read_pcap(path, q):
            off = 0
            if lt == LINKTYPE_RADIOTAP:
                if len(d) < 4:
                    continue
                off = struct.unpack_from('<H', d, 2)[0]
            if len(d) >= off + 16 and d[off] in (0x80, 0x50):     # beacon / probe response
                aps.add(mac(d[off + 10:off + 16]))
    return aps


def ingest(paths, known_aps=frozenset()):
    sensors = {}
    events = []                                     # lifecycle events, all sensors
    client_signal = collections.defaultdict(list)
    ssid_of = {}
    overlap_keys = {}                               # sensor -> {10s bucket: set(frame keys)}
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        q = collections.Counter()
        minutes = collections.defaultdict(new_minute)
        chans = collections.Counter()
        first = last = None
        prev_ts = None
        gaps = []
        keys = collections.defaultdict(set)
        for ts, lt, d, origlen in read_pcap(path, q):
            q['records'] += 1
            freq = signal = None
            rtflags = 0
            if lt == LINKTYPE_RADIOTAP:
                rt = parse_radiotap(d)
                if rt is None:
                    q['bad_radiotap'] += 1
                    continue
                rtlen, freq, signal, rtflags = rt
                body = d[rtlen:]
            else:
                body = d
            if rtflags & 0x10 and len(d) == origlen and len(body) >= 4:   # FCS present and not truncated away
                body = body[:-4]
            fr = parse_frame(body)
            if fr is None:
                q['bad_80211'] += 1
                continue
            if prev_ts is not None and ts - prev_ts > GAP_S:
                gaps.append((prev_ts, ts))
            prev_ts = ts
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
            if freq:
                chans[freq] += 1
            m = minutes[int(ts // 60) * 60]
            m['frames'] += 1
            m[('mgmt', 'ctrl', 'data', 'mgmt')[fr['ftype']]] += 1
            if rtflags & 0x40:
                m['bad_fcs'] += 1
            if fr['prot']:
                m['protected'] += 1
            if fr['ftype'] in (0, 2) and not is_group(fr['a1']):
                m['uni'] += 1
                m['uni_retry'] += fr['retry']
            m['retry'] += fr['retry']
            if fr['ftype'] == 0:
                m['mgmt_retry'] += fr['retry']
            elif fr['ftype'] == 2:
                m['data_retry'] += fr['retry']
            if fr['ftype'] == 0 and fr['sub'] == 5:
                m['presp'] += 1
                m['presp_retry'] += fr['retry']
            if fr['retry'] and is_group(fr['a1']):
                m['bcast_retry'] += 1          # unusual: broadcast frames are never retransmitted in real 802.11
            if signal is not None:
                m['signals'].append(signal)

            bssid, client, from_ap = roles(fr, known_aps)
            if client:
                m['clients'].add(client)
                if not from_ap and signal is not None and len(client_signal[client]) < 2000:
                    client_signal[client].append(signal)
            s, i = fr['sub'], fr['info']
            if fr['ftype'] == 0:
                if s == 8:
                    m['beacon'] += 1
                elif s == 4:
                    m['probe_req'] += 1
                elif s == 11:
                    m['auth'] += 1
                    if i.get('status', 0) != 0:
                        m['auth_fail'] += 1
                elif s in (0, 2):
                    m['assoc_req'] += 1
                elif s in (1, 3) and i.get('status', 0) != 0:
                    m['assoc_fail'] += 1
                elif s == 12:
                    m['deauth'] += 1
                elif s == 10:
                    m['disassoc'] += 1
                if 'ssid' in i and fr['a3'] and i['ssid']:
                    ssid_of.setdefault(fr['a3'], i['ssid'])
            if 'eapol_type' in i:
                m['eapol'] += 1
                if (i['eapol_type'] == 0 and 'eap_code' not in i) or (i['eapol_type'] == 3 and 'key_msg' not in i):
                    q['eapol_truncated'] += 1
                if i.get('eap_code') == 3:
                    m['eap_success'] += 1
                elif i.get('eap_code') == 4:
                    m['eap_failure'] += 1
                if i.get('key_msg'):
                    m['key_msgs'] += 1

            if fr['seq'] is not None and fr['a2']:
                keys[int(ts // 10)].add(hash((fr['a2'], fr['a1'], fr['seq'], fr['ftype'], fr['sub'])))

            kind = classify_event(fr, from_ap) if client else None
            if kind:
                events.append(dict(t=ts, sensor=name, freq=freq, kind=kind, client=client, bssid=bssid,
                                   from_ap=from_ap, retry=fr['retry'], seq=fr['seq'], ta=fr['a2'], ra=fr['a1'],
                                   info=i, signal=signal))
        if first is None:
            print(f'WARNING: {name}: no parseable frames')
            continue
        main_freq = chans.most_common(1)[0][0] if chans else None
        sensors[name] = dict(path=path, first=first, last=last, minutes=minutes, quality=dict(q), gaps=gaps,
                             freqs=dict(chans), freq=main_freq, channel=freq_to_channel(main_freq))
        overlap_keys[name] = keys
    return sensors, events, client_signal, ssid_of, overlap_keys


# ----------------------------------------------------------------------------- minute metrics + anomaly detection
RATE_METRICS = {'uni_retry_rate': 'unicast', 'all_retry_rate': 'frames', 'mgmt_retry_rate': 'mgmt',
                'data_retry_rate': 'data', 'probe_resp_retry_rate': 'probe_resp',
                'non_probe_retry_rate': 'non_probe_unicast'}
METRICS = ['uni_retry_rate', 'all_retry_rate', 'mgmt_retry_rate', 'data_retry_rate', 'probe_resp_retry_rate',
           'probe_resp', 'frames', 'deauth', 'disassoc', 'auth_fail', 'assoc_fail', 'eap_failure', 'probe_req']


def minute_rows(sensors):
    rows = []
    for name, s in sensors.items():
        for t0, m in sorted(s['minutes'].items()):
            cover = min(t0 + 60, s['last']) - max(t0, s['first'])
            sig = sorted(m['signals'])
            rows.append(dict(sensor=name, channel=s['channel'], minute_utc=t0, partial=cover < 50,
                             frames=m['frames'], mgmt=m['mgmt'], ctrl=m['ctrl'], data=m['data'],
                             protected=m['protected'], bad_fcs=m['bad_fcs'], unicast=m['uni'],
                             unicast_retry=m['uni_retry'],
                             uni_retry_rate=round(m['uni_retry'] / m['uni'], 5) if m['uni'] else None,
                             all_retry_rate=round(m['retry'] / m['frames'], 5) if m['frames'] else None,
                             mgmt_retry_rate=round(m['mgmt_retry'] / m['mgmt'], 5) if m['mgmt'] else None,
                             data_retry_rate=round(m['data_retry'] / m['data'], 5) if m['data'] else None,
                             broadcast_retry=m['bcast_retry'], probe_resp=m['presp'],
                             probe_resp_retry_rate=round(m['presp_retry'] / m['presp'], 5) if m['presp'] else None,
                             non_probe_unicast=m['uni'] - m['presp'],
                             non_probe_retry_rate=round((m['uni_retry'] - m['presp_retry']) / (m['uni'] - m['presp']), 5)
                             if m['uni'] - m['presp'] > 0 else None,
                             beacon=m['beacon'], probe_req=m['probe_req'], auth=m['auth'],
                             auth_fail=m['auth_fail'], assoc_req=m['assoc_req'], assoc_fail=m['assoc_fail'],
                             deauth=m['deauth'], disassoc=m['disassoc'], eapol=m['eapol'],
                             eap_success=m['eap_success'], eap_failure=m['eap_failure'], key_msgs=m['key_msgs'],
                             active_clients=len(m['clients']),
                             signal_median=sig[len(sig) // 2] if sig else None,
                             signal_p10=sig[len(sig) // 10] if sig else None))
    return rows


def detect(rows, z_thresh=4.0, min_unicast=200):
    """Robust per-sensor anomaly flags: compare each full minute with that sensor's own median over the
    whole capture (median/MAD, so the anomaly itself barely moves the baseline)."""
    flags = []
    by_sensor = collections.defaultdict(list)
    for r in rows:
        if not r['partial']:
            by_sensor[r['sensor']].append(r)
    for sensor, rs in by_sensor.items():
        for metric in METRICS:
            if metric in RATE_METRICS:
                vals = [r[metric] for r in rs if r[metric] is not None
                        and r[RATE_METRICS[metric]] >= (min_unicast if metric != 'non_probe_retry_rate' else 30)]
            else:
                vals = [r[metric] for r in rs]
            if len(vals) < 5:
                continue
            med = statistics.median(vals)
            mad = statistics.median(abs(v - med) for v in vals) * 1.4826
            floor = 0.005 if metric in RATE_METRICS else max(math.sqrt(med + 1), 0.1 * med)
            scale = max(mad, floor)
            for r in rs:
                v = r[metric]
                if v is None or (metric in RATE_METRICS and r[RATE_METRICS[metric]] <
                                 (min_unicast if metric != 'non_probe_retry_rate' else 30)):
                    continue
                z = (v - med) / scale
                if z >= z_thresh:
                    flags.append(dict(sensor=sensor, channel=r['channel'], minute_utc=r['minute_utc'],
                                      metric=metric, value=v, baseline_median=round(med, 5), z=round(z, 1)))
    return flags


def group_incidents(flags, n_sensors):
    """Merge flags on the same metric in consecutive minutes; label scope by how many sensors flagged it."""
    by_metric = collections.defaultdict(list)
    for f in flags:
        by_metric[f['metric']].append(f)
    incidents = []
    for metric, fs in by_metric.items():
        mins = sorted({f['minute_utc'] for f in fs})
        run = [mins[0]]
        runs = []
        for m in mins[1:]:
            if m - run[-1] <= 60:
                run.append(m)
            else:
                runs.append(run)
                run = [m]
        runs.append(run)
        for run in runs:
            inr = [f for f in fs if run[0] <= f['minute_utc'] <= run[-1]]
            sens = sorted({f['sensor'] for f in inr})
            peak = max(inr, key=lambda f: f['z'])
            scope = ('environment-wide' if len(sens) >= max(2, math.ceil(0.75 * n_sensors))
                     else 'multi-sensor' if len(sens) >= 2 else 'single-sensor')
            incidents.append(dict(metric=metric, start_utc=run[0], end_utc=run[-1] + 60, minutes=len(run),
                                  scope=scope, sensors_flagged=len(sens), sensors=sens,
                                  channels=sorted({f['channel'] for f in inr if f['channel']}),
                                  peak_sensor=peak['sensor'], peak_minute_utc=peak['minute_utc'],
                                  peak_value=peak['value'], peak_baseline=peak['baseline_median'], peak_z=peak['z']))
    incidents.sort(key=lambda x: (x['start_utc'], -x['sensors_flagged']))
    return incidents


# ----------------------------------------------------------------------------- connection state machine
STAGE = {'AUTH': 1, 'ASSOC': 2, 'EAP': 3, 'KEY': 4, 'DONE': 5}
IDLE_S = 60.0          # no frame for this long => attempt stalled. 802.1X authenticators resend
                       # EAP-Request/Identity about every 30 s, so shorter timeouts split one stuck
                       # client into many "attempts"
LINK_S = 30.0          # an AP deauth up to this long after a stall is the AP giving up on that attempt


def dedupe(events):
    """Same frame heard by several sensors, or retransmitted, becomes one event (heard_by keeps sensors)."""
    events.sort(key=lambda e: e['t'])
    out, last = [], {}
    for e in events:
        k = (e['freq'], e['bssid'], e['ta'], e['ra'], e['kind'], e['seq'], e['info'].get('eap_id'),
             e['info'].get('key_msg'))
        prev = last.get(k)
        if prev is not None and e['t'] - prev['t'] <= 1.0:
            prev['heard_by'].add(e['sensor'])
            prev['copies'] += 1
            prev['retries'] += e['retry']
            continue
        e = dict(e, heard_by={e['sensor']}, copies=1, retries=e['retry'])
        last[k] = e
        out.append(e)
    return out


def hint_for(outcome, stage_detail):
    h = {
        'auth_rejected': 'AP refused open/SAE authentication (see status code)',
        'assoc_rejected': 'AP refused association (capacity, capabilities or policy - see status code)',
        'eap_failure': 'Authentication server rejected the client (credentials, certificate or policy)',
        'deauth_during_setup': 'Connection torn down before completion (see reason code and sender)',
        'restarted': 'Client gave up and started again - usually a timeout on the previous attempt',
        'abandoned_for_other_ap': 'Client left mid-setup and tried a different AP (roaming or giving up on this AP)',
    }.get(outcome)
    if h:
        return h
    if outcome == 'probable_success_client_unheard':
        return 'Sensor never heard the client, but the AP sent M3 (only done after a valid M2) - not a failure'
    if outcome == 'insufficient_observation':
        return 'Only one setup frame seen - not enough to call it a failure'
    if outcome == 'stalled':
        return {
            'auth sent, no response': 'AP did not answer authentication (AP busy, poor uplink or client not heard)',
            'associated, no EAPOL': 'Associated but 802.1X/4-way never started (AP or controller side)',
            'EAP started, no result': 'EAP exchange stopped mid-way - consistent with slow or unreachable RADIUS',
            'EAP identity loop: client answered, AP never started EAP method':
                'Client sent its identity but the AP never got an answer from the authentication server '
                '(RADIUS unreachable, rejecting silently, or misconfigured) - AP re-asks every ~30 s then gives up',
            'EAP identity loop: AP never started EAP method (client not audible to sensor)':
                'Only Identity requests, each with a new EAP id - same pattern as clients heard answering; '
                'consistent with the authentication server not responding',
            'EAP identity requested, audible client did not answer':
                'Client heard on air but did not answer EAP - check client 802.1X configuration',
            'M1 sent, no M2': 'Client did not answer key message 1 (client/driver or RF on the downlink)',
            'M2 sent, no M3': 'AP did not accept M2 - consistent with wrong PSK/PMK mismatch',
            'M3 sent, no M4': 'Client did not confirm keys (client/driver issue or lost frames)',
        }.get(stage_detail, 'No progress within the idle timeout')
    return ''


def stage_detail_of(a):
    o = a.get('outcome')
    if o == 'auth_rejected':
        return 'auth rejected'
    if o == 'assoc_rejected':
        return 'assoc rejected'
    if o == 'eap_failure':
        return 'EAP-Failure from server'
    if a['max_key']:
        return {1: 'M1 sent, no M2', 2: 'M2 sent, no M3', 3: 'M3 sent, no M4'}.get(a['max_key'], '4-way incomplete')
    if a['eap_events'] and a['eap_req_types'] <= {1} and a['eap_resp']:
        return 'EAP identity loop: client answered, AP never started EAP method'
    if a['eap_events'] and a['eap_req_types'] <= {1} and not a['client_frames']:
        return 'EAP identity loop: AP never started EAP method (client not audible to sensor)'
    if a['eap_events'] and a['eap_req_types'] <= {1}:
        return 'EAP identity requested, audible client did not answer'
    if a['eap_events']:
        return 'EAP started, no result'
    if a['assoc_ok']:
        return 'associated, no EAPOL'
    if a['stage'] >= STAGE['ASSOC']:
        return 'assoc sent, no response'
    return 'auth sent, no response'


def build_attempts(events, eapol_bssids, ssid_of, capture_end, gaps=None):
    per_client = collections.defaultdict(list)
    for e in events:
        per_client[e['client']].append(e)
    attempts, disconnects = [], []
    nonlocal_prev = [None]

    def new(e):
        return dict(client=e['client'], bssid=e['bssid'], start=e['t'], last=e['t'], stage=STAGE['AUTH'],
                    assoc_ok=False, eap_events=0, eap_req=0, eap_types=set(), eap_first=None, eap_end=None,
                    observed_from=e['kind'], deauth_delay_s=None, n_events=0, eap_req_repeats=0, eap_ids=[],
                    eap_req_types=set(), eap_resp=0, client_frames=0, max_key=0, key_uncertain=0, key_info=[], sensors=set(), freqs=set(), retries=0, outcome=None, code=None, code_text='',
                    deauth_by=None)

    def close(a, outcome, end_t, code=None, code_text='', by=None):
        if outcome == 'stalled' and a['n_events'] <= 1:
            outcome = 'insufficient_observation'
        if outcome in ('stalled', 'in_progress_at_capture_end') and a['max_key'] >= 3 and a['client_frames'] == 0:
            outcome = 'probable_success_client_unheard'   # AP only sends M3 after a valid M2
        a['outcome'], a['end'] = outcome, end_t
        a['code'], a['code_text'], a['deauth_by'] = code, code_text, by
        a['stage_detail'] = '' if outcome == 'success' else stage_detail_of(a)
        a['hint'] = hint_for(outcome, a['stage_detail'])
        attempts.append(a)
        nonlocal_prev[0] = a if outcome in FAILED or outcome == 'insufficient_observation' else None

    for client, evs in per_client.items():
        cur = None
        nonlocal_prev[0] = None
        for e in evs:
            k, i = e['kind'], e['info']
            if cur and e['t'] - cur['last'] > IDLE_S:
                if cur['assoc_ok'] and not cur['eap_events'] and not cur['max_key'] \
                        and cur['bssid'] not in eapol_bssids:
                    close(cur, 'associated_no_eapol_seen', cur['last'])
                else:
                    close(cur, 'stalled', cur['last'])
                cur = None
            if k == 'AUTH_REQ' and i.get('auth_seq') in (1, None):
                if cur and not (cur['stage'] == STAGE['AUTH'] and cur['bssid'] == e['bssid']):
                    close(cur, 'restarted' if cur['bssid'] == e['bssid'] else 'abandoned_for_other_ap', e['t'])
                    cur = None
                cur = cur or new(e)
            elif k == 'ASSOC_REQ' and (cur is None or cur['bssid'] != e['bssid'] or cur['stage'] > STAGE['ASSOC']):
                if cur:
                    close(cur, 'restarted' if cur['bssid'] == e['bssid'] else 'abandoned_for_other_ap', e['t'])
                cur = new(e)                     # e.g. capture started mid-way, or fast roaming
                cur['stage'] = STAGE['ASSOC']
            prev_fail = nonlocal_prev[0]
            if cur is None and k in ('EAPOL_START', 'EAP_REQ', 'EAP_RESP', 'KEY_M1', 'ASSOC_RESP'):
                cur = new(e)                     # setup observed from mid-way (reauth, or earlier frames missed)
                cur['observed_from'] = k
                cur['stage'] = STAGE['ASSOC'] if k == 'ASSOC_RESP' else STAGE['EAP'] if 'EAP' in k else STAGE['KEY']
            if k in ('DEAUTH', 'DISASSOC') and cur is None and prev_fail is not None \
                    and prev_fail['code'] is None and prev_fail['bssid'] == e['bssid'] \
                    and e['t'] - prev_fail['end'] <= (LINK_S if prev_fail['outcome'] in ('stalled', 'insufficient_observation')
                                                  else 2.0):
                prev_fail['code'] = i.get('reason')
                prev_fail['deauth_by'] = 'AP' if e['from_ap'] else 'client'
                prev_fail['deauth_delay_s'] = round(e['t'] - prev_fail['end'], 2)
                if prev_fail['outcome'] in ('stalled', 'insufficient_observation'):
                    prev_fail['outcome'] = 'deauth_during_setup'
                    prev_fail['code_text'] = REASON.get(i.get('reason'), '')
                    prev_fail['hint'] = hint_for('stalled', prev_fail['stage_detail']) + \
                        f"; {prev_fail['deauth_by']} gave up after {prev_fail['deauth_delay_s']}s"
                else:
                    prev_fail['code_text'] = f"then {k.lower()}: {REASON.get(i.get('reason'), '')}"
                nonlocal_prev[0] = None
                continue
            if k in ('DEAUTH', 'DISASSOC') and cur is None:
                disconnects.append(dict(t=e['t'], client=client, bssid=e['bssid'], kind=k,
                                        by='AP' if e['from_ap'] else 'client', reason=i.get('reason'),
                                        reason_text=REASON.get(i.get('reason'), ''), sensors=sorted(e['heard_by'])))
                continue
            if cur is None:
                continue
            cur['last'] = e['t']
            cur['n_events'] += 1
            cur['client_frames'] += not e['from_ap']
            cur['sensors'] |= e['heard_by']
            if e['freq']:
                cur['freqs'].add(e['freq'])
            cur['retries'] += e['retries']
            if k == 'AUTH_RESP' and i.get('status', 0) != 0:
                close(cur, 'auth_rejected', e['t'], i['status'], STATUS.get(i['status'], ''))
                cur = None
            elif k == 'ASSOC_REQ':
                cur['stage'] = max(cur['stage'], STAGE['ASSOC'])
            elif k == 'ASSOC_RESP':
                if i.get('status', 0) != 0:
                    close(cur, 'assoc_rejected', e['t'], i['status'], STATUS.get(i['status'], ''))
                    cur = None
                else:
                    cur['assoc_ok'] = True
                    cur['stage'] = max(cur['stage'], STAGE['ASSOC'])
            elif k.startswith('EAP'):
                cur['stage'] = max(cur['stage'], STAGE['EAP'])
                cur['eap_events'] += 1
                cur['eap_first'] = cur['eap_first'] or e['t']
                if k == 'EAP_RESP':
                    cur['eap_resp'] += 1
                if k == 'EAP_REQ':
                    cur['eap_req'] += 1
                    cur['eap_req_types'].add(i.get('eap_type'))
                    if i.get('eap_id') in cur['eap_ids'] or i.get('eap_type') == 1 and cur['eap_req'] > 1:
                        cur['eap_req_repeats'] += 1       # authenticator resending: client not answering
                    cur['eap_ids'].append(i.get('eap_id'))
                if 'eap_type' in i:
                    cur['eap_types'].add(EAP_TYPES.get(i['eap_type'], str(i['eap_type'])))
                if k == 'EAP_FAILURE':
                    cur['eap_end'] = e['t']
                    close(cur, 'eap_failure', e['t'])
                    cur = None
                elif k == 'EAP_SUCCESS':
                    cur['eap_end'] = e['t']
            elif k.startswith('KEY_M'):
                cur['stage'] = max(cur['stage'], STAGE['KEY'])
                cur['max_key'] = max(cur['max_key'], int(k[-1]))
                cur['key_info'].append(i['key_info'])
                cur['key_uncertain'] += not i['key_certain']
                if k == 'KEY_M4':
                    cur['stage'] = STAGE['DONE']
                    close(cur, 'success', e['t'])
                    cur = None
            elif k in ('DEAUTH', 'DISASSOC'):
                close(cur, 'deauth_during_setup', e['t'], i.get('reason'), REASON.get(i.get('reason'), ''),
                      'AP' if e['from_ap'] else 'client')
                cur = None
        if cur:
            if capture_end - cur['last'] < IDLE_S:
                close(cur, 'in_progress_at_capture_end', cur['last'])
            elif cur['assoc_ok'] and not cur['eap_events'] and not cur['max_key'] \
                    and cur['bssid'] not in eapol_bssids:
                close(cur, 'associated_no_eapol_seen', cur['last'])
            else:
                close(cur, 'stalled', cur['last'])
    gaps = gaps or {}

    def near_gap(a, s):
        return any(g0 - IDLE_S <= a['last'] <= g1 + 1 for g0, g1 in gaps.get(s, []))
    for a in attempts:
        if a['outcome'] in ('stalled', 'restarted') and a['sensors'] and all(
                any(g0 - 1 <= a['last'] <= g1 and g0 < a['last'] + IDLE_S for g0, g1 in gaps.get(s, []))
                for s in a['sensors']):
            a['outcome'], a['hint'] = 'capture_gap', 'Sensor stopped capturing - outcome unknown, not a client failure'
        gap_sensors = [s for s in a['sensors'] if near_gap(a, s)]
        if a['outcome'] in ('success', 'auth_rejected', 'assoc_rejected', 'eap_failure', 'deauth_during_setup'):
            conf = 'high'                           # an explicit frame proves the outcome
        elif a['outcome'] == 'capture_gap' or gap_sensors:
            conf = 'low'
        elif a['outcome'] in ('stalled', 'restarted', 'abandoned_for_other_ap'):
            conf = 'medium'                         # inferred from silence
        else:
            conf = 'low'
        if a['key_uncertain'] and conf == 'high':
            conf = 'medium'
        a['confidence'] = conf
        a['sensor_first_seen'] = min(a['sensors']) if a['sensors'] else ''
        a['ssid'] = ssid_of.get(a['bssid'], '')
        a['duration_s'] = round(a['end'] - a['start'], 3)
        a['eap_duration_s'] = round(a['eap_end'] - a['eap_first'], 3) if a['eap_first'] and a['eap_end'] else None
    attempts.sort(key=lambda a: a['start'])
    disconnects.sort(key=lambda d: d['t'])
    return attempts, disconnects


FAILED = {'auth_rejected', 'assoc_rejected', 'eap_failure', 'deauth_during_setup', 'stalled', 'restarted',
          'abandoned_for_other_ap'}


def client_rollup(attempts, disconnects, client_signal, events):
    seen = collections.defaultdict(lambda: dict(sensors=set(), freqs=set(), bssids=[]))
    for e in events:
        c = seen[e['client']]
        c['sensors'] |= e['heard_by']
        if e['freq']:
            c['freqs'].add(e['freq'])
        if e['bssid'] and (not c['bssids'] or c['bssids'][-1] != e['bssid']):
            c['bssids'].append(e['bssid'])
    rows = []
    by_client = collections.defaultdict(list)
    for a in attempts:
        by_client[a['client']].append(a)
    dis = collections.Counter(d['client'] for d in disconnects)
    for client, c in seen.items():
        at = by_client.get(client, [])
        fails = [a for a in at if a['outcome'] in FAILED]
        fail_aps = {a['bssid'] for a in fails}
        codes = collections.Counter(a['code'] for a in fails if a['code'] is not None)
        why = collections.Counter(f"{a['stage_detail']}" + (f" ({a['code']}: {a['code_text']})" if a['code'] is not None else '')
                                  for a in fails)
        sig = sorted(client_signal.get(client, []))
        rows.append(dict(client=client, attempts=len(at), successes=sum(a['outcome'] == 'success' for a in at),
                         failures=len(fails), failure_rate=round(len(fails) / len(at), 3) if at else None,
                         failed_on_aps=len(fail_aps), codes=';'.join(f'{c}x{n}' for c, n in codes.most_common()),
                         retries_in_failed=sum(a['retries'] for a in fails),
                         signal_p10=sig[len(sig) // 10] if sig else None,
                         top_failure=why.most_common(1)[0][0] if why else '',
                         disconnects=dis.get(client, 0), distinct_bssids=len(set(c['bssids'])),
                         bssid_changes=max(0, len(c['bssids']) - 1), sensors=len(c['sensors']),
                         channels=sorted(freq_to_channel(f) for f in c['freqs']),
                         signal_median=sig[len(sig) // 2] if sig else None))
    rows.sort(key=lambda r: (-r['failures'], -r['attempts']))
    return rows


def sensor_overlap(overlap_keys):
    names = sorted(overlap_keys)
    out = []
    totals = {n: sum(len(s) for s in overlap_keys[n].values()) for n in names}
    for x in range(len(names)):
        for y in range(x + 1, len(names)):
            a, b = overlap_keys[names[x]], overlap_keys[names[y]]
            shared = 0
            for bucket, ks in a.items():
                other = b.get(bucket, set()) | b.get(bucket - 1, set()) | b.get(bucket + 1, set())
                shared += len(ks & other)
            denom = min(totals[names[x]], totals[names[y]]) or 1
            out.append(dict(sensor_a=names[x], sensor_b=names[y], shared_frames=shared,
                            shared_pct_of_smaller=round(100 * shared / denom, 2)))
    return out


# ----------------------------------------------------------------------------- output
def write_csv(path, rows, fields=None):
    if not rows:
        open(path, 'w').close()
        return
    fields = fields or list(rows[0].keys())
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow({k: (';'.join(map(str, sorted(v))) if isinstance(v, set) else ';'.join(map(str, v)) if isinstance(v, list) else v)
                        for k, v in r.items()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('folder')
    ap.add_argument('--out', default='airframe_results')
    ap.add_argument('--tz', default='Europe/Paris', help='display timezone for the report (data stays UTC)')
    ap.add_argument('--z', type=float, default=4.0, help='anomaly threshold (robust z-score)')
    args = ap.parse_args()
    tz = ZoneInfo(args.tz)
    loc = lambda t: datetime.datetime.fromtimestamp(t, tz).strftime('%H:%M:%S')
    os.makedirs(args.out, exist_ok=True)

    paths = sorted(glob.glob(os.path.join(args.folder, '*.pcap')) + glob.glob(os.path.join(args.folder, '*.cap')))
    if not paths:
        raise SystemExit(f'no .pcap files in {args.folder}')
    known_aps = scan_aps(paths)
    sensors, raw_events, client_signal, ssid_of, overlap_keys = ingest(paths, known_aps)
    events = dedupe(raw_events)
    eapol_bssids = {e['bssid'] for e in events if e['kind'].startswith(('EAP', 'KEY'))}
    capture_end = max(s['last'] for s in sensors.values())

    rows = minute_rows(sensors)
    for r in rows:
        r['minute_local'] = loc(r['minute_utc'])[:5]
    flags = detect(rows, min(3.0, args.z))
    same = collections.Counter((f['metric'], f['minute_utc']) for f in flags)
    flags = [f for f in flags if f['z'] >= args.z or same[(f['metric'], f['minute_utc'])] >= math.ceil(len(sensors) / 2)]
    incidents = group_incidents(flags, len(sensors))
    attempts, disconnects = build_attempts(events, eapol_bssids, ssid_of, capture_end,
                                           {n: s['gaps'] for n, s in sensors.items()})
    clients = client_rollup(attempts, disconnects, client_signal, events)
    overlap = sensor_overlap(overlap_keys)

    fails_sm = collections.Counter()
    for a in attempts:
        a['start_local'] = loc(a['start'])
        if a['outcome'] in FAILED:
            for s in a['sensors']:
                fails_sm[(s, int(a['start'] // 60) * 60)] += 1
    for r in rows:
        r['failed_attempts'] = fails_sm.get((r['sensor'], r['minute_utc']), 0)
    for inc in incidents:
        ins = [a for a in attempts if inc['start_utc'] <= a['start'] < inc['end_utc']]
        bad = [a for a in ins if a['outcome'] in FAILED]
        inc['attempts_in_window'] = len(ins)
        inc['failed_attempts_in_window'] = len(bad)
        inc['clients_failing_in_window'] = len({a['client'] for a in bad})
        chans = inc['channels']
        inc['bands'] = '+'.join(b for b, ok in (('2.4GHz', any(c <= 14 for c in chans)),
                                               ('5GHz-low', any(36 <= c <= 64 for c in chans)),
                                               ('5GHz-mid', any(100 <= c <= 144 for c in chans)),
                                               ('5GHz-high', any(149 <= c <= 177 for c in chans))) if ok)
    for i in incidents:
        i['start_local'], i['end_local'] = loc(i['start_utc'])[:5], loc(i['end_utc'])[:5]
    for d in disconnects:
        d['time_local'] = loc(d['t'])

    write_csv(os.path.join(args.out, 'minute_metrics.csv'), rows)
    write_csv(os.path.join(args.out, 'incidents.csv'), incidents)
    write_csv(os.path.join(args.out, 'attempts.csv'), attempts,
              ['start_local', 'start', 'client', 'confidence', 'bssid', 'ssid', 'outcome', 'stage_detail', 'code', 'code_text',
               'deauth_by', 'hint', 'duration_s', 'eap_duration_s', 'eap_req', 'eap_types', 'max_key',
               'key_info', 'key_uncertain', 'observed_from', 'n_events', 'eap_req_repeats', 'deauth_delay_s', 'retries', 'sensors', 'freqs'])
    write_csv(os.path.join(args.out, 'disconnects.csv'), disconnects,
              ['time_local', 't', 'client', 'bssid', 'kind', 'by', 'reason', 'reason_text', 'sensors'])
    write_csv(os.path.join(args.out, 'clients.csv'), clients)
    tl = []
    for e in sorted(events, key=lambda e: (e['client'], e['t'])):
        i = e['info']
        tl.append(dict(client=e['client'], time_local=loc(e['t']) + f"{e['t'] % 1:.3f}"[1:], t=e['t'], bssid=e['bssid'],
                       dir='AP->client' if e['from_ap'] else 'client->AP', kind=e['kind'],
                       detail=' '.join(f'{k}={v}' for k, v in i.items() if k not in ('eapol_type',)),
                       retry=e['retries'], copies=e['copies'], sensors=sorted(e['heard_by'])))
    write_csv(os.path.join(args.out, 'timelines.csv'), tl)
    write_csv(os.path.join(args.out, 'frame_overlap.csv'), overlap)

    # ---------------- report
    L = []
    p = L.append
    p(f'AIRFRAME ANALYSIS  ({len(sensors)} sensors, times in {args.tz})')
    p('')
    p('Sensors')
    for n, s in sorted(sensors.items()):
        qq = s['quality']
        p(f"  {n:<12} ch {s['channel']!s:>4} ({s['freq']} MHz)  {loc(s['first'])} - {loc(s['last'])}  "
          f"records {qq.get('records', 0):>8}  bad_radiotap {qq.get('bad_radiotap', 0)}  "
          f"bad_80211 {qq.get('bad_80211', 0)}  truncated {qq.get('truncated_records', 0)}  "
          f"eapol_cut_short {qq.get('eapol_truncated', 0)}")
    starts = [s['first'] for s in sensors.values()]
    for n, s in sorted(sensors.items()):
        for g0, g1 in s['gaps']:
            p(f"  CAPTURE GAP {n}: {loc(g0)} - {loc(g1)} ({g1 - g0:.0f}s) - no data, not an outage")
    p(f"  common window {loc(max(starts))} - {loc(min(s['last'] for s in sensors.values()))}, "
      f"start skew {max(starts) - min(starts):.1f}s")
    p('')
    p('Retry bit per sensor (median minute -> worst minute). Retries = retransmissions seen at the sensor,')
    p('not receiver-side loss. broadcast_retry should be ~0 in real 802.11; if not, the dataset marks retries on')
    p('broadcast frames and the unicast-only rate will under-report the event.')
    p('If probe_resp is flat but all-frames jumps, the jump is a traffic-mix effect (more probe responses), not')
    p('worse radio conditions.')
    p(f"  {'sensor':<10}{'unicast':>18}{'all frames':>18}{'mgmt':>18}{'probe_resp':>18}{'non-probe':>18}{'bcast_retry':>13}")
    for n in sorted(sensors):
        rs = [r for r in rows if r['sensor'] == n and not r['partial']]
        def mm(key, rs=rs):
            v = [r[key] for r in rs if r[key] is not None]
            if not v:
                return 'n/a'
            w = max(rs, key=lambda r: r[key] if r[key] is not None else -1)
            return f"{100 * statistics.median(v):.1f}->{100 * w[key]:.1f}@{w['minute_local']}"
        p(f"  {n:<10}{mm('uni_retry_rate'):>18}{mm('all_retry_rate'):>18}{mm('mgmt_retry_rate'):>18}"
          f"{mm('probe_resp_retry_rate'):>18}{mm('non_probe_retry_rate'):>18}{sum(r['broadcast_retry'] for r in rs):>13}")
    p('')
    p('Detected incidents (per-sensor robust baseline over the whole capture; partial edge minutes excluded)')
    if not incidents:
        p('  none above threshold')
    for i in incidents:
        p(f"  {i['start_local']}-{i['end_local']}  {i['metric']:<15} {i['scope']:<17} "
          f"{i['sensors_flagged']}/{len(sensors)} sensors  peak {i['peak_value']} vs baseline {i['peak_baseline']} "
          f"on {i['peak_sensor']} (z={i['peak_z']})  bands {i['bands']}  "
          f"failed attempts {i['failed_attempts_in_window']}/{i['attempts_in_window']}, "
          f"{i['clients_failing_in_window']} clients")
    p('')
    oc = collections.Counter(a['outcome'] for a in attempts)
    cc = collections.Counter(a['confidence'] for a in attempts if a['outcome'] in FAILED)
    p('Outcome meanings: *_rejected / eap_failure = explicit refusal frame seen; stalled = no progress for '
      f'{IDLE_S:.0f}s (no refusal seen); insufficient_observation = one frame only, not counted as failure;')
    p('  probable_success_client_unheard = AP sent M3 but the sensor never heard the client (not a failure);')
    p('  capture_gap = sensor stopped recording; in_progress_at_capture_end = cut off')
    p(f"Connection attempts: {len(attempts)}  " + '  '.join(f'{k}={v}' for k, v in oc.most_common()))
    p('  failure confidence: ' + '  '.join(f'{k}={v}' for k, v in cc.most_common()))
    of = collections.Counter(a['observed_from'] for a in attempts)
    p('  first frame observed: ' + '  '.join(f'{k}={v}' for k, v in of.most_common()))
    why = collections.Counter((a['outcome'], a['stage_detail'], a['code'], a['code_text']) for a in attempts
                              if a['outcome'] in FAILED)
    for (o, dtl, code, ct), n in why.most_common(10):
        extra = f'  [code {code}: {ct}]' if code is not None else ''
        p(f"  {n:>5}  {o:<22} {dtl}{extra}")
    p('')
    dr = collections.Counter((d['by'], d['kind'], d['reason'], d['reason_text']) for d in disconnects)
    p(f'Disconnects outside a setup attempt (after success, or setup not seen): {len(disconnects)}')
    for (by, kind, rc, rt), n in dr.most_common(8):
        ds = [d for d in disconnects if (d['by'], d['kind'], d['reason']) == (by, kind, rc)]
        aps = collections.Counter(d['bssid'] for d in ds)
        cl = len({d['client'] for d in ds})
        p(f'  {n:>5}  {kind} by {by}, reason {rc} ({rt})  clients {cl}  APs {len(aps)}  '
          f'top AP {aps.most_common(1)[0][0]} x{aps.most_common(1)[0][1]}  '
          f'{ds[0]["time_local"]}-{ds[-1]["time_local"]}')
    p('')
    p('Disconnects per minute (all, deduplicated) - by reason')
    top_r = list(dict.fromkeys(k[2] for k, _ in dr.most_common(6)))[:4]
    dm = collections.Counter((int(d['t'] // 60) * 60, d['reason']) for d in disconnects)
    for t0 in sorted({k[0] for k in dm}):
        p(f"  {loc(t0)[:5]}  " + '  '.join(f"r{r}={dm.get((t0, r), 0):>4}" for r in top_r))
    p('')
    p('Example timelines (full list in timelines.csv) - check these look like real sequences')
    by_c = collections.defaultdict(list)
    for r in tl:
        by_c[r['client']].append(r)
    shown = set()
    for want in ('deauth_during_setup', 'stalled', 'success', 'probable_success_client_unheard'):
        ex = next((a for a in attempts if a['outcome'] == want and a['client'] not in shown), None)
        if not ex:
            continue
        shown.add(ex['client'])
        p(f"  [{want}] client {ex['client']} bssid {ex['bssid']}")
        for r in [r for r in by_c[ex['client']] if ex['start'] - 1 <= r['t'] <= ex['end'] + LINK_S][:25]:
            p(f"    {r['time_local']}  {r['dir']:<11} {r['kind']:<12} {r['detail']}")
    p('')
    p('Clients with the most failures')
    for c in clients[:10]:
        if not c['failures']:
            break
        p(f"  {c['client']}  failures {c['failures']}/{c['attempts']}  {c['top_failure']}  "
          f"bssids {c['distinct_bssids']}  sensors {c['sensors']}  signal {c['signal_median']}")
    p('')
    p('Failures per minute (all sensors, deduplicated)')
    fm = collections.Counter(int(a['start'] // 60) * 60 for a in attempts if a['outcome'] in FAILED)
    am = collections.Counter(int(a['start'] // 60) * 60 for a in attempts)
    for t0 in sorted(am):
        p(f"  {loc(t0)[:5]}  attempts {am[t0]:>4}  failed {fm.get(t0, 0):>4}  " + '#' * min(60, fm.get(t0, 0)))
    p('')
    p('Frame overlap (identical frame heard by both sensors - expected ~0 for sensors on different channels;')
    p('cross-channel correlation of the same incident is in the incident list and failed_attempts per sensor-minute)')
    for o in sorted(overlap, key=lambda o: -o['shared_frames'])[:10]:
        p(f"  {o['sensor_a']} <-> {o['sensor_b']}: {o['shared_frames']} frames ({o['shared_pct_of_smaller']}%)")
    report = '\n'.join(L)
    print(report)
    with open(os.path.join(args.out, 'report.txt'), 'w') as f:
        f.write(report + '\n')

    def js(x):
        if isinstance(x, set):
            return sorted(x)
        raise TypeError(type(x))
    summary = dict(timezone=args.tz,
                   sensors={n: {k: v for k, v in s.items() if k != 'minutes'} for n, s in sensors.items()},
                   incidents=incidents, outcomes=dict(oc), top_clients=clients[:50],
                   disconnect_reasons=[dict(by=k[0], kind=k[1], reason=k[2], text=k[3], count=n)
                                       for k, n in dr.most_common()],
                   overlap=overlap)
    with open(os.path.join(args.out, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=1, default=js)
    print(f'\nwrote results to {args.out}/')
    dash = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'airframe_dashboard.py')
    if os.path.exists(dash):
        import importlib.util
        spec = importlib.util.spec_from_file_location('airframe_dashboard', dash)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.write(args.out)


if __name__ == '__main__':
    main()
