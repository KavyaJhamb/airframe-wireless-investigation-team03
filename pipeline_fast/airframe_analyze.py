#!/usr/bin/env python3
"""
airframe_analyze.py - header-only 802.11 / 802.1X analysis across multiple sensors.

Input: a folder of captures, one per sensor (.pcap, .cap or .pcapng; radiotap or plain 802.11),
       and/or edge files written by --edge.
Output (in --out):
  report.txt           human-readable summary (also printed)
  findings.csv         judgment rules -> findings, one per problem; many clients with the same problem at the same
                       time roll up under one parent: 802.1X/EAP, 4-way handshake and join failures, deauth loops
                       and floods, silent APs (beacon loss), congested channels, per-client probe storms
  attempts.csv         every client connection attempt as a state machine: auth -> assoc -> EAP -> 4-way,
                       with where it broke, the reason/status code and a confidence
  clients.csv          per-client roll-up          disconnects.csv  disconnects outside an attempt
  timelines.csv        every connection frame per client (for sequence views)
  minute_metrics.csv   per-sensor, per-minute counters (retry split by frame type, RSSI from histograms)
  incidents.csv        anomalies found in the data itself (robust per-sensor baselines, cross-sensor grouping)
  summary.json         machine-readable summary; dashboard.html if airframe_dashboard.py sits next to this file

Usage:
  python3 airframe_analyze.py CAPTURES --out results                  # full analysis, one process per core
  python3 airframe_analyze.py CAPTURES --out edge --edge              # sensor-side stage: compact edge files
  python3 airframe_analyze.py edge --out results                      # central stage from edge files
  --jobs N sets worker processes (default: one per core); --partitions N overrides the automatic split of the
  central stage (about 250k connection events per partition, so memory stays bounded at any fleet size)
  MACs (vendor prefix kept) and SSIDs are pseudonymised with a salted hash by default; with --edge nothing raw
  leaves the sensor stage. --no-mask keeps raw identifiers for internal debugging and the report says so

Header fields only; nothing is transmitted and no payload is read. Standard library only (Python 3.9+).
"""
import argparse, bisect, collections, concurrent.futures, csv, datetime, glob, gzip, heapq, hmac, json, math, os
import pickle, secrets, shutil, statistics, struct, tempfile, zlib
from zoneinfo import ZoneInfo

# ----------------------------------------------------------------------------- pcap reading
PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 10 ** 6), b'\xa1\xb2\xc3\xd4': ('>', 10 ** 6),     # ticks per second
    b'\x4d\x3c\xb2\xa1': ('<', 10 ** 9), b'\xa1\xb2\x3c\x4d': ('>', 10 ** 9),
}
LINKTYPE_80211, LINKTYPE_RADIOTAP, LINKTYPE_PRISM, LINKTYPE_AVS, LINKTYPE_PPI = 105, 127, 119, 163, 192
LINKTYPES = frozenset((LINKTYPE_80211, LINKTYPE_RADIOTAP, LINKTYPE_PRISM, LINKTYPE_AVS, LINKTYPE_PPI))
CAPTURE_EXTS = ('.pcap', '.cap', '.pcapng')         # each optionally .gz


def sensor_name(path):
    n = os.path.basename(path)
    n = n[:-3] if n.lower().endswith('.gz') else n
    return os.path.splitext(n)[0]


def _open_capture(path):
    f = open(path, 'rb', buffering=1 << 20)
    if f.peek(2)[:2] == b'\x1f\x8b':                     # gzip: read it in place, no temporary copy
        f.close()
        return gzip.open(path, 'rb')
    return f


def read_pcapng(f, path, q):
    """pcapng: Section Header, Interface Description and Enhanced Packet blocks. Other blocks are skipped."""
    ifaces, endian = [], '<'
    while True:
        h = f.read(8)
        if len(h) < 8:
            if h:
                q['truncated_records'] += 1
            return
        if h[:4] == b'\x0a\x0d\x0d\x0a':                      # section header: byte order comes from its body
            bom = f.read(4)
            endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            blen = struct.unpack(endian + 'I', h[4:8])[0]
            f.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + 'II', h)
        if blen < 12:
            q['truncated_records'] += 1
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            q['truncated_records'] += 1
            return
        body = body[:-4]
        if btype == 1:                                           # interface description
            lt = struct.unpack_from(endian + 'H', body, 0)[0]
            res, pos = 10 ** 6, 8                                   # ticks per second
            while pos + 4 <= len(body):
                code, olen = struct.unpack_from(endian + 'HH', body, pos)
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[pos + 4]
                    res = 2 ** (v & 0x7f) if v & 0x80 else 10 ** v
                pos += 4 + (olen + 3) // 4 * 4
            ifaces.append((lt, res))
        elif btype == 6 and len(body) >= 20:                     # enhanced packet
            iid, hi, lo, caplen, origlen = struct.unpack_from(endian + 'IIIII', body, 0)
            if iid >= len(ifaces) or ifaces[iid][0] not in LINKTYPES:
                q['skipped_other_linktype'] += 1
                continue
            lt, res = ifaces[iid]
            yield ((hi << 32) | lo) / res, lt, body[20:20 + caplen], origlen
        elif btype == 3:
            q['skipped_no_timestamp'] += 1                       # simple packet block has no timestamp


def read_pcap(path, q):
    """Yields (timestamp, linktype, frame bytes, original length), streaming: memory does not grow with file size."""
    with _open_capture(path) as f:
        gh = f.read(24)
        if gh[:4] == b'\x0a\x0d\x0d\x0a':
            f.seek(0)
            yield from read_pcapng(f, path, q)
            return
        if len(gh) < 24 or gh[:4] not in PCAP_MAGICS:
            raise ValueError(f'{path}: not a pcap file')
        endian, scale = PCAP_MAGICS[gh[:4]]
        linktype = struct.unpack(endian + 'I', gh[20:24])[0] & 0x0FFFFFFF
        if linktype not in LINKTYPES:
            raise ValueError(f'{path}: unsupported link type {linktype} (need 802.11, radiotap, Prism, AVS or PPI)')
        unpack, read = struct.Struct(endian + 'IIII').unpack, f.read
        while True:
            h = read(16)
            if not h:
                break
            if len(h) < 16:
                q['truncated_records'] += 1
                break
            sec, frac, caplen, origlen = unpack(h)
            d = read(caplen)
            if len(d) < caplen:
                q['truncated_records'] += 1
                break
            yield (sec * scale + frac) / scale, linktype, d, origlen      # exact integer ticks, one rounding


# ----------------------------------------------------------------------------- radiotap
# bit -> (alignment, size), namespace 0 only (radiotap.org defined fields)
RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1), 7: (2, 2),
             8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2),
             16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3), 20: (4, 8), 21: (2, 12), 22: (8, 12),
             23: (2, 12), 24: (2, 12), 25: (2, 6), 26: (1, 1), 27: (2, 4)}


_RT_CACHE = {}          # radiotap layout per (length, present words): nearly every frame of a capture shares one


def _rt_layout(d, words_end):
    rtlen = d[2] | d[3] << 8
    if rtlen < 8 or words_end > rtlen:
        return False
    w0 = d[4] | d[5] << 8 | d[6] << 16 | d[7] << 24
    pos, of, ofq, osg = words_end, -1, -1, -1
    # Fields are laid out in bit order; the ones we need (1,3,5) live in the first word,
    # so parse word 0 only and stop at the first field we cannot size.
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
            of = pos
        elif bit == 3:
            ofq = pos
        elif bit == 5:
            osg = pos
        pos += size
    return rtlen, of, ofq, osg


def parse_radiotap(d):
    """Returns (header_len, freq_mhz, signal_dbm, rt_flags) or None if malformed."""
    n = len(d)
    if n < 8:
        return None
    pos = 8
    while d[pos - 1] & 0x80:                         # extended presence bitmap: another 32-bit word follows
        pos += 4
        if pos > n:
            return None
    key = d[2:pos]
    lay = _RT_CACHE.get(key)
    if lay is None:
        lay = _rt_layout(d, pos)
        if len(_RT_CACHE) < 4096:
            _RT_CACHE[key] = lay
    if not lay:
        return None
    rtlen, of, ofq, osg = lay
    if rtlen > n:
        return None
    sig = d[osg] if osg >= 0 else None
    return (rtlen, (d[ofq] | d[ofq + 1] << 8) if ofq >= 0 else None,
            (sig - 256 if sig > 127 else sig) if sig is not None else None, d[of] if of >= 0 else 0)


def _chan_to_freq(c):
    return None if not c else 2484 if c == 14 else 2407 + 5 * c if c < 14 else 5000 + 5 * c if c < 200 else None


def link_header(lt, d):
    """(header_len, freq_mhz, signal_dbm, flags) for any supported link type; flags use radiotap bits
    (0x10 FCS at end, 0x40 bad FCS). None if the header is malformed."""
    if lt == LINKTYPE_RADIOTAP:
        return parse_radiotap(d)
    if lt == LINKTYPE_80211:
        return 0, None, None, 0
    n = len(d)
    if lt == LINKTYPE_PRISM:                  # msgcode, msglen, devname[16], then 12-byte DID items
        if n < 8:
            return None
        hl = struct.unpack_from('<I', d, 4)[0]
        if hl > n or hl < 24:
            return None
        freq = sig = None
        for pos in range(24, hl - 11, 12):
            did, status, ln, val = struct.unpack_from('<IHHi', d, pos)
            if status:                        # 0 = value present
                continue
            item = did & 0xFFF
            if item == 0x041:                 # channel
                freq = _chan_to_freq(val)
            elif item == 0x061:               # signal
                sig = val if -127 <= val <= 0 else None
        return hl, freq, sig, 0
    if lt == LINKTYPE_AVS:                    # big-endian, length at offset 4, channel at 36, ssi at 44
        if n < 64:
            return None
        hl = struct.unpack_from('>I', d, 4)[0]
        if hl > n or hl < 64:
            return None
        ch, ssi_type, ssi = struct.unpack_from('>IIi', d, 36)
        return hl, _chan_to_freq(ch), ssi if ssi_type == 1 and -127 <= ssi <= 0 else None, 0
    if lt == LINKTYPE_PPI:                    # little-endian TLVs; type 2 = 802.11-common
        if n < 8:
            return None
        hl = struct.unpack_from('<H', d, 2)[0]
        if hl > n or hl < 8:
            return None
        pos, freq, sig, flags = 8, None, None, 0
        while pos + 4 <= hl:
            t, ln = struct.unpack_from('<HH', d, pos)
            if t == 2 and ln >= 20 and pos + 4 + 20 <= hl:
                fl, freq = struct.unpack_from('<H2xH', d, pos + 12)
                s = d[pos + 20]
                sig = s - 256 if s > 127 else s
                flags = (0x10 if fl & 1 else 0) | (0x40 if fl & 4 else 0)
            pos += 4 + ln
        return hl, freq or None, sig, flags
    return None


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
    return b.hex(':')


def decode_ssid(raw):
    """SSIDs are bytes: UTF-8 in most networks, GB18030/GBK on many Chinese APs; anything else stays readable."""
    for enc in ('utf-8', 'gb18030'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode('latin-1')


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
          16: 'auth timeout', 17: 'AP full (cannot handle more clients)', 18: 'basic rates not supported',
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
                fr['info'] = dict(ssid=decode_ssid(body[p + 2:p + 2 + body[p + 1]]))
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
                    m = 4 if kdl == 0 else 2                    # M2 always carries the RSN/WPA IE; a WPA1 M4
                                                                # has no Secure bit and no key data
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
SILENT_S = 60.0        # no beacon from a BSSID for this long (while the sensor keeps capturing) = AP silent


def new_minute():
    return dict(frames=0, mgmt=0, ctrl=0, data=0, protected=0, bad_fcs=0, uni=0, uni_retry=0, retry=0,
                mgmt_retry=0, data_retry=0, bcast_retry=0, presp=0, presp_retry=0,
                beacon=0, probe_req=0, auth=0, auth_fail=0, assoc_req=0, assoc_fail=0, deauth=0, disassoc=0,
                eapol=0, eap_success=0, eap_failure=0, key_msgs=0, clients=set(), rssi=collections.Counter())


def scan_one(path):
    aps = set()
    q = collections.Counter()
    for ts, lt, d, origlen in read_pcap(path, q):
        off = 0
        if lt == LINKTYPE_RADIOTAP:
            if len(d) < 4:
                continue
            off = struct.unpack_from('<H', d, 2)[0]
        elif lt != LINKTYPE_80211:
            h = link_header(lt, d)
            if h is None:
                continue
            off = h[0]
        if len(d) >= off + 16 and d[off] in (0x80, 0x50):     # beacon / probe response
            aps.add(mac(d[off + 10:off + 16]))
    return aps


def ingest_one(path, known_aps, want_overlap=False):
    """Parse one sensor's capture into per-minute counters and connection-lifecycle events."""
    name = sensor_name(path)
    events, client_signal, ssid_of = [], collections.defaultdict(collections.Counter), {}
    q = collections.Counter()
    minutes = collections.defaultdict(new_minute)
    chans = collections.Counter()
    first = last = None
    prev_ts = None
    gaps = []
    keys = collections.defaultdict(set)
    bcn = {}                               # bssid -> [beacons, first, last, [(silent_from, silent_to)]]
    probes = collections.defaultdict(set)  # (client, (freq, 10 s window)) -> probe-request sequence numbers
    prot_seen = set()                      # (client, bssid, 10 s window) already represented by a DATA_PROT event
    kind_of = ('mgmt', 'ctrl', 'data', 'mgmt')
    m_t, m = None, None                    # current minute bucket (captures are time-ordered: almost always a hit)
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
        elif lt == LINKTYPE_80211:
            body = d
        else:
            rt = link_header(lt, d)
            if rt is None:
                q['bad_radiotap'] += 1
                continue
            rtlen, freq, signal, rtflags = rt
            body = d[rtlen:]
        if rtflags & 0x10 and len(d) == origlen and len(body) >= 4:   # FCS present and not truncated away
            body = body[:-4]
        blen = len(body)
        if blen < 10:
            q['bad_80211'] += 1
            continue
        fc0, fc1 = body[0], body[1]
        ftype, sub, retry, group1 = (fc0 >> 2) & 3, (fc0 >> 4) & 0xF, (fc1 >> 3) & 1, body[4] & 1
        if prev_ts is not None and ts - prev_ts > GAP_S:
            gaps.append((prev_ts, ts))
        prev_ts = ts
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts
        if freq:
            chans[freq] += 1
        mt = int(ts // 60) * 60
        if mt != m_t:
            m_t, m = mt, minutes[mt]
        m['frames'] += 1
        m[kind_of[ftype]] += 1
        if rtflags & 0x40:
            m['bad_fcs'] += 1
        if fc1 & 0x40:
            m['protected'] += 1
        if (ftype == 0 or ftype == 2) and not group1:
            m['uni'] += 1
            m['uni_retry'] += retry
        m['retry'] += retry
        if ftype == 0:
            m['mgmt_retry'] += retry
            if sub == 5:
                m['presp'] += 1
                m['presp_retry'] += retry
        elif ftype == 2:
            m['data_retry'] += retry
        if retry and group1:
            m['bcast_retry'] += 1          # unusual: broadcast frames are never retransmitted in real 802.11
        if signal is not None:
            m['rssi'][signal] += 1         # histogram: memory bounded by the dBm range, not frame count

        # Fast path: protected data (the bulk of traffic on a busy network) cannot carry EAPOL. Roles come from the
        # DS bits; one DATA_PROT event per client/AP per 10 s is kept as proof that a join worked.
        if ftype == 2 and fc1 & 0x40 and blen >= 24:
            ds = fc1 & 3
            if ds == 1 or ds == 2:
                if ds == 1:
                    client, bssid, from_ap = body[10:16].hex(':'), body[4:10].hex(':'), False
                elif group1:
                    client = None
                else:
                    client, bssid, from_ap = body[4:10].hex(':'), body[10:16].hex(':'), True
                if client:
                    m['clients'].add(client)
                    if not from_ap and signal is not None:
                        client_signal[client][signal] += 1
                    w = (client, bssid, int(ts // 10))
                    if w not in prot_seen:
                        prot_seen.add(w)
                        events.append(dict(t=ts, sensor=name, freq=freq, kind='DATA_PROT', client=client, bssid=bssid,
                                           from_ap=from_ap, retry=retry, seq=(body[22] | body[23] << 8) >> 4,
                                           ta=body[10:16].hex(':'), ra=body[4:10].hex(':'), info={}, signal=signal))
            if want_overlap:
                keys[int(ts // 10)].add(body[0:1] + body[4:16] + body[22:24])
            continue

        # Fast path: beacons and probe responses sent by an AP (~97% of frames) carry no connection event,
        # so they only update counters. Anything unusual falls through to the full parser below.
        if ftype == 0 and (sub == 8 or sub == 5) and blen >= 24:
            a2, a3 = body[10:16].hex(':'), body[16:22].hex(':')
            a1 = None if group1 else body[4:10].hex(':')
            if a2 in known_aps or (a2 == a3 and (a1 is None or a1 not in known_aps)):
                if a1:
                    m['clients'].add(a1)
                if sub == 8:
                    m['beacon'] += 1
                    b = bcn.get(a2)
                    if b is None:
                        bcn[a2] = [1, ts, ts, []]
                    else:
                        if ts - b[2] > SILENT_S:
                            b[3].append((b[2], ts))
                        b[0] += 1
                        b[2] = ts
                if a3 not in ssid_of:
                    off = 24 + (4 if fc1 & 0x80 else 0)
                    if blen - off >= 14 and body[off + 12] == 0 and off + 14 + body[off + 13] <= blen:
                        ssid = decode_ssid(body[off + 14:off + 14 + body[off + 13]])
                        if ssid:
                            ssid_of[a3] = ssid
                if want_overlap:              # raw header bytes, not hash(): stable across worker processes
                    keys[int(ts // 10)].add(body[0:1] + body[4:16] + body[22:24])
                continue

        fr = parse_frame(body)
        bssid, client, from_ap = roles(fr, known_aps)
        if client:
            m['clients'].add(client)
            if not from_ap and signal is not None:
                client_signal[client][signal] += 1
        s, i = fr['sub'], fr['info']
        if ftype == 0:
            if s == 8:
                m['beacon'] += 1
            elif s == 4:
                m['probe_req'] += 1
                if fr['a2'] and fr['seq'] is not None and not is_group(fr['a2']):
                    probes[(fr['a2'], (freq or 0, int(ts // PROBE_WINDOW_S) * PROBE_WINDOW_S))].add(fr['seq'])
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

        if want_overlap and ftype != 1 and blen >= 24:
            keys[int(ts // 10)].add(body[0:1] + body[4:16] + body[22:24])

        kind = classify_event(fr, from_ap) if client else None
        if kind:
            events.append(dict(t=ts, sensor=name, freq=freq, kind=kind, client=client, bssid=bssid,
                               from_ap=from_ap, retry=fr['retry'], seq=fr['seq'], ta=fr['a2'], ra=fr['a1'],
                               info=i, signal=signal))
    if first is None:
        return name, None, [], {}, {}, {}, {}
    main_freq = chans.most_common(1)[0][0] if chans else None
    sensor = dict(path=os.path.basename(path), first=first, last=last, minutes=dict(minutes), quality=dict(q), gaps=gaps,
                  freqs=dict(chans), freq=main_freq, channel=freq_to_channel(main_freq), beacons=bcn,
                  radio_of={b: b[:14] for b in bcn})        # same first 5 bytes = candidate for one physical AP
    return name, sensor, events, dict(client_signal), ssid_of, dict(keys), dict(probes)


EDGE_SCHEMA = 'airframe-edge/2'
EDGE_SCHEMAS = ('airframe-edge/1', EDGE_SCHEMA)     # /1 files still load (no beacon or probe detail)
EDGE_SUFFIX = '.airframe.jsonl.gz'


class Masker:
    """Salted pseudonyms, applied once per distinct identifier (memoised, so the cost does not grow with frames).
    The vendor prefix is kept for device grouping; the device half becomes a keyed hash. SSIDs become SSID-<hash>.
    Group addresses (broadcast/multicast) are not identifiers and stay as they are."""
    def __init__(self, salt):
        self.key, self.memo = salt.encode(), {}

    def mac(self, m):
        r = self.memo.get(m)
        if r is None:
            r = m if m is None or is_group(m) or '-' in m else \
                m[:8] + '-' + hmac.new(self.key, m.encode(), 'sha256').hexdigest()[:10]
            self.memo[m] = r
        return r

    def ssid(self, s):
        return 'SSID-' + hmac.new(self.key, b'ssid:' + s.encode(), 'sha256').hexdigest()[:8] if s else s


def load_salt(salt_file):
    if os.environ.get('AIRFRAME_SALT'):
        return os.environ['AIRFRAME_SALT']
    if os.path.exists(salt_file):
        with open(salt_file, encoding='utf-8') as f:
            return f.read().strip()
    salt = secrets.token_hex(16)
    with open(salt_file, 'w', encoding='utf-8') as f:
        f.write(salt)
    return salt


def mask_result(res, salt):
    name, sensor, events, cs, ssid_of, keys, probes = res
    if sensor is None or not salt or sensor.get('masked'):
        return res
    mk = Masker(salt)
    M = mk.mac
    for e in events:
        e['client'], e['bssid'], e['ta'], e['ra'] = M(e['client']), M(e['bssid']), M(e['ta']), M(e['ra'])
    for m in sensor['minutes'].values():
        m['clients'] = {M(c) for c in m['clients']}
    sensor['beacons'] = {M(b): v for b, v in sensor.get('beacons', {}).items()}
    sensor['radio_of'] = {M(b): 'R-' + hmac.new(mk.key, r.encode(), 'sha256').hexdigest()[:10]
                          for b, r in sensor.get('radio_of', {}).items()}
    sensor['masked'] = True
    return (name, sensor, events, {M(c): h for c, h in cs.items()}, {M(b): mk.ssid(s) for b, s in ssid_of.items()},
            keys, {(M(c), t): s for (c, t), s in probes.items()})


def write_edge(out_dir, result):
    """One compact file per sensor: sensor metadata + per-minute counters on the first line, then one line per
    connection-lifecycle event. This is what a sensor would ship instead of raw frames."""
    name, sensor, events, cs, ssid_of, _, probes = result
    head = dict(schema=EDGE_SCHEMA, name=name, sensor={k: v for k, v in sensor.items() if k != 'minutes'},
                minutes={str(t): dict(m, clients=sorted(m['clients']), rssi={str(k): v for k, v in m['rssi'].items()})
                         for t, m in sensor['minutes'].items()},
                client_signal={c: {str(k): v for k, v in h.items()} for c, h in cs.items()}, ssid_of=ssid_of,
                probes=[[c, f, t, sorted(s)] for (c, (f, t)), s in probes.items()])
    path = os.path.join(out_dir, name + EDGE_SUFFIX)
    with gzip.open(path, 'wt', encoding='utf-8', compresslevel=6) as f:
        f.write(json.dumps(head, separators=(',', ':')) + '\n')
        for e in events:
            f.write(json.dumps(e, separators=(',', ':')) + '\n')
    return path


def read_edge(path):
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        head = json.loads(f.readline())
        if head.get('schema') not in EDGE_SCHEMAS:
            raise ValueError(f'{path}: unknown edge schema {head.get("schema")}')
        events = [json.loads(line) for line in f]
    sensor = head['sensor']
    sensor['gaps'] = [tuple(g) for g in sensor['gaps']]
    sensor['beacons'] = {b: [v[0], v[1], v[2], [tuple(g) for g in v[3]]] for b, v in sensor.get('beacons', {}).items()}
    sensor['minutes'] = {}
    for t, m in head['minutes'].items():
        m['clients'] = set(m['clients'])
        m['rssi'] = collections.Counter({int(k): v for k, v in m['rssi'].items()})
        sensor['minutes'][int(t)] = m
    cs = {c: collections.Counter({int(k): v for k, v in h.items()}) for c, h in head['client_signal'].items()}
    probes = {(c, (f, t)): set(s) for c, f, t, s in head.get('probes', [])}
    return head['name'], sensor, events, cs, head['ssid_of'], {}, probes


def _edge_job(path, out_dir, salt=None):
    res = mask_result(ingest_one(path, frozenset(scan_one(path)), False), salt)
    return (write_edge(out_dir, res) if res[1] else None), os.path.getsize(path)


def _pool(jobs, n):
    jobs = max(1, min(jobs or os.cpu_count() or 1, n))
    return None if jobs == 1 else concurrent.futures.ProcessPoolExecutor(max_workers=jobs)


# ----------------------------------------------------------------------------- central stage: map / reduce
# Map: each capture (or edge file) is parsed on its own and its connection events are spilled to disk, split by a
# stable hash of the client MAC. Reduce: each partition holds every sensor's copy of its clients' frames, so
# dedupe, the connection state machine and the client roll-up run per partition with no coordination.
# Memory per worker is bounded by the partition size, not by the fleet size.
EVENTS_PER_PARTITION = 250_000
TL_FIELDS = ['client', 'time_local', 't', 'bssid', 'dir', 'kind', 'detail', 'retry', 'copies', 'sensors']


def _part(client, parts):
    return zlib.crc32(client.encode()) % parts       # stable across processes, unlike hash()


def make_loc(tzname):
    try:
        tz = ZoneInfo(tzname)
    except Exception:                   # Windows without the tzdata package
        tz = datetime.datetime.now().astimezone().tzinfo
    return lambda t: datetime.datetime.fromtimestamp(t, tz).strftime('%H:%M:%S')


def map_file(idx, path, known_aps, spill_dir, parts, want_overlap, salt=None):
    if path.endswith(EDGE_SUFFIX):
        res = read_edge(path)
    else:
        res = ingest_one(path, known_aps, want_overlap)
    name, sensor, events, cs, ssid_of, keys, probes = mask_result(res, salt)
    if sensor is None:
        return name, None, {}, {}, set(), 0
    buckets = collections.defaultdict(lambda: ([], {}, {}, name))
    for e in events:
        buckets[_part(e['client'], parts)][0].append(e)
    for c, h in cs.items():
        buckets[_part(c, parts)][1][c] = h
    for (c, t), s in probes.items():
        buckets[_part(c, parts)][2][(c, t)] = s
    for p, payload in buckets.items():
        with open(os.path.join(spill_dir, f'{p:05d}.{idx:06d}.pkl'), 'wb') as f:
            pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
    eapol_bssids = {e['bssid'] for e in events if e['kind'].startswith(('EAP', 'KEY'))}
    return name, sensor, ssid_of, keys, eapol_bssids, len(events)


PROBE_WINDOW_S = 10   # probe storm: at least PROBE_BURST distinct probe requests from one client on one channel
PROBE_BURST = 10      # in one window. A normal scan sends 1-2 per channel (the challenge captures peak at 4), so
                      # a scanning client is not a storm; a client hammering one channel is


def probe_storms(probes, sensors_of):
    """Per client: windows with at least PROBE_BURST distinct probe requests on one channel (sequence numbers
    dedupe retries and copies heard by several sensors on the same channel)."""
    per = collections.defaultdict(list)
    for (c, (f, t)), s in probes.items():
        if len(s) >= PROBE_BURST:
            per[c].append((t, f, len(s)))
    out = []
    for c, hot in per.items():
        hot.sort()
        out.append(dict(client=c, windows=[t for t, _, _ in hot], channels=sorted({freq_to_channel(f) for _, f, _ in hot
                                                                                   if f}),
                        probes=sum(n for _, _, n in hot), peak=max(n for _, _, n in hot), sensors=sorted(sensors_of[c])))
    return out


def reduce_part(p, spill_dir, eapol_bssids, ssid_of, capture_end, gaps, tzname):
    events, cs = [], collections.defaultdict(collections.Counter)
    probes, probe_sensors = collections.defaultdict(set), collections.defaultdict(set)
    for fn in sorted(glob.glob(os.path.join(spill_dir, f'{p:05d}.*.pkl'))):   # sensor order = input order
        with open(fn, 'rb') as f:
            ev, h, pr, sensor_name = pickle.load(f)
        os.remove(fn)
        events += ev
        for c, v in h.items():
            cs[c].update(v)
        for k, s in pr.items():
            probes[k] |= s
            probe_sensors[k[0]].add(sensor_name)
    storms = probe_storms(probes, probe_sensors)
    if not events and not cs:
        return [], [], [], None, storms
    events = dedupe(events)
    attempts, disconnects = build_attempts(events, eapol_bssids, ssid_of, capture_end, gaps)
    clients = client_rollup(attempts, disconnects, cs, events)
    loc = make_loc(tzname)
    tl_path = os.path.join(spill_dir, f'tl.{p:05d}.csv')
    with open(tl_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        for e in sorted(events, key=lambda e: (e['client'], e['t'])):
            w.writerow([e['client'], loc(e['t']) + f"{e['t'] % 1:.3f}"[1:], e['t'], e['bssid'],
                        'AP->client' if e['from_ap'] else 'client->AP', e['kind'],
                        ' '.join(f'{k}={v}' for k, v in e['info'].items() if k != 'eapol_type'),
                        e['retries'], e['copies'], ';'.join(sorted(e['heard_by']))])
    return attempts, disconnects, clients, tl_path, storms


def run_central(paths, out_dir, tzname, jobs=None, parts=None, want_overlap=False, salt=None):
    raw = [p for p in paths if not p.endswith(EDGE_SUFFIX)]
    est = sum(os.path.getsize(p) / (20 if p.endswith(EDGE_SUFFIX) else 25_600) for p in paths)
    parts = parts or max(1, min(4096, math.ceil(est / EVENTS_PER_PARTITION)))
    pool = _pool(jobs, max(len(paths), parts))
    run = (lambda fn, args: [fn(*a) for a in args]) if pool is None else \
        (lambda fn, args: list(pool.map(fn, *zip(*args))))
    spill = tempfile.mkdtemp(prefix='.spill-', dir=out_dir)
    try:
        known_aps = frozenset().union(*run(scan_one, [(p,) for p in raw])) if raw else frozenset()
        sensors, ssid_of, overlap_keys, eapol_bssids = {}, {}, {}, set()
        for name, sensor, so, keys, eb, _ in run(map_file, [(i, p, known_aps, spill, parts, want_overlap, salt)
                                                            for i, p in enumerate(paths)]):
            if sensor is None:
                print(f'WARNING: {name}: no parseable frames')
                continue
            sensors[name] = sensor
            for k, v in so.items():
                ssid_of.setdefault(k, v)
            overlap_keys[name] = keys
            eapol_bssids |= eb
        if not sensors:
            raise SystemExit('no parseable frames in any input')
        capture_end = max(s['last'] for s in sensors.values())
        gaps = {n: s['gaps'] for n, s in sensors.items()}
        res = run(reduce_part, [(p, spill, frozenset(eapol_bssids), ssid_of, capture_end, gaps, tzname)
                                for p in range(parts)])
        attempts = list(heapq.merge(*[r[0] for r in res], key=lambda a: a['start']))
        disconnects = list(heapq.merge(*[r[1] for r in res], key=lambda d: d['t']))
        clients = sorted((c for r in res for c in r[2]), key=lambda r: (-r['failures'], -r['attempts'], r['client']))
        storms = sorted((s for r in res for s in r[4]), key=lambda s: -s['probes'])
        with open(os.path.join(out_dir, 'timelines.csv'), 'wb') as f:          # binary: parts are copied verbatim
            f.write((','.join(TL_FIELDS) + '\r\n').encode())
            for r in res:
                if r[3]:
                    with open(r[3], 'rb') as g:
                        shutil.copyfileobj(g, f, 1 << 20)
    finally:
        if pool:
            pool.shutdown()
        shutil.rmtree(spill, ignore_errors=True)
    return sensors, attempts, disconnects, clients, overlap_keys, parts, storms, ssid_of


# ----------------------------------------------------------------------------- minute metrics + anomaly detection
RATE_METRICS = {'uni_retry_rate': 'unicast', 'all_retry_rate': 'frames', 'mgmt_retry_rate': 'mgmt',
                'data_retry_rate': 'data', 'probe_resp_retry_rate': 'probe_resp',
                'non_probe_retry_rate': 'non_probe_unicast'}
METRICS = ['uni_retry_rate', 'all_retry_rate', 'mgmt_retry_rate', 'data_retry_rate', 'probe_resp_retry_rate',
           'probe_resp', 'frames', 'deauth', 'disassoc', 'auth_fail', 'assoc_fail', 'eap_failure', 'probe_req']


def hist_at(h, idx_fn):
    """Value at sorted position idx_fn(n) of a {value: count} histogram (same as sorted(list)[idx_fn(n)])."""
    n = sum(h.values())
    if not n:
        return None
    k, cum = idx_fn(n), 0
    for v in sorted(h):
        cum += h[v]
        if cum > k:
            return v


def minute_rows(sensors):
    rows = []
    for name, s in sensors.items():
        for t0, m in sorted(s['minutes'].items()):
            cover = min(t0 + 60, s['last']) - max(t0, s['first'])
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
                             signal_median=hist_at(m['rssi'], lambda n: n // 2),
                             signal_p10=hist_at(m['rssi'], lambda n: n // 10)))
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
CLIENT_LEFT_S = 5.0    # a client deauth this early in an unstuck setup is the client leaving, not a network failure,
CLIENT_FAIL_REASONS = {13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 34}   # unless it names a security failure


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
        'client_left': 'Client ended the setup itself (leaving) before anything went wrong - not a network failure',
        'assoc_comeback': 'AP asked the client to retry shortly (status 30, PMF SA Query) - normal, not a failure',
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
    if o == 'assoc_comeback':
        return 'assoc deferred (come back later)'
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
                    eap_req_types=set(), eap_resp=0, client_frames=0, max_key=0, key_uncertain=0, key_info=[], key_seq='',
                    sensors=set(), freqs=set(), retries=0, outcome=None, code=None, code_text='', deauth_by=None,
                    via_data=False)

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
            if k == 'DATA_PROT':                 # encrypted data between the two: keys are in place, the join worked
                if cur and cur['bssid'] == e['bssid'] and (cur['assoc_ok'] or cur['stage'] >= STAGE['EAP']):
                    cur['via_data'] = True
                    cur['sensors'] |= e['heard_by']
                    close(cur, 'success', e['t'])
                    cur = None
                continue
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
                if i.get('status', 0) != 0:          # 30 = come back later (PMF SA Query): not a refusal
                    close(cur, 'assoc_comeback' if i['status'] == 30 else 'assoc_rejected', e['t'], i['status'],
                          STATUS.get(i['status'], ''))
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
                n = int(k[-1])
                if n == 2 and cur['max_key'] >= 3:   # WPA1 M4 looks like M2 when its key data is cut off
                    n, k = 4, 'KEY_M4'
                cur['stage'] = max(cur['stage'], STAGE['KEY'])
                cur['max_key'] = max(cur['max_key'], n)
                cur['key_seq'] += f'M{n}'
                cur['key_info'].append(i['key_info'])
                cur['key_uncertain'] += not i['key_certain']
                if k == 'KEY_M4':
                    cur['stage'] = STAGE['DONE']
                    close(cur, 'success', e['t'])
                    cur = None
            elif k in ('DEAUTH', 'DISASSOC'):
                # the client saying "leaving" early in a setup that was not stuck is the user/device going away
                left = not e['from_ap'] and i.get('reason') not in CLIENT_FAIL_REASONS and not cur['eap_req_repeats'] \
                    and e['t'] - cur['start'] < CLIENT_LEFT_S
                close(cur, 'client_left' if left else 'deauth_during_setup', e['t'], i.get('reason'),
                      REASON.get(i.get('reason'), ''), 'AP' if e['from_ap'] else 'client')
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
        if a['key_uncertain'] and conf == 'high' or a['via_data']:
            conf = 'medium'
        if a['via_data']:
            a['stage_detail'] = f"joined: encrypted data seen ({a['key_seq'] or 'no key messages'} captured)"
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


JOINED = {'success', 'probable_success_client_unheard'}


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
        sig = client_signal.get(client) or {}
        joined = [a['bssid'] for a in at if a['outcome'] in JOINED]     # attempts are in time order
        roams = sum(x != y for x, y in zip(joined, joined[1:]))
        rows.append(dict(client=client, attempts=len(at), successes=sum(a['outcome'] == 'success' for a in at),
                         failures=len(fails), failure_rate=round(len(fails) / len(at), 3) if at else None,
                         failed_on_aps=len(fail_aps), codes=';'.join(f'{c}x{n}' for c, n in codes.most_common()),
                         retries_in_failed=sum(a['retries'] for a in fails),
                         signal_p10=hist_at(sig, lambda n: n // 10),
                         top_failure=why.most_common(1)[0][0] if why else '',
                         disconnects=dis.get(client, 0), distinct_bssids=len(set(c['bssids'])),
                         bssid_changes=max(0, len(c['bssids']) - 1), roams=roams, sensors=len(c['sensors']),
                         channels=sorted(freq_to_channel(f) for f in c['freqs']),
                         signal_median=hist_at(sig, lambda n: n // 2)))
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


# ----------------------------------------------------------------------------- findings (judgment rules)
# Each rule turns evidence already computed above into findings a network engineer can act on. One client with one
# problem is one finding; many clients with the same problem at the same time become one parent finding with the
# clients as children, so a site-wide outage reads as one incident, not as sixty.
LOOP_MIN = 5            # AP-sent disconnects to one client, outside any setup, before it counts as a loop
LOOP_MAX_IVL_S = 120.0  # ... with a median spacing no longer than this
FLOOD_IVL_S = 2.0       # median spacing below this = flood (a burst of frames), above = loop (join, kicked, repeat)
ROLLUP_MIN = 5          # clients with the same finding at the same time -> one parent finding
SILENT_ROLLUP = 3       # APs going silent within a minute of each other -> one parent (power, switch, controller)
CONGEST_RETRY = 0.25    # non-probe unicast retry rate that makes a congested minute ...
CONGEST_FRAMES = 60     # ... with at least this many non-probe unicast frames in it
CONGEST_MINUTES = 2     # ... for at least this many minutes on one sensor
SILENT_TOL_S = 2.0      # sensor clock skew allowed when checking that no other sensor heard the AP
FINDING_FIELDS = ['id', 'parent', 'children', 'severity', 'category', 'title', 'client', 'ap', 'ssid', 'count', 'start_local',
                  'end_local', 'start', 'end', 'channels', 'sensors', 'tags', 'explanation']
SEV_ORDER = {'critical': 0, 'serious': 1, 'warning': 2, 'info': 3}


def _finding(sev, cat, title, explanation, count, start, end, client='', ap='', ssid='', channels=(), sensors=(),
             tags=(), kids=()):
    return dict(severity=sev, category=cat, title=title, explanation=explanation, count=count, start=start, end=end,
                client=client, ap=ap, ssid=ssid, channels=';'.join(map(str, sorted(set(channels)))),
                sensors=';'.join(sorted(set(sensors))), tags=';'.join(tags), kids=list(kids))


def _codes_text(fs, top=3):
    c = collections.Counter((a['code'], a['code_text'], a['deauth_by']) for a in fs if a['code'] is not None)
    return ', '.join(f"{by + ' ' if by else ''}{'reason' if by else 'status'} {code} "
                     f"({txt.split(': ', 1)[-1] if txt.startswith('then ') else txt}) x{n}"
                     for (code, txt, by), n in c.most_common(top))


def failure_category(a):
    o = a['outcome']
    if o in ('auth_rejected', 'assoc_rejected'):
        return 'Join failure'
    if o == 'eap_failure' or (a['eap_events'] and not a['max_key']):
        return '802.1X / EAP failure'
    if a['max_key']:
        return '4-way handshake failure'
    return 'Join failure'


def failure_findings(attempts, loc, cut_by=None):
    """cut_by: {(client, reason): (loop finding, loop start)}. A join attempt ended before login by the same AP
    disconnect that is looping on that client is part of the loop, not a join problem of its own."""
    per = collections.defaultdict(list)
    joined_by_ssid = collections.Counter()
    cut_by = cut_by or {}
    for a in attempts:
        if a['outcome'] in FAILED:
            hit = cut_by.get((a['client'], a['code'])) if a['deauth_by'] == 'AP' else None
            if hit and failure_category(a) == 'Join failure' and a['end'] >= hit[1] - LOOP_MAX_IVL_S:
                hit[0]['_cut'] = hit[0].get('_cut', 0) + 1
                continue
            per[(failure_category(a), a['client'])].append(a)
        elif a['outcome'] in JOINED:
            joined_by_ssid[a['ssid']] += 1
    kids = []
    for (cat, client), fs in per.items():
        aps = collections.Counter(a['bssid'] for a in fs)
        ssid = collections.Counter(a['ssid'] for a in fs).most_common(1)[0][0]
        heard = sum(a['client_frames'] for a in fs)
        answered = sum(a['eap_resp'] for a in fs)
        ended = _codes_text(fs)
        on = f"{len(fs)} attempt{'s' if len(fs) > 1 else ''} on {len(aps)} AP{'s' if len(aps) > 1 else ''}"
        tags = []
        if cat == '802.1X / EAP failure':
            loops = sum(a['stage_detail'].startswith('EAP identity loop') for a in fs)
            rejected = sum(a['outcome'] == 'eap_failure' for a in fs)
            parts = [on]
            if rejected:
                parts.append(f"authentication server sent EAP-Failure {rejected}x")
                tags.append('EAP-Failure')
            if loops:
                parts.append(f"{loops} identity loop{'s' if loops > 1 else ''}: the AP asked for the identity "
                             f"{sum(a['eap_req'] for a in fs)}x and never started the EAP method")
                tags.append('identity loop')
            if answered:
                parts.append(f"client answered {answered} EAP request{'s' if answered > 1 else ''}")
                tags.append('client answered')
            elif not heard:
                parts.append('the client itself was never heard by a sensor (AP side only)')
                tags.append('AP side only')
            else:
                parts.append('client was heard but never answered EAP')
                tags.append('client silent')
            if ended:
                parts.append(f"ended by {ended}")
            title = f"802.1X failing for {client} on {ssid or 'unknown SSID'}"
        elif cat == '4-way handshake failure':
            seq = collections.Counter(a['key_seq'] for a in fs).most_common(1)[0][0]
            detail = collections.Counter(a['stage_detail'] for a in fs).most_common(1)[0][0]
            parts = [on, f"key messages seen {seq} ({detail})"]
            if ended:
                parts.append(f"ended by {ended}")
            parts.append(hint_for('stalled', detail))
            tags.append(detail)
            title = f"4-way handshake failing for {client} on {ssid or 'unknown SSID'}"
        else:
            detail = collections.Counter(a['stage_detail'] for a in fs).most_common(1)[0][0]
            parts = [on, f"{detail}" + (f": {ended}" if ended else '')]
            tags.append(detail)
            title = f"{client} cannot join {ssid or 'unknown SSID'}"
        kids.append(_finding('warning' if len(fs) > 1 else 'info', cat, title, '; '.join(parts) + '.', len(fs),
                             min(a['start'] for a in fs), max(a['end'] for a in fs), client=client,
                             ap=';'.join(b for b, _ in aps.most_common()), ssid=ssid,
                             channels=[freq_to_channel(f) for a in fs for f in a['freqs']],
                             sensors=[s for a in fs for s in a['sensors']], tags=tags))
        kids[-1]['_attempts'] = fs
    groups = collections.defaultdict(list)
    for k in kids:
        groups[(k['category'], k['ssid'])].append(k)
    out = []
    for (cat, ssid), ks in groups.items():
        fs = [a for k in ks for a in k.pop('_attempts')]
        aps = {a['bssid'] for a in fs}
        if len(ks) < ROLLUP_MIN or len(aps) < 2:
            out += ks
            continue
        audible = [a for a in fs if a['client_frames']]
        parts = [f"{len(ks)} clients failed on {ssid or 'an unknown SSID'} across {len(aps)} APs "
                 f"({len(fs)} attempts, {loc(min(a['start'] for a in fs))}-{loc(max(a['end'] for a in fs))})"]
        if _codes_text(fs):
            parts.append(f"ended by {_codes_text(fs)}")
        top = collections.Counter(a['stage_detail'] for a in fs).most_common(1)[0]
        parts.append(f"most common: {top[0]} ({top[1]} of {len(fs)})")
        if cat == '802.1X / EAP failure' and audible:
            parts.append(f"clients answered in {sum(1 for a in audible if a['eap_resp'])} of {len(audible)} failed "
                         f"attempts where a sensor could hear them, so the clients are not the problem")
        others = [f"{s} ({n} joined)" for s, n in joined_by_ssid.most_common() if s != ssid and n]
        if others:
            parts.append('other SSIDs are connecting: ' + ', '.join(others[:3]))
        out.append(_finding('critical' if cat == '802.1X / EAP failure' else 'serious', cat,
                            f"{cat.split(' /')[0]} failing for {len(ks)} clients on {ssid or 'unknown SSID'} "
                            f"across {len(aps)} APs", '; '.join(parts) + '.', len(ks),
                            min(k['start'] for k in ks), max(k['end'] for k in ks), ap=';'.join(sorted(aps)),
                            ssid=ssid, channels=[c for k in ks for c in k['channels'].split(';') if c],
                            sensors=[s for k in ks for s in k['sensors'].split(';') if s], tags=['systemic'], kids=ks))
    return out


def loop_findings(disconnects, attempts, loc):
    per = collections.defaultdict(list)
    for d in disconnects:
        if d['by'] == 'AP':
            per[d['client']].append(d)
    joins = collections.defaultdict(list)
    for a in attempts:
        if a['outcome'] in JOINED:
            joins[a['client']].append(a['end'])
    kids = []
    for c, ds in per.items():
        if len(ds) < LOOP_MIN:
            continue
        ts = [d['t'] for d in ds]
        ivl = statistics.median(y - x for x, y in zip(ts, ts[1:]))
        if ivl > LOOP_MAX_IVL_S:
            continue
        kind = collections.Counter(d['kind'] for d in ds).most_common(1)[0][0].capitalize()
        (rc, rt), _ = collections.Counter((d['reason'], d['reason_text']) for d in ds).most_common(1)[0]
        aps = collections.Counter(d['bssid'] for d in ds)
        rejoined = sum(ts[0] <= t <= ts[-1] for t in joins[c])
        span = ts[-1] - ts[0]
        where = f"from {'the same AP' if len(aps) == 1 else f'{len(aps)} APs'}"
        if ivl < FLOOD_IVL_S:
            title = f"{kind} flood on {c}: {len(ds)} frames in {span:.0f} s"
            expl = (f"{len(ds)} {kind.lower()} frames {where}, reason {rc} ({rt}), {loc(ts[0])}-{loc(ts[-1])}, "
                    f"one every {ivl:.2f} s. A real AP sends one; a burst like this is a misbehaving AP/controller "
                    f"or a spoofed (forged) disconnect attack. Frames are not authenticated in the capture, "
                    f"so which one needs AP logs.")
            sev, tags = 'serious', ['flood', 'spoofing not checked']
        else:
            title = f"{kind} loop on {c}: kicked every ~{ivl:.0f} s"
            expl = (f"{len(ds)} {kind.lower()} frames {where}, reason {rc} ({rt}), {loc(ts[0])}-{loc(ts[-1])}, "
                    f"about every {ivl:.0f} s" + (f"; the client rejoined {rejoined}x in between and was kicked "
                                                  f"again" if rejoined else '') + '.')
            sev, tags = 'warning', ['loop']
        kids.append(_finding(sev, 'Deauth / disassoc loop', title, expl, len(ds), ts[0], ts[-1], client=c,
                             ap=';'.join(b for b, _ in aps.most_common()),
                             sensors=[s for d in ds for s in d['sensors']], tags=tags + [f'reason {rc}']))
        kids[-1]['_reason'], kids[-1]['_ivl'], kids[-1]['_ds'] = (rc, rt), ivl, ds
    by_reason = collections.defaultdict(list)
    for k in kids:
        by_reason[k['_reason']].append(k)
    out = []
    for (rc, rt), ks in by_reason.items():
        ds = sorted((d for k in ks for d in k['_ds']), key=lambda d: d['t'])
        ivls = sorted(k.pop('_ivl') for k in ks)
        for k in ks:
            del k['_ds'], k['_reason']
        if len(ks) < ROLLUP_MIN:
            out += ks
            continue
        pairs = len({(d['client'], d['bssid']) for d in ds})
        groups = collections.Counter(k['client'][:8] for k in ks)
        mins = max(1.0, (ds[-1]['t'] - ds[0]['t']) / 60)
        out.append(_finding(
            'serious', 'Deauth / disassoc loop', f"APs keep disconnecting {len(ks)} clients (reason {rc}) from "
            f"{loc(ds[0]['t'])}",
            f"{len(ds)} AP-sent disconnect frames with reason {rc} ({rt}) to {len(ks)} clients, {loc(ds[0]['t'])}-"
            f"{loc(ds[-1]['t'])} (about {len(ds) / mins:.0f} per minute); each client about every "
            f"{ivls[0]:.0f}-{ivls[-1]:.0f} s" + ('; every client is always disconnected by the same AP'
                                                   if pairs == len(ks) else '') +
            f"; client groups: {', '.join(f'{g} x{n}' for g, n in groups.most_common(3))}.",
            len(ks), ds[0]['t'], ds[-1]['t'], ap=';'.join(sorted({d['bssid'] for d in ds})),
            sensors=[s for d in ds for s in d['sensors']], tags=['wave', f'reason {rc}'], kids=ks))
    return out


def _heard_inside(obs, a, b):
    """Did this sensor hear a beacon from the BSSID strictly between a and b?"""
    n, f, l, gaps = obs
    if a >= b or f >= b or l <= a:
        return False
    if a < f or l < b:
        return True
    return not any(g0 <= a and g1 >= b for g0, g1 in gaps)


def silent_ap_findings(sensors, ssid_of, loc):
    per = collections.defaultdict(list)
    for name, s in sensors.items():
        for bssid, v in s.get('beacons', {}).items():
            per[bssid].append((name, v, s))
    found = []
    for bssid, obs in per.items():
        cands = []
        for name, (n, f, l, gaps), s in obs:
            thr = max(SILENT_S, 50 * (l - f) / max(n - 1, 1))       # 50 of this sensor's usual beacon spacing
            ivs = [(x, y, True) for x, y in gaps if y - x >= thr]
            if s['last'] - l >= thr:
                ivs.append((l, s['last'], False))                    # not heard again before this capture ends
            for x, y, back in ivs:
                down = sum(max(0.0, min(y, g1) - max(x, g0)) for g0, g1 in s['gaps'])
                if down <= 0.1 * (y - x):                            # the sensor itself kept capturing
                    cands.append((x, y, back, name))
        merged = []
        for x, y, back, name in sorted(cands):
            if any(_heard_inside(v, x + SILENT_TOL_S, y - SILENT_TOL_S) for _, v, _ in obs):
                continue                                             # another sensor still heard it
            if merged and x <= merged[-1][1]:
                merged[-1][1], merged[-1][2] = max(merged[-1][1], y), merged[-1][2] and back
                merged[-1][3].add(name)
            else:
                merged.append([x, y, back, {name}])
        for x, y, back, names in merged:
            mins = max(1, round((y - x) / 60))
            ssid = ssid_of.get(bssid, '')
            chans = [sensors[n]['channel'] for n in names]
            found.append(_finding(
                'warning', 'AP silent / beacon loss',
                f"AP {bssid}{' (' + ssid + ')' if ssid else ''} silent for {mins} min"
                + (' then back' if back else ', not heard again'),
                f"No beacon from {bssid} {loc(x)}-{loc(y)} ({y - x:.0f} s) while {', '.join(sorted(names))} kept "
                f"capturing; {len(obs)} sensor{'s hear' if len(obs) > 1 else ' hears'} this AP and none heard it in that "
                f"window. " + ('It came back afterwards (reboot, power or uplink loss).' if back else
                               'It had not come back when the capture ended.'),
                mins, x, y, ap=bssid, ssid=ssid, channels=chans, sensors=names,
                tags=['came back' if back else 'not back']))
    found.sort(key=lambda f: f['start'])
    out, i = [], 0
    while i < len(found):
        j = i
        while j + 1 < len(found) and found[j + 1]['start'] - found[i]['start'] <= 60:
            j += 1
        ks = found[i:j + 1]
        if len(ks) >= SILENT_ROLLUP:
            out.append(_finding(
                'serious', 'AP silent / beacon loss', f"{len(ks)} APs went silent at {loc(ks[0]['start'])}",
                f"{len(ks)} APs stopped beaconing within a minute of each other ({loc(ks[0]['start'])}): a shared "
                f"cause such as a power, switch or controller event is more likely than {len(ks)} separate faults.",
                len(ks), ks[0]['start'], max(k['end'] for k in ks), ap=';'.join(k['ap'] for k in ks),
                channels=[c for k in ks for c in k['channels'].split(';') if c],
                sensors=[s for k in ks for s in k['sensors'].split(';') if s], tags=['shared cause'], kids=ks))
        else:
            out += ks
        i = j + 1
    return out


def congestion_findings(rows, loc):
    bad = collections.defaultdict(list)
    base = []
    for r in rows:
        if r['partial'] or r['non_probe_unicast'] < CONGEST_FRAMES or r['non_probe_retry_rate'] is None:
            continue
        (bad[r['sensor']] if r['non_probe_retry_rate'] >= CONGEST_RETRY else base).append(r)
    out = []
    for sensor, rs in bad.items():
        if len(rs) < CONGEST_MINUTES:
            continue
        peak = max(rs, key=lambda r: r['non_probe_retry_rate'])
        ref = statistics.median(r['non_probe_retry_rate'] for r in base) if base else None
        ch = rs[0]['channel']
        out.append(_finding(
            'warning', 'Congestion / channel health',
            f"Channel {ch} congested: up to {100 * peak['non_probe_retry_rate']:.0f}% of frames retried",
            f"{len(rs)} minutes on {sensor} (channel {ch}) with at least {100 * CONGEST_RETRY:.0f}% of unicast frames "
            f"retransmitted (probe responses excluded), peak {100 * peak['non_probe_retry_rate']:.0f}% at "
            f"{loc(peak['minute_utc'])[:5]}" + (f"; healthy minutes elsewhere median {100 * ref:.1f}%" if ref is not None
                                                  else '') + '. Look for interference, overlapping APs or a busy channel.',
            len(rs), rs[0]['minute_utc'], rs[-1]['minute_utc'] + 60, channels=[ch], sensors=[sensor],
            tags=['retries']))
    return out


def probe_findings(storms, loc):
    kids = []
    for s in storms:
        n = len(s['windows'])
        kids.append(_finding(
            'warning' if n >= 3 else 'info', 'Probe storm',
            f"Probe storm from {s['client']}: {s['peak']} probe requests in {PROBE_WINDOW_S} s on one channel",
            f"{s['probes']} probe requests in {n} burst{'s' if n > 1 else ''} of at least {PROBE_BURST} per "
            f"{PROBE_WINDOW_S} s on one channel (copies and retries removed), first at {loc(s['windows'][0])}. "
            f"A normal scan sends one or two per channel; a client hammering a channel like this has a driver or "
            f"roaming problem and takes airtime from everyone on it.",
            s['probes'], s['windows'][0], s['windows'][-1] + PROBE_WINDOW_S, client=s['client'],
            channels=s['channels'], sensors=s['sensors'], tags=['client scanning']))
        kids[-1]['_minutes'] = {int(t // 60) * 60 for t in s['windows']}
    out, left = [], kids
    while left:
        cnt = collections.Counter(m for k in left for m in k['_minutes'])
        m, n = cnt.most_common(1)[0]
        if n < ROLLUP_MIN:
            break
        ks = [k for k in left if m in k['_minutes']]
        left = [k for k in left if m not in k['_minutes']]
        out.append(_finding(
            'warning', 'Probe storm', f"{len(ks)} clients in probe storms at {loc(m)[:5]}",
            f"{len(ks)} clients each hammered a channel with probe requests in the same minute ({loc(m)[:5]}): "
            f"a shared trigger (coverage loss, an AP going away, a pushed driver or profile) is likely.",
            len(ks), min(k['start'] for k in ks), max(k['end'] for k in ks),
            channels=[c for k in ks for c in k['channels'].split(';') if c],
            sensors=[x for k in ks for x in k['sensors'].split(';') if x], tags=['many clients'], kids=ks))
    out += left
    for k in kids:
        k.pop('_minutes', None)
    return out


OVERLAP_MIN_APS = 4      # co-channel overlap: at least this many APs on one channel ...
OVERLAP_FACTOR = 1.5     # ... and this many times the median of the other channels
MIN_BEACONS = 10         # a BSSID must be heard beaconing this often to count as an AP on a channel
JOIN_BURST_MIN = 6       # join burst: at least this many attempts per SSID in a minute, and 3x the usual rate


def overlap_findings(sensors, ssid_of):
    """APs per channel. BSSIDs are one physical AP only if they share a MAC block (first 5 bytes) and a channel and
    advertise different SSIDs, so an AP with two SSIDs counts once and neighbouring APs never merge."""
    where = {}                                             # bssid -> (beacons, channel, radio key, sensor)
    for name, s in sensors.items():
        radio_of = s.get('radio_of', {})
        for b, v in s.get('beacons', {}).items():
            if v[0] >= MIN_BEACONS and s['channel'] and v[0] > where.get(b, (0,))[0]:
                where[b] = (v[0], s['channel'], radio_of.get(b, b), name)
    groups = collections.defaultdict(list)
    for b, (_, ch, radio, name) in where.items():
        groups[(ch, radio)].append((b, name))
    per_ch = collections.defaultdict(lambda: [0, 0, set()])
    for (ch, _), members in groups.items():
        per_ch[ch][0] += max(collections.Counter(ssid_of.get(b, '') for b, _ in members).values())
        per_ch[ch][1] += len(members)
        per_ch[ch][2].update(n for _, n in members)
    if len(per_ch) < 2:
        return []
    out = []
    for ch, (aps, bss, names) in sorted(per_ch.items()):
        med = statistics.median(v[0] for c, v in per_ch.items() if c != ch)
        if aps >= max(OVERLAP_MIN_APS, OVERLAP_FACTOR * med):
            out.append(_finding(
                'warning', 'Co-channel overlap', f"Channel {ch}: {aps} APs share it",
                f"{aps} APs ({bss} networks beaconing) are on channel {ch}, against a median of {med:g} on the other "
                f"channels. Every client and AP on this channel contends for the same airtime, and beacons alone take "
                f"a bigger share of it. A channel re-plan is a configuration change.", aps,
                min(sensors[n]['first'] for n in names), max(sensors[n]['last'] for n in names), channels=[ch],
                sensors=names, tags=['channel plan']))
    return out


def join_burst_findings(attempts, sensors, loc):
    """Many join attempts on one SSID within a minute or two, far above its usual rate: a reconnect wave that
    usually follows an AP, controller or authentication event rather than individual client problems."""
    if not attempts or not sensors:
        return []
    t0 = min(s['first'] for s in sensors.values())
    last = int((max(s['last'] for s in sensors.values()) - t0) // 60)
    per = collections.defaultdict(lambda: collections.defaultdict(list))
    for a in attempts:
        per[a['ssid']][int((a['start'] - t0) // 60)].append(a)
    out = []
    for ssid, mins in per.items():
        counts = [len(mins.get(m, ())) for m in range(last + 1)]
        thresh = max(JOIN_BURST_MIN, 3 * statistics.median(counts) + 1)
        hot = [m for m in range(1, last + 1) if counts[m] >= thresh]      # minute 0 is capture warm-up
        runs = []
        for m in hot:
            if runs and m - runs[-1][-1] <= 1:
                runs[-1].append(m)
            else:
                runs.append([m])
        for run in runs:
            sub = [a for m in run for a in mins[m]]
            rest = [c for m, c in enumerate(counts) if m not in run]
            clients = {a['client'] for a in sub}
            out.append(_finding(
                'warning', 'Join burst', f"{ssid or 'unknown SSID'}: {len(sub)} join attempts from {len(clients)} "
                f"clients in {len(run)} min",
                f"Outside this wave {ssid or 'the SSID'} averages {sum(rest) / max(1, len(rest)):.1f} join attempts per "
                f"minute; here {len(sub)} attempts from {len(clients)} clients hit {len({a['bssid'] for a in sub})} APs "
                f"within {len(run)} minute{'s' if len(run) > 1 else ''} ({loc(min(a['start'] for a in sub))}). A "
                f"reconnect wave like this usually follows an AP, controller or authentication event.",
                len(sub), min(a['start'] for a in sub), max(a['end'] for a in sub), ssid=ssid,
                sensors=[x for a in sub for x in a['sensors']], tags=['reconnect wave']))
    return out


def build_findings(attempts, disconnects, sensors, rows, storms, ssid_of, loc):
    loops = loop_findings(disconnects, attempts, loc)
    cut_by = {}
    for f in loops:
        for k in f['kids'] or [f]:
            rc = next((int(t[7:]) for t in k['tags'].split(';') if t.startswith('reason ') and t[7:].isdigit()), None)
            cut_by[(k['client'], rc)] = (f, k['start'])
    fails = failure_findings(attempts, loc, cut_by)
    for f in loops:
        n = f.pop('_cut', 0)
        if n:
            f['explanation'] += (f" {n} further join attempt{'s were' if n > 1 else ' was'} cut short by the same "
                                 f"disconnects before login started.")
    top = (fails + loops + silent_ap_findings(sensors, ssid_of, loc) + congestion_findings(rows, loc) +
           probe_findings(storms, loc) + overlap_findings(sensors, ssid_of) + join_burst_findings(attempts, sensors, loc))
    top.sort(key=lambda f: (SEV_ORDER[f['severity']], -len(f['kids']), -f['count'], f['start']))
    out = []
    for f in top:
        f['id'], f['parent'] = f'F{len(out) + 1:04d}', ''
        out.append(f)
        for k in sorted(f['kids'], key=lambda k: (-k['count'], k['start'])):
            k['id'], k['parent'] = f'F{len(out) + 1:04d}', f['id']
            out.append(k)
    for f in out:
        f['children'] = len(f.pop('kids'))
        f['start_local'], f['end_local'] = loc(f['start']), loc(f['end'])
    return out


# ----------------------------------------------------------------------------- output
def write_csv(path, rows, fields=None):
    if not rows:
        open(path, 'w', encoding='utf-8').close()
        return
    fields = fields or list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
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
    ap.add_argument('--jobs', type=int, default=0, help='parallel worker processes (default: one per CPU core)')
    ap.add_argument('--partitions', type=int, default=0,
                    help='client partitions for the central stage (default: automatic, ~250k events each)')
    ap.add_argument('--edge', action='store_true',
                    help='sensor-side stage only: turn each capture into a compact edge file in --out and stop. '
                         'Run again without --edge on a folder of edge files to analyze them centrally')
    ap.add_argument('--overlap', action='store_true', help='also count identical frames heard by sensor pairs '
                                                           '(memory-heavy at scale; off by default)')
    ap.add_argument('--no-mask', action='store_true',
                    help='keep raw MAC addresses and SSIDs (internal debugging only; the report says so). By default '
                         'they are pseudonymised as they are parsed: vendor prefix kept, the rest a salted hash; '
                         'with --edge, raw identifiers never leave the sensor stage')
    ap.add_argument('--mask', action='store_true', help=argparse.SUPPRESS)       # the default; kept for old scripts
    ap.add_argument('--salt-file', default='.airframe_salt',
                    help='salt for masking ($AIRFRAME_SALT wins; created on first use - keep it private)')
    args = ap.parse_args()
    salt = None if args.no_mask else load_salt(args.salt_file)
    try:
        tz = ZoneInfo(args.tz)
    except Exception:                   # Windows without the tzdata package
        tz = datetime.datetime.now().astimezone().tzinfo
        print(f'WARNING: timezone {args.tz} not available (on Windows run: pip install tzdata). '
              f'Using this computer\'s local time instead.')
    loc = lambda t: datetime.datetime.fromtimestamp(t, tz).strftime('%H:%M:%S')
    os.makedirs(args.out, exist_ok=True)

    exts = tuple('*' + e + z for e in CAPTURE_EXTS for z in ('', '.gz')) + (() if args.edge else ('*' + EDGE_SUFFIX,))
    paths = sorted({p for ext in exts for p in glob.glob(os.path.join(args.folder, ext))})
    if not paths:
        raise SystemExit(f'no .pcap / .pcapng / edge files in {args.folder}')
    if args.edge:
        pool = _pool(args.jobs, len(paths))
        jobs = [(p, args.out, salt) for p in paths]
        done = list(map(lambda a: _edge_job(*a), jobs)) if pool is None else list(pool.map(_edge_job, *zip(*jobs)))
        if pool:
            pool.shutdown()
        tot_in = sum(sz for _, sz in done)
        tot_out = sum(os.path.getsize(p) for p, _ in done if p)
        for (p, sz) in done:
            if p:
                print(f'  {os.path.basename(p):<40} {os.path.getsize(p) / 1e3:>9.1f} KB  (capture {sz / 1e6:.1f} MB)')
        print(f'edge files: {tot_out / 1e6:.2f} MB from {tot_in / 1e6:.1f} MB of captures '
              f'({tot_in / max(tot_out, 1):.0f}x smaller). Analyze with: airframe_analyze.py {args.out} --out results')
        return
    sensors, attempts, disconnects, clients, overlap_keys, parts, storms, ssid_of = run_central(
        paths, args.out, args.tz, args.jobs, args.partitions, args.overlap, salt)
    masked = all(s.get('masked') for s in sensors.values())

    rows = minute_rows(sensors)
    for r in rows:
        r['minute_local'] = loc(r['minute_utc'])[:5]
    flags = detect(rows, min(3.0, args.z))
    same = collections.Counter((f['metric'], f['minute_utc']) for f in flags)
    flags = [f for f in flags if f['z'] >= args.z or same[(f['metric'], f['minute_utc'])] >= math.ceil(len(sensors) / 2)]
    incidents = group_incidents(flags, len(sensors))
    overlap = sensor_overlap(overlap_keys) if args.overlap else []

    fails_sm = collections.Counter()
    for a in attempts:
        a['start_local'] = loc(a['start'])
        if a['outcome'] in FAILED:
            for s in a['sensors']:
                fails_sm[(s, int(a['start'] // 60) * 60)] += 1
    for r in rows:
        r['failed_attempts'] = fails_sm.get((r['sensor'], r['minute_utc']), 0)
    starts = [a['start'] for a in attempts]                    # attempts are sorted by start
    for inc in incidents:
        ins = attempts[bisect.bisect_left(starts, inc['start_utc']):bisect.bisect_left(starts, inc['end_utc'])]
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
    findings = build_findings(attempts, disconnects, sensors, rows, storms, ssid_of, loc)

    write_csv(os.path.join(args.out, 'minute_metrics.csv'), rows)
    write_csv(os.path.join(args.out, 'incidents.csv'), incidents)
    write_csv(os.path.join(args.out, 'attempts.csv'), attempts,
              ['start_local', 'start', 'client', 'confidence', 'bssid', 'ssid', 'outcome', 'stage_detail', 'code', 'code_text',
               'deauth_by', 'hint', 'duration_s', 'eap_duration_s', 'eap_req', 'eap_types', 'max_key',
               'key_info', 'key_uncertain', 'observed_from', 'n_events', 'eap_req_repeats', 'deauth_delay_s', 'retries', 'sensors', 'freqs',
               'key_seq', 'eap_resp', 'client_frames'])
    write_csv(os.path.join(args.out, 'disconnects.csv'), disconnects,
              ['time_local', 't', 'client', 'bssid', 'kind', 'by', 'reason', 'reason_text', 'sensors'])
    write_csv(os.path.join(args.out, 'clients.csv'), clients)
    write_csv(os.path.join(args.out, 'findings.csv'), findings, FINDING_FIELDS)
    if args.overlap:
        write_csv(os.path.join(args.out, 'frame_overlap.csv'), overlap)

    # ---------------- report
    L = []
    p = L.append
    p(f'AIRFRAME ANALYSIS  ({len(sensors)} sensors, times in {args.tz})')
    p('Identifiers: ' + ('MACs keep only their vendor prefix (rest a salted hash), SSIDs hashed, EAP identities never '
                         'read' if masked else 'RAW MAC addresses and SSIDs (--no-mask) - do not share this output'))
    p('')
    p('Findings (full list with explanations in findings.csv)')
    if not findings:
        p('  none')
    for f in findings:
        if not f['parent']:
            p(f"  [{f['severity'].upper():<8}] {f['title']}" + (f"  ({f['children']} clients/APs)" if f['children'] else ''))
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
    shown, examples = set(), []
    for want in ('deauth_during_setup', 'stalled', 'success', 'probable_success_client_unheard'):
        ex = next((a for a in attempts if a['outcome'] == want and a['client'] not in shown), None)
        if ex:
            shown.add(ex['client'])
            examples.append((want, ex))
    by_c = collections.defaultdict(list)
    if examples:                                                   # stream the file: it can be large
        with open(os.path.join(args.out, 'timelines.csv'), encoding='utf-8') as f:
            for r in csv.DictReader(f):
                if r['client'] in shown:
                    r['t'] = float(r['t'])
                    by_c[r['client']].append(r)
    for want, ex in examples:
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
    if args.overlap:
        p('Frame overlap (identical frame heard by both sensors - expected ~0 for sensors on different channels;')
        p('cross-channel correlation of the same incident is in the incident list and failed_attempts per sensor-minute)')
        for o in sorted(overlap, key=lambda o: -o['shared_frames'])[:10]:
            p(f"  {o['sensor_a']} <-> {o['sensor_b']}: {o['shared_frames']} frames ({o['shared_pct_of_smaller']}%)")
    report = '\n'.join(L)
    print(report)
    with open(os.path.join(args.out, 'report.txt'), 'w', encoding='utf-8') as f:
        f.write(report + '\n')

    def js(x):
        if isinstance(x, set):
            return sorted(x)
        raise TypeError(type(x))
    summary = dict(timezone=args.tz,
                   sensors={n: {k: v for k, v in s.items() if k not in ('minutes', 'beacons', 'radio_of')}
                            for n, s in sensors.items()},
                   incidents=incidents, outcomes=dict(oc), top_clients=clients[:50], masked=masked,
                   roams=sum(c['roams'] for c in clients),
                   findings=[{k: f[k] for k in ('id', 'severity', 'category', 'title', 'count', 'children')}
                             for f in findings if not f['parent']],
                   disconnect_reasons=[dict(by=k[0], kind=k[1], reason=k[2], text=k[3], count=n)
                                       for k, n in dr.most_common()],
                   overlap=overlap)
    with open(os.path.join(args.out, 'summary.json'), 'w', encoding='utf-8') as f:
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
