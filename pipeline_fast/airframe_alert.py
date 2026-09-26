#!/usr/bin/env python3
"""
airframe_alert.py - turn airframe_analyze.py output into operational alerts (Slack/Teams style).

Every number comes from the result CSVs, using the same rules as the dashboard, so alert and dashboard agree.
Nothing is sent anywhere: alerts are printed and written to alerts.md and alerts.json.

Usage:
  python3 airframe_alert.py results_folder
  python3 airframe_alert.py results_folder --workflows workflows.json   # optional, see below

workflows.json (optional) maps a client MAC prefix to what those devices do, e.g.
  {"3c:58:c2": "handheld scanners, goods-in", "f0:18:98": "office laptops"}
Without it, alerts say which device groups are affected and that workflow impact needs confirming.
"""
import collections, datetime, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('airframe_dashboard', os.path.join(HERE, 'airframe_dashboard.py'))
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)

try:
    from zoneinfo import ZoneInfo
except ImportError:                      # pragma: no cover
    ZoneInfo = None


def local(t, tz):
    try:
        return datetime.datetime.fromtimestamp(t, ZoneInfo(tz)).strftime('%H:%M:%S')
    except Exception:
        return datetime.datetime.fromtimestamp(t).strftime('%H:%M:%S')


def first_fire(items, window, min_events, min_distinct):
    """items: sorted [(t, distinct_key)]. First time a sliding window holds enough events and distinct keys."""
    q = collections.deque()
    for t, k in items:
        q.append((t, k))
        while q and t - q[0][0] > window:
            q.popleft()
        if len(q) >= min_events and len({x[1] for x in q}) >= min_distinct:
            return t, len(q), len({x[1] for x in q})
    return None


def groups_text(macs, workflows):
    g = collections.Counter(m[:8] for m in macs)
    parts = []
    for p, n in g.most_common():
        name = D.OUI.get(p)
        label = f"{p}{' (' + name + ')' if name else ''}: {n} clients"
        if workflows.get(p):
            label += f" - {workflows[p]}"
        parts.append(label)
    return parts


def build_alerts(folder, workflows):
    data = D.build(folder)
    at = D.rd(folder, 'attempts.csv')
    dis = D.rd(folder, 'disconnects.csv')
    tz = data['tz']
    cap_end = max(s['last'] for s in data['sensors'])
    alerts = []
    for f in data['findings']:
        kind = f['kind']
        facts = dict(f['facts'])
        if kind == 'auth':
            loop_all = [a for a in at if (a['stage_detail'] or '').startswith('EAP identity loop')]
            loop = [a for a in loop_all if a['outcome'] in D.FAILED]
            cut = len(loop_all) - len(loop)
            ends = sorted((float(a['start']) + float(a['duration_s'] or 0), a['bssid']) for a in loop)
            fire = first_fire(ends, 120, 3, 3)
            clients = {a['client'] for a in loop}
            first, last = ends[0][0], ends[-1][0]
            ongoing = cap_end - last < 120
            high = sum(a['confidence'] == 'high' for a in loop)
            by_code = collections.Counter(a['code'] for a in loop)
            wave = next((g for g in data['findings'] if g['kind'] == 'wave'), None)
            wave_rc = wave['lead'].split('(reason ')[1].split(')')[0] if wave else None
            wave_clients = {d['client'] for d in dis if d['by'] == 'AP' and d['reason'] == wave_rc} if wave else set()
            split = [f"{by_code.get('23', 0)} ended by the AP's 802.1X timeout (reason 23)"]
            for rc, n in by_code.most_common():
                if rc in ('23', '') or not n:
                    continue
                cut_by = {a['client'] for a in loop if a['code'] == rc}
                split.append(f"{n} cut short by " + ("the rejection wave" + (" (same clients)" if cut_by <= wave_clients
                                                                              else "")
                                                     if rc == wave_rc else "an AP disconnect")
                             + f" (reason {rc}: {D.REASON.get(int(rc), '') if rc.isdigit() else rc})")
            if by_code.get(''):
                split.append(f"{by_code['']} stalled with no disconnect seen")
            alerts.append(dict(
                severity='CRITICAL', kind=kind,
                title=f"802.1X logins failing at the Identity step on {', '.join(sorted({a['ssid'] for a in loop}))}",
                fired_at=local(fire[0], tz) if fire else None,
                detect_delay_s=round(fire[0] - first) if fire else None, delay_of='the first failed login',
                observed=[
                    f"{len(loop)} failed login attempts from {len(clients)} clients on {facts.get('APs affected')} APs, "
                    f"{local(first, tz)}-{local(last, tz)}" + (f", plus {cut} cut off by the end of the capture" if cut else "")
                    + (" - still failing when the capture ends" if ongoing else ""),
                    "Of these: " + ", ".join(split),
                    "Every EAP request the APs send is an Identity request; no AP ever starts the login method",
                    f"Clients answer when the sensors can hear them: {facts.get('Clients that answered when audible')}",
                    f"AP re-asks every {facts.get('AP re-asks every')}, then deauths: {facts.get('Ended by AP deauth')}",
                    "No EAP-Success frame anywhere in the capture" if 'never' in f['title'] else
                    "Few EAP-Success frames in the capture",
                ],
                consistent_with="The APs get no answer from the authentication server path (RADIUS or the link to it)",
                not_proven=["Whether the server is down, unreachable or misconfigured",
                            "Business impact (no payload or application data in the captures)"],
                owner="Network identity / RADIUS team",
                next_checks=["RADIUS server health and request/timeout logs for the incident window",
                             "Controller-to-RADIUS reachability and shared-secret/certificate changes",
                             "Controller authentication logs for the affected APs"],
                confidence=f"High that logins fail at the auth-server step ({high} of {len(loop)} attempts end in an "
                           f"explicit AP deauth); which component failed needs server-side logs",
                affected=groups_text(clients, workflows), example=f['example']))
        elif kind == 'wave':
            rc = [r for r in f['lead'].split('(reason ')[1].split(')')[:1]][0]
            ds = sorted((float(d['t']), d['client']) for d in dis if d['by'] == 'AP' and d['reason'] == rc)
            fire = first_fire(ds, 60, 5, 3)
            clients = {c for _, c in ds}
            alerts.append(dict(
                severity='SERIOUS', kind=kind, title=f['title'],
                fired_at=local(fire[0], tz) if fire else None,
                detect_delay_s=round(fire[0] - ds[0][0]) if fire else None, delay_of='the first rejection',
                observed=[f"{facts.get('Disconnect frames')} disconnect frames with reason {rc} "
                          f"({D.REASON.get(int(rc), '')}) from {facts.get('Start')} to capture end",
                          f"{facts.get('Clients / AP pairs')} clients / AP pairs, each client always rejected by the same AP",
                          f"About {facts.get('Rate after start')} across the site"],
                consistent_with="APs no longer hold valid authentication state for these clients (controller or AP-side change)",
                not_proven=["What changed on the controller at the start time", "Whether the clients notice",
                            "That the real APs sent these frames: no spoofing check is run (802.11 management "
                            "frames are not authenticated unless PMF/802.11w is on)"],
                owner="WLAN controller team",
                next_checks=[f"Controller and AP event logs around {facts.get('Start')}",
                             "Config pushes, reboots or session-table events at that time",
                             "Why only this client group is affected"],
                confidence="High that the APs send these rejections; cause needs controller logs",
                affected=groups_text(clients, workflows), example=f['example']))
        elif kind == 'storm':
            i0 = f['window'][0]
            alerts.append(dict(
                severity='INFO', kind=kind, title=f['title'],
                fired_at=data['labels'][i0] + ':00' if i0 is not None else None, detect_delay_s=None,
                observed=[f"{k}: {v}" for k, v in f['facts']],
                consistent_with="Many clients scanning for a new AP at once, e.g. after being kicked off",
                not_proven=["A radio problem: probe-response retry stays flat, so the retry rise is a traffic-mix effect"]
                if 'Retry, probe responses' in facts else ["The trigger of the scan wave"],
                owner="WLAN operations (for information)",
                next_checks=["Line up with the other alerts: is this clients reacting to failed logins?"],
                confidence="High for the traffic change; no RF fault indicated",
                affected=[], example=None))
    covered = {f['kind'] for f in data['findings']}
    fnd = D.rd(folder, 'findings.csv')
    members_of = collections.defaultdict(list)
    for k in fnd:
        if k['parent'] and k['client']:
            members_of[k['parent']].append(k['client'])
    for f in fnd:
        if f['parent'] or f['severity'] == 'info':
            continue
        if ('auth' in covered and f['category'] == '802.1X / EAP failure' and f['children'] not in ('', '0')) or \
                ('wave' in covered and 'wave' in f['tags'].split(';')):
            continue
        g = GENERIC[f['category']]
        flood = 'flood' in f['tags'].split(';')
        members = members_of[f['id']]
        planning = f['category'] == 'Co-channel overlap'           # a re-plan item, not something to page for
        alerts.append(dict(
            severity='INFO' if planning else f['severity'].upper(), kind=f['category'], title=f['title'],
            fired_at=None if planning else f['start_local'],
            detect_delay_s=None, observed=[f['explanation']],
            consistent_with=g['flood'] if flood else g['why'], not_proven=g['not_proven'], owner=g['owner'],
            next_checks=g['checks_flood'] if flood else g['checks'],
            confidence="High for what the sensors saw; the cause needs the owner's logs",
            affected=groups_text(members or ([f['client']] if f['client'] else []), workflows),
            example=f['client'] or (members[0] if members else None)))
    return data, alerts


# Wording for alerts built from findings.csv (the analyzer's per-category judgment rules)
_LOOP_CHECKS = ["Controller/AP logs for this client: why is it being disconnected", "Client's auth/session state on "
                "the controller (stale session, ACL or role change)"]
GENERIC = {
    'Deauth / disassoc loop': dict(
        why="The AP/controller keeps rejecting this client's session", flood="A misbehaving AP/controller, or forged "
        "disconnect frames (a deauth attack)", owner="WLAN controller team",
        not_proven=["That the real AP sent the frames (no spoofing check is run)"], checks=_LOOP_CHECKS,
        checks_flood=["Is PMF (802.11w) enabled on this SSID? It blocks forged disconnects",
                      "AP/controller logs: did the AP really send these?", "Physical check near the client for a "
                      "rogue transmitter if the AP did not"]),
    'AP silent / beacon loss': dict(
        why="The AP lost power, rebooted, lost its uplink or was switched off", flood='', owner="Network operations",
        not_proven=["Which of power, PoE, uplink or AP crash (no AP logs in the captures)"],
        checks=["AP uptime and last reboot reason", "PoE switch port and power logs", "Controller AP-down events"],
        checks_flood=[]),
    'Congestion / channel health': dict(
        why="A busy or noisy channel: overlapping APs, non-Wi-Fi interference or too many clients", flood='',
        owner="RF / WLAN design", not_proven=["The source of the interference (needs a spectrum analysis)"],
        checks=["Channel plan and neighbouring APs on this channel", "Spectrum scan near the sensor",
                "Client count per AP on this channel"], checks_flood=[]),
    'Probe storm': dict(
        why="A client driver or roaming problem, or clients searching for coverage", flood='',
        owner="Endpoint / device team", not_proven=["Which driver or setting causes it"],
        checks=["Driver/firmware version on the device", "Roaming and scan settings", "Coverage where the device is"],
        checks_flood=[]),
    'Join failure': dict(
        why="The AP refuses or ignores the join (capacity, policy or capability mismatch)", flood='',
        owner="WLAN operations", not_proven=["The AP's internal reason beyond the status code"],
        checks=["AP client limits and load balancing", "SSID security/capability settings vs the client"],
        checks_flood=[]),
    '4-way handshake failure': dict(
        why="Key mismatch between client and AP (wrong PSK, PMF/cipher mismatch)", flood='',
        owner="Endpoint / device team", not_proven=["That the PSK is wrong (keys are not visible)"],
        checks=["PSK configured on the device vs the SSID", "PMF and cipher settings on both sides"],
        checks_flood=[]),
    'Co-channel overlap': dict(
        why="Too many APs on one channel for the airtime available", flood='', owner="RF / WLAN design",
        not_proven=["That users notice it today (no airtime or throughput data in header captures)"],
        checks=["Channel plan: move APs to quieter channels", "Transmit power and AP density in this area"],
        checks_flood=[]),
    'Join burst': dict(
        why="Many clients reconnecting at once after an AP, controller or authentication event", flood='',
        owner="WLAN operations", not_proven=["What triggered the reconnects"],
        checks=["Controller and AP events just before the burst", "Other findings in the same minutes"],
        checks_flood=[]),
    '802.1X / EAP failure': dict(
        why="The authentication server rejects or does not answer this client", flood='',
        owner="Network identity / RADIUS team", not_proven=["Credential vs certificate vs policy cause"],
        checks=["RADIUS logs for this client", "Client certificate / credential validity"], checks_flood=[]),
}


def render(a, slack=False):
    b = (lambda s: f"*{s}*") if slack else (lambda s: s.upper())
    L = [f"[{a['severity']}] {a['title']}"]
    if a['fired_at']:
        L.append(f"Detected at {a['fired_at']}" + (f" ({a['detect_delay_s']} s after {a.get('delay_of')})"
                                                    if a['detect_delay_s'] is not None else ""))
    L.append(b('Observed'))
    L += [f"  • {x}" for x in a['observed']]
    L.append(f"{b('Most consistent with')}: {a['consistent_with']}")
    L.append(b('Not proven'))
    L += [f"  • {x}" for x in a['not_proven']]
    if a['affected']:
        L.append(b('Affected devices'))
        L += [f"  • {x}" for x in a['affected']]
        L.append("  • Workflow impact: join with asset inventory / WMS logs to confirm")
    L.append(f"{b('Owner')}: {a['owner']}")
    L.append(b('Next checks'))
    L += [f"  {n}. {x}" for n, x in enumerate(a['next_checks'], 1)]
    L.append(f"{b('Confidence')}: {a['confidence']}")
    if a['example']:
        L.append(f"Example client to open in the dashboard: {a['example']}")
    return '\n'.join(L)


def main():
    args = [x for x in sys.argv[1:] if not x.startswith('--')]
    folder = args[0] if args else 'airframe_results'
    workflows = {}
    if '--workflows' in sys.argv:
        with open(sys.argv[sys.argv.index('--workflows') + 1], encoding='utf-8') as fh:
            workflows = json.load(fh)
    data, alerts = build_alerts(folder, workflows)
    order = {'CRITICAL': 0, 'SERIOUS': 1, 'WARNING': 2, 'INFO': 3}
    alerts.sort(key=lambda a: (order[a['severity']], a['fired_at'] or ''))
    sep = '\n' + '-' * 78 + '\n'
    text = sep.join(render(a) for a in alerts)
    print(text)
    with open(os.path.join(folder, 'alerts.md'), 'w', encoding='utf-8') as fh:
        fh.write(sep.join(render(a, slack=True) for a in alerts) + '\n')
    with open(os.path.join(folder, 'alerts.json'), 'w', encoding='utf-8') as fh:
        json.dump([dict(a, slack_text=render(a, slack=True)) for a in alerts], fh, indent=1)
    print(f"\nwrote {folder}/alerts.md and {folder}/alerts.json (nothing was sent)")


if __name__ == '__main__':
    main()
