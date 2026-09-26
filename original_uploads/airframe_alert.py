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
            alerts.append(dict(
                severity='CRITICAL', kind=kind,
                title=f"802.1X logins failing at the Identity step on {', '.join(sorted({a['ssid'] for a in loop}))}",
                fired_at=local(fire[0], tz) if fire else None,
                detect_delay_s=round(fire[0] - first) if fire else None, delay_of='the first failed login',
                observed=[
                    f"{len(loop)} failed login attempts from {len(clients)} clients on {facts.get('APs affected')} APs, "
                    f"{local(first, tz)}-{local(last, tz)}" + (f", plus {cut} cut off by the end of the capture" if cut else "")
                    + (" - still failing when the capture ends" if ongoing else ""),
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
                          f"About {facts.get('Rate after start')} across the site",
                          "Frames sit in each AP's own sequence counter: sent by the real APs, not spoofed"],
                consistent_with="APs no longer hold valid authentication state for these clients (controller or AP-side change)",
                not_proven=["What changed on the controller at the start time", "Whether the clients notice"],
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
    return data, alerts


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
    order = {'CRITICAL': 0, 'SERIOUS': 1, 'INFO': 2}
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
