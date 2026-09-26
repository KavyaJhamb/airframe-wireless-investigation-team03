#!/usr/bin/env python3
"""
airframe_dashboard.py - build a single self-contained dashboard.html from airframe_analyze.py output.

Usage:
  python3 airframe_dashboard.py results_folder            # writes results_folder/dashboard.html
Findings are computed from the CSVs by fixed rules, so the page works for any capture set.
"""
import csv, json, os, re, sys, collections, statistics

OUI = {'00:0b:86': 'Aruba', 'f0:18:98': 'Apple', 'b8:27:eb': 'Raspberry Pi', '3c:58:c2': 'Intel'}
FAILED = {'auth_rejected', 'assoc_rejected', 'eap_failure', 'deauth_during_setup', 'stalled', 'restarted',
          'abandoned_for_other_ap'}
REASON = {1: 'unspecified', 2: 'previous authentication no longer valid', 3: 'client leaving', 4: 'inactivity',
          5: 'AP overloaded', 6: 'class 2 frame from unauthenticated client', 7: 'class 3 frame from unassociated client',
          8: 'client leaving (disassoc)', 14: 'MIC failure', 15: '4-way handshake timeout',
          23: '802.1X authentication failed', 34: 'poor channel conditions'}

NICE = {'all_retry_rate': 'retry (all)', 'mgmt_retry_rate': 'retry (mgmt)', 'uni_retry_rate': 'retry (unicast)',
        'data_retry_rate': 'retry (data)', 'probe_req': 'probe requests', 'probe_resp': 'probe responses',
        'probe_resp_retry_rate': 'retry (probe resp.)', 'frames': 'frame count', 'deauth': 'deauths',
        'disassoc': 'disassocs', 'auth_fail': 'auth failures', 'assoc_fail': 'assoc failures',
        'eap_failure': 'EAP failures'}


# Size limits keep the page fast for fleet-sized inputs; everything is still in the CSVs.
MAX_CLIENTS = 2000          # rows in the client table (worst first)
MAX_TL_CLIENTS = 300        # clients whose frame sequence is embedded
MAX_TL_FRAMES = 400         # frames per embedded client
MAX_HEAT_ROWS = 40          # sensors in the heatmap (most failures first)
MAX_EXTRA_CARDS = 6         # findings.csv cards beyond the narrated ones (warning and above)
SYSTEMIC_MIN_CLIENTS = 5    # the narrated auth/wave cards need this many clients; fewer = per-client findings
SEV_LABEL = {'critical': 'Critical', 'serious': 'Serious', 'warning': 'Warning', 'info': 'Note'}


def rd(folder, name):
    p = os.path.join(folder, name)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return []
    with open(p, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def iter_csv(folder, name):
    """Stream a CSV row by row: timelines.csv can have millions of rows at fleet scale."""
    p = os.path.join(folder, name)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return
    with open(p, encoding='utf-8') as f:
        yield from csv.DictReader(f)


def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def group(mac):
    return mac[:8] if mac else ''


def build(folder):
    mm = rd(folder, 'minute_metrics.csv')
    at = rd(folder, 'attempts.csv')
    cl = rd(folder, 'clients.csv')
    dis = rd(folder, 'disconnects.csv')
    inc = rd(folder, 'incidents.csv')
    fnd = rd(folder, 'findings.csv')
    summ = json.load(open(os.path.join(folder, 'summary.json'), encoding='utf-8'))
    tzname = summ.get('timezone', '')

    # ---------------- axis
    minutes = sorted({(int(r['minute_utc']), r['minute_local']) for r in mm})
    mins = [m for m, _ in minutes]
    labels = [l for _, l in minutes]
    idx = {m: i for i, m in enumerate(mins)}
    n = len(mins)
    mi = lambda t: idx.get(int(float(t) // 60) * 60)

    sensors = sorted(summ['sensors'].items())
    sens_meta = [dict(name=k, channel=v.get('channel'), freq=v.get('freq'), first=v.get('first'), last=v.get('last'),
                      records=v.get('quality', {}).get('records', 0), quality=v.get('quality', {}),
                      gaps=len(v.get('gaps', []))) for k, v in sensors]
    sidx = {s['name']: i for i, s in enumerate(sens_meta)}

    # ---------------- per-minute series (all sensors)
    probe = [0] * n
    frames = [0] * n
    retry_w = [0.0] * n
    presp_retry_w = [0.0] * n
    heat = {k: [[None] * n for _ in sens_meta] for k in ('probe_resp', 'failed_attempts', 'disconnects', 'retry')}
    for r in mm:
        i = idx[int(r['minute_utc'])]
        s = sidx[r['sensor']]
        pr = int(float(r.get('probe_resp') or 0))
        fr = int(float(r['frames']))
        probe[i] += pr
        frames[i] += fr
        ar = fnum(r['all_retry_rate'])
        if ar is not None:
            retry_w[i] += ar * fr
        prr = fnum(r.get('probe_resp_retry_rate'))
        if prr is not None:
            presp_retry_w[i] += prr * pr
        heat['probe_resp'][s][i] = pr
        heat['failed_attempts'][s][i] = int(float(r.get('failed_attempts') or 0))
        heat['disconnects'][s][i] = int(float(r['deauth'])) + int(float(r['disassoc']))
        heat['retry'][s][i] = round(100 * ar, 2) if ar is not None and fr >= 100 else None
    retry_all = [round(100 * retry_w[i] / frames[i], 2) if frames[i] else None for i in range(n)]
    retry_presp = [round(100 * presp_retry_w[i] / probe[i], 2) if probe[i] else None for i in range(n)]

    def rcat(code):
        return 'r23' if code == '23' else 'r2' if code == '2' else 'other'

    fail_by = {k: [0] * n for k in ('r23', 'r2', 'other')}
    ok_by = [0] * n
    for a in at:
        i = mi(a['start'])
        if i is None:
            continue
        if a['outcome'] in FAILED:
            fail_by[rcat(a['code'])][i] += 1
        elif a['outcome'] in ('success', 'probable_success_client_unheard'):
            ok_by[i] += 1
    dis_by = {k: [0] * n for k in ('r23', 'r2', 'other')}
    for d in dis:
        i = mi(d['t'])
        if i is not None:
            dis_by[rcat(d['reason'])][i] += 1

    # ---------------- totals
    oc = collections.Counter(a['outcome'] for a in at)
    failed = sum(v for k, v in oc.items() if k in FAILED)
    ok = oc.get('success', 0)
    ok_prob = oc.get('probable_success_client_unheard', 0)
    kpis = dict(frames=sum(s['records'] for s in sens_meta), sensors=len(sens_meta),
                channels=[s['channel'] for s in sens_meta], attempts=len(at), failed=failed, success=ok,
                probable=ok_prob, clients=len(cl), aps=len({a['bssid'] for a in at}))

    # ---------------- findings (rule-based)
    findings = []
    eap_att = [a for a in at if 'EAP' in (a['stage_detail'] or '')]
    loop = [a for a in eap_att if a['stage_detail'].startswith('EAP identity loop')]
    loop_heard = [a for a in loop if 'client answered' in a['stage_detail']]
    eap_success_total = sum(int(float(r.get('eap_success') or 0)) for r in mm)
    if eap_att and len(loop) >= 0.5 * len(eap_att) and len({a['client'] for a in loop}) >= SYSTEMIC_MIN_CLIENTS:
        ssids = collections.Counter(a['ssid'] for a in loop)
        aps = {a['bssid'] for a in loop}
        codes = collections.Counter(a['code'] for a in loop if a['code'])
        heard_ok = sum(1 for a in at if 'client answered' in (a['stage_detail'] or ''))
        heard_all = heard_ok + sum(1 for a in at if 'audible client did not answer' in (a['stage_detail'] or ''))
        # re-ask interval: gaps between consecutive EAP_REQ to the same client (<120 s)
        gaps = []
        last = {}
        for r in iter_csv(folder, 'timelines.csv'):
            if r['kind'] == 'EAP_REQ':
                t = float(r['t'])
                if r['client'] in last and 5 < t - last[r['client']] < 120:
                    gaps.append(t - last[r['client']])
                last[r['client']] = t
        ivl = round(statistics.median(gaps)) if gaps else None
        groups = collections.Counter(group(a['client']) for a in loop)
        findings.append(dict(
            sev='critical', label='Critical', kind='auth',
            title='802.1X never gets past the Identity step' if eap_success_total == 0 else
            'Most 802.1X logins stop at the Identity step',
            lead=f"{len(loop)} of {len(eap_att)} 802.1X attempts on {', '.join(ssids)} ended in an identity loop. "
                 f"The AP asks who the client is, the client answers, and the AP never starts the login method. "
                 f"{'No EAP-Success frame appears anywhere in the capture. ' if eap_success_total == 0 else ''}"
                 f"This points at the authentication server behind the APs, not at the clients.",
            facts=[
                ['Attempts in the loop', f"{len(loop)} / {len(eap_att)}"],
                ['Clients that answered when audible', f"{heard_ok} of {heard_all}" if heard_all else 'n/a'],
                ['AP re-asks every', f"{ivl} s" if ivl else 'n/a'],
                ['Ended by AP deauth', ', '.join(f"reason {c} x{v}" for c, v in codes.most_common(2))],
                ['APs affected', str(len(aps))],
                ['Client groups', ', '.join(f"{g}{' (' + OUI[g] + ')' if g in OUI else ''}" for g, _ in groups.most_common())],
            ],
            window=None, example=loop_heard[0]['client'] if loop_heard else loop[0]['client']))
    # disconnect waves: a reason code with many AP-sent disconnects outside setup
    wave_by = collections.defaultdict(list)
    for d in dis:
        if d['by'] == 'AP':
            wave_by[d['reason']].append(d)
    for rc, ds in sorted(wave_by.items(), key=lambda kv: -len(kv[1])):
        if len(ds) < 100 or len({d['client'] for d in ds}) < SYSTEMIC_MIN_CLIENTS:
            continue
        ds.sort(key=lambda d: float(d['t']))
        onset = float(ds[0]['t'])
        end = float(ds[-1]['t'])
        per_cl = collections.defaultdict(list)
        for d in ds:
            per_cl[d['client']].append(float(d['t']))
        ivs = [b - a for v in per_cl.values() for a, b in zip(v, v[1:]) if b - a < 120]
        ivl = round(statistics.median(ivs), 1) if ivs else None
        rate = round(len(ds) / max(1, (end - onset) / 60))
        groups = collections.Counter(group(d['client']) for d in ds)
        rtext = REASON.get(int(rc), 'reason ' + rc) if rc.isdigit() else rc
        pairs = len({(d['client'], d['bssid']) for d in ds})
        findings.append(dict(
            sev='serious', label='Serious', kind='wave',
            title=f"APs start rejecting clients at {ds[0]['time_local'][:8]}",
            lead=f"From {ds[0]['time_local'][:8]} the APs send \"{rtext}\" (reason {rc}) to {len(per_cl)} clients, "
                 f"about every {ivl} s per client, until the capture ends. Each client is always rejected by the same AP.",
            facts=[
                ['Disconnect frames', str(len(ds))],
                ['Start', ds[0]['time_local'][:8]],
                ['Rate after start', f"{rate} per minute"],
                ['Clients / AP pairs', f"{len(per_cl)} / {pairs}"],
                ['Client groups', ', '.join(f"{g}{' (' + OUI[g] + ')' if g in OUI else ''}" for g, _ in groups.most_common())],
            ],
            window=[mi(onset), mi(end)], example=max(per_cl, key=lambda c: len(per_cl[c]))))
        break
    # incidents from the detector, merged by window
    if inc:
        inc.sort(key=lambda r: float(r['peak_z']), reverse=True)
        top = [r for r in inc if r['scope'] in ('environment-wide', 'multi-sensor')] or inc
        s0 = min(int(r['start_utc']) for r in top)
        e0 = max(int(r['end_utc']) for r in top)
        pr = [r for r in top if r['metric'] == 'probe_resp']
        mets = sorted({r['metric'] for r in top})
        i0, i1 = idx.get(s0), idx.get(e0 - 60)
        # is the retry rise a traffic-mix effect?
        mix = None
        if any('retry' in m for m in mets) and i0 is not None:
            peak = max(range(i0, (i1 or i0) + 1), key=lambda i: retry_all[i] or 0)
            full = slice(1, -1) if n > 2 else slice(None)        # first and last minute are partial
            base = statistics.median([v for v in retry_presp[full] if v is not None])
            if retry_presp[peak] is not None and abs(retry_presp[peak] - base) < 3:
                mix = (retry_all[peak], statistics.median([v for v in retry_all[full] if v is not None]),
                       retry_presp[peak], base, probe[peak], statistics.median(probe[full]))
        lead = (f"Between {top[0]['start_local']} and {max(r['end_local'] for r in top)} "
                f"{max(int(r['sensors_flagged']) for r in top)} of {len(sens_meta)} sensors show an anomaly in "
                f"{', '.join(NICE.get(m, m) for m in mets)}.")
        n_pr = max((int(r['sensors_flagged']) for r in pr), default=0)
        if pr:
            lead = (f"Probe traffic jumps on {pr[0]['sensors_flagged']} of {len(sens_meta)} channels at once "
                    f"({pr[0]['start_local']}-{pr[0]['end_local']}): many clients scan for a new AP at the same time.")
        facts = [['Metrics flagged', ', '.join(NICE.get(m, m) for m in mets)],
                 ['Sensors', f"{max(int(r['sensors_flagged']) for r in top)} of {len(sens_meta)}"],
                 ['Failed attempts in window', f"{top[0]['failed_attempts_in_window']} of {top[0]['attempts_in_window']}"]]
        if mix:
            facts.append(['Retry, all frames', f"{mix[1]:.1f}% to {mix[0]:.1f}%"])
            facts.append(['Retry, probe responses', f"{mix[3]:.1f}% to {mix[2]:.1f}% (flat)"])
            lead += (" The retry rate doubles too, but only because probe responses (always retried about "
                     f"{mix[3]:.0f}% of the time) make up more of the traffic. Radio conditions did not get worse.")
        title = ('Multi-sensor anomaly' if not pr else 'Probe storm on every channel' if n_pr >= len(sens_meta)
                 else f'Probe storm on {n_pr} of {len(sens_meta)} channels')
        findings.append(dict(sev='warning', label='Warning', kind='storm', title=title, lead=lead, facts=facts,
                             window=[i0, i1], example=None))
    # findings.csv (analyzer judgment rules): cards for what the narrated cards above do not already cover
    narrated = {k['kind'] for k in findings}
    kids = collections.Counter(f['parent'] for f in fnd if f['parent'])
    extra = []
    quiet = not any(f['severity'] != 'info' for f in fnd if not f['parent']) and not findings
    for f in fnd:                       # minor findings get cards only when there is nothing bigger to show
        if f['parent'] or (f['severity'] == 'info' and not quiet):
            continue
        if ('auth' in narrated and f['category'] == '802.1X / EAP failure' and kids[f['id']]) or \
                ('wave' in narrated and 'wave' in f['tags'].split(';')):
            continue
        facts = [['Clients' if f['category'] not in ('AP silent / beacon loss', 'Congestion / channel health')
                  else 'APs', str(kids[f['id']])]] if kids[f['id']] else []
        facts += [[k, v] for k, v in (('Client', f['client']), ('AP', f['ap'] if len(f['ap']) < 40 else
                                                                 f"{len(f['ap'].split(';'))} APs"),
                                      ('SSID', f['ssid']), ('Channels', f['channels']),
                                      ('Sensors', f['sensors'] if f['sensors'].count(';') < 3 else
                                       f"{f['sensors'].count(';') + 1} sensors"),
                                      ('When', f"{f['start_local']}-{f['end_local']}")) if v]
        extra.append(dict(sev=f['severity'], label=SEV_LABEL[f['severity']], kind='finding', title=f['title'],
                          lead=f['explanation'], facts=facts, window=[mi(f['start']), mi(float(f['end']) - 1)],
                          example=f['client'] or next((k['client'] for k in fnd if k['parent'] == f['id']
                                                       and k['client']), None)))
    over = [e for e, f in zip(extra, [f for f in fnd if not f['parent'] and f['title'] in {x['title'] for x in extra}])
            if f['category'] == 'Co-channel overlap']
    if len(over) > 1:                  # one card for the channel plan, not one per channel
        rows_ = [f for f in fnd if not f['parent'] and f['category'] == 'Co-channel overlap']
        chs = [r['channels'] for r in rows_]
        n_aps = sorted({r['count'] for r in rows_})
        first = extra.index(over[0])
        m = re.search(r'median of (\S+) on', rows_[0]['explanation'])
        med_txt = m.group(1) if m else 'fewer'
        extra = [e for e in extra if e not in over]
        extra.insert(first, dict(
            sev='warning', label='Warning', kind='finding',
            title=f"Channels {', '.join(chs[:-1])} and {chs[-1]} are crowded" + (f": {n_aps[0]} APs each" if len(n_aps) == 1
                                                                                else ''),
            lead=(f"Channels {', '.join(chs[:-1])} and {chs[-1]} carry "
                  + (f"{n_aps[0]} APs each" if len(n_aps) == 1 else "up to " + str(n_aps[-1]) + " APs")
                  + f", against a median of {med_txt} on "
                  f"the other channels. Every client and AP on a crowded channel contends for the same airtime, and "
                  f"beacons alone take a bigger share of it. A channel re-plan is a configuration change."),
            facts=[['Channel ' + r['channels'], f"{r['count']} APs"] for r in rows_], window=None, example=None))
    findings += extra[:MAX_EXTRA_CARDS]
    unheard = sum(1 for a in at if a['observed_from'] == 'ASSOC_RESP')
    if ok_prob or unheard:
        findings.append(dict(
            sev='info', label='Note', kind='visibility', title='What the sensors cannot hear',
            lead=f"In {unheard} of {len(at)} attempts the first frame heard is the AP's reply, so the client itself is "
                 f"out of the sensors' range. {ok_prob} handshakes where the AP sent message 3 (which it only does "
                 f"after a valid message 2) are counted as probable successes, not failures.",
            facts=[['Probable successes', str(ok_prob)], ['Confirmed successes', str(ok)]], window=None,
            example=next((a['client'] for a in at if a['outcome'] == 'probable_success_client_unheard'), None)))

    # ---------------- clients
    ssid_of = {}
    for a in at:
        ssid_of.setdefault(a['client'], a['ssid'])
    clients = []
    for c in cl:
        clients.append(dict(mac=c['client'], g=group(c['client']), ssid=ssid_of.get(c['client'], ''),
                            att=int(c['attempts']), ok=int(c['successes']), fail=int(c['failures']),
                            top=c['top_failure'], codes=c['codes'], dis=int(c['disconnects']),
                            aps=int(c['distinct_bssids']), sensors=int(c['sensors']), ch=c['channels'],
                            sig=fnum(c['signal_median'])))
    prob = collections.Counter(a['client'] for a in at if a['outcome'] == 'probable_success_client_unheard')
    for c in clients:
        c['prob'] = prob.get(c['mac'], 0)
    groups = collections.Counter(c['g'] for c in clients)
    clients_total = len(clients)
    clients.sort(key=lambda c: (-c['fail'], -c['dis'], -c['att']))
    clients = clients[:MAX_CLIENTS]

    # ---------------- timelines (compact, only for the clients worth opening)
    want = {c['mac'] for c in clients[:MAX_TL_CLIENTS]} | {f['example'] for f in findings if f.get('example')}
    tlc, tl_counts = collections.defaultdict(list), collections.Counter()
    for r in iter_csv(folder, 'timelines.csv'):
        c = r['client']
        if c in want:
            tl_counts[c] += 1
            if tl_counts[c] <= MAX_TL_FRAMES:
                tlc[c].append([r['time_local'], 0 if r['dir'] == 'AP->client' else 1, r['kind'], r['detail'],
                               r['bssid'], r['sensors']])

    # ---------------- heatmap rows: the sensors that matter most
    score = [(sum(v or 0 for v in heat['failed_attempts'][i]), sum(v or 0 for v in heat['probe_resp'][i]), i)
             for i in range(len(sens_meta))]
    rows = sorted(i for _, _, i in sorted(score, reverse=True)[:MAX_HEAT_ROWS])
    heat = {k: [m[i] for i in rows] for k, m in heat.items()}
    heat_sensors = [sens_meta[i] for i in rows]
    return dict(tz=tzname, masked=bool(summ.get('masked')), labels=labels, n=n, sensors=sens_meta, kpis=kpis, findings=findings,
                series=dict(probe=probe, retry_all=retry_all, retry_presp=retry_presp, fail=fail_by, ok=ok_by,
                            dis=dis_by),
                heat=heat, heat_sensors=heat_sensors, clients=clients, clients_total=clients_total, tl=tlc,
                tl_counts=dict(tl_counts),
                groups=[[g, groups[g], OUI.get(g, '')] for g, _ in groups.most_common()],
                incidents=inc, oui=OUI,
                outcomes=dict(oc))


TEMPLATE = r'''<title>Airframe Incident Board</title>
<style>
:root{
  --ground:#eef2f1; --surface:#fbfcfc; --surface-2:#e4eae9; --rule:#d3dcdb; --ink:#121819; --ink-2:#465355; --ink-3:#72807f;
  --accent:#0d6973; --accent-soft:#d5e9ea; --focus:#0d6973;
  --s-probe:#2a78d6; --s-r23:#eb6834; --s-r2:#1baf7a; --s-other:#9aa6a5; --s-ink:#2a3436;
  --heat-lo:#e7eff8; --heat-hi:#0d366b;
  --crit:#d03b3b; --serious:#ec835a; --warn:#fab219; --info:#6d8a8c; --good:#0ca30c;
  --band:rgba(13,105,115,.10);
  --f-display:"Avenir Next Condensed","Roboto Condensed","Arial Narrow",system-ui,sans-serif;
  --f-body:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --f-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --ground:#0e1314; --surface:#151c1d; --surface-2:#1d2627; --rule:#2b3637; --ink:#e7edec; --ink-2:#a9b6b5; --ink-3:#7c8a89;
    --accent:#56b6bf; --accent-soft:#16373a; --focus:#56b6bf;
    --s-probe:#3987e5; --s-r23:#d95926; --s-r2:#199e70; --s-other:#5d6a69; --s-ink:#d6dedd;
    --heat-lo:#18222a; --heat-hi:#86b6ef; --band:rgba(86,182,191,.13);
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --ground:#0e1314; --surface:#151c1d; --surface-2:#1d2627; --rule:#2b3637; --ink:#e7edec; --ink-2:#a9b6b5; --ink-3:#7c8a89;
  --accent:#56b6bf; --accent-soft:#16373a; --focus:#56b6bf;
  --s-probe:#3987e5; --s-r23:#d95926; --s-r2:#199e70; --s-other:#5d6a69; --s-ink:#d6dedd;
  --heat-lo:#18222a; --heat-hi:#86b6ef; --band:rgba(86,182,191,.13);
}
*{box-sizing:border-box}
body{background:var(--ground);color:var(--ink);font:15px/1.5 var(--f-body);margin:0}
.wrap{max-width:1240px;margin:0 auto;padding-inline:20px;padding-block:28px 64px;display:flex;flex-direction:column;gap:28px}
h1,h2,h3{font-family:var(--f-display);font-weight:600;letter-spacing:.005em;margin:0;text-wrap:balance}
h1{font-size:clamp(28px,4vw,40px);line-height:1.05}
h2{font-size:22px;line-height:1.15}
h3{font-size:18px;line-height:1.2}
.eyebrow{font:600 12px/1 var(--f-display);letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.muted{color:var(--ink-2)}
.mono{font-family:var(--f-mono);font-size:13px;font-variant-numeric:tabular-nums}
.num{font-variant-numeric:tabular-nums}
header{display:flex;flex-direction:column;gap:10px}
.meta{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;color:var(--ink-2);font-size:14px}
.chips{display:flex;flex-wrap:wrap;gap:4px}
.ch{font:500 12px/1 var(--f-mono);padding:4px 6px;border:1px solid var(--rule);border-radius:3px;background:var(--surface);color:var(--ink-2)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));border-top:2px solid var(--ink);border-bottom:1px solid var(--rule)}
.kpi{padding:12px 14px 12px 0;display:flex;flex-direction:column;gap:2px}
.kpi b{font:600 30px/1.05 var(--f-display);font-variant-numeric:tabular-nums}
.kpi span{font-size:13px;color:var(--ink-2)}
.kpi b.bad{color:var(--crit)}
section{display:flex;flex-direction:column;gap:14px}
.sechead{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:end;gap:10px}
.panel{background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:16px}
/* findings */
.findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.finding{background:var(--surface);border:1px solid var(--rule);border-top:4px solid var(--sev);border-radius:4px;padding:14px 16px;display:flex;flex-direction:column;gap:10px}
.finding[data-sev=critical]{--sev:var(--crit)} .finding[data-sev=serious]{--sev:var(--serious)}
.finding[data-sev=warning]{--sev:var(--warn)} .finding[data-sev=info]{--sev:var(--info)}
.sev{display:inline-flex;align-items:center;gap:6px;font:600 12px/1 var(--f-display);letter-spacing:.1em;text-transform:uppercase;color:var(--ink-2)}
.sev i{width:14px;height:14px;display:inline-grid;place-items:center;border-radius:50%;background:var(--sev);color:#fff;font:700 10px/1 var(--f-body);font-style:normal}
.finding p{margin:0;font-size:14px;color:var(--ink-2)}
.facts{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:3px 12px;margin:0;font-size:13px}
.facts dt{color:var(--ink-3)} .facts dd{margin:0;font-family:var(--f-mono);font-size:12.5px;font-variant-numeric:tabular-nums}
.actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:auto}
button{font:500 13px/1 var(--f-body);color:var(--accent);background:transparent;border:1px solid var(--accent);border-radius:3px;padding:7px 10px;cursor:pointer}
button:hover{background:var(--accent-soft)}
button[aria-pressed=true]{background:var(--accent);color:var(--surface)}
button:focus-visible,tr:focus-visible,input:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.seg{display:flex;flex-wrap:wrap;gap:4px}
/* charts */
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--ink-2)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:12px;height:12px;border-radius:2px;display:inline-block}
.swl{width:16px;height:0;border-top:2px solid;display:inline-block}
.chart{position:relative;width:100%;overflow:hidden}
.chart svg{display:block;width:100%;height:auto}
.ax{font:11px var(--f-mono);fill:var(--ink-3)}
.plabel{font:600 13px var(--f-display);fill:var(--ink);letter-spacing:.02em}
.psub{font:12px var(--f-body);fill:var(--ink-3)}
.grid{stroke:var(--rule);stroke-width:1}
.base{stroke:var(--ink-3);stroke-width:1}
.mark-line{stroke:var(--ink-2);stroke-width:1;stroke-dasharray:3 3}
.mark-text{font:600 11px var(--f-display);fill:var(--ink-2);letter-spacing:.04em;text-transform:uppercase}
.tip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--rule);border-radius:4px;padding:8px 10px;font-size:12.5px;box-shadow:0 4px 14px rgba(0,0,0,.12);min-width:170px;z-index:5}
.tip b{font-family:var(--f-mono);font-weight:500}
.tip .r{display:flex;justify-content:space-between;gap:14px;align-items:center}
.tip .r span{display:inline-flex;align-items:center;gap:6px;color:var(--ink-2)}
.cross{stroke:var(--ink);stroke-width:1;opacity:.5}
/* table */
.twocol{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:16px;align-items:start}
@media (max-width:900px){.twocol{grid-template-columns:minmax(0,1fr)}}
.filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
input[type=search]{font:13px var(--f-mono);padding:7px 9px;border:1px solid var(--rule);border-radius:3px;background:var(--surface);color:var(--ink);min-width:0;width:190px}
.tablewrap{overflow:auto;max-height:560px;border:1px solid var(--rule);border-radius:4px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:13px}
th{position:sticky;top:0;background:var(--surface-2);text-align:left;font:600 12px/1.2 var(--f-display);letter-spacing:.06em;text-transform:uppercase;color:var(--ink-2);padding:8px 10px;white-space:nowrap}
td{padding:7px 10px;border-top:1px solid var(--rule);vertical-align:top}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--accent-soft)}
tbody tr[aria-selected=true]{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
td.n{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--f-mono);font-size:12.5px}
.bar{display:inline-block;height:6px;border-radius:0 2px 2px 0;background:var(--crit);vertical-align:middle;margin-left:6px}
.pill{display:inline-block;font:500 11px/1 var(--f-body);padding:3px 6px;border-radius:10px;border:1px solid var(--rule);color:var(--ink-2);white-space:nowrap}
.pill.bad{border-color:var(--crit);color:var(--crit)} .pill.ok{border-color:var(--good);color:var(--good)}
.why{color:var(--ink-2);font-size:12.5px;max-width:34ch}
/* ladder */
.ladder{max-height:640px;overflow:auto}
.lad-ev{font:12px var(--f-mono)}
.lad-t{font:11px var(--f-mono);fill:var(--ink-3)}
.lad-k{font:500 12px var(--f-mono);fill:var(--ink)}
.lad-d{font:11px var(--f-mono);fill:var(--ink-3)}
.lane{stroke:var(--rule);stroke-width:2}
.lane-h{font:600 13px var(--f-display);fill:var(--ink)}
.lane-s{font:11px var(--f-mono);fill:var(--ink-3)}
.gapnote{font:italic 11px var(--f-body);fill:var(--ink-3)}
/* evidence */
.ev{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.ev ul{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:6px;font-size:14px;color:var(--ink-2)}
.qt td,.qt th{padding:5px 8px}
footer{font-size:13px;color:var(--ink-3)}
@media (prefers-reduced-motion:no-preference){ tbody tr{transition:background .12s} }
</style>

<div class="wrap">
  <header>
    <div class="eyebrow">Header-only 802.11 / 802.1X forensics</div>
    <h1>Airframe incident board</h1>
    <div class="meta" id="meta"></div>
  </header>

  <div class="kpis" id="kpis"></div>

  <section aria-labelledby="h-find">
    <div class="sechead"><h2 id="h-find">What went wrong</h2><span class="muted" style="font-size:13px">Computed from the captures by fixed rules. Click to see each one on the timeline or in a client's frames.</span></div>
    <div class="findings" id="findings"></div>
  </section>

  <section aria-labelledby="h-time">
    <div class="sechead">
      <div><h2 id="h-time">Minute by minute, all sensors</h2><div class="muted" style="font-size:13px">Same time axis in every panel. Hover for values.</div></div>
      <div class="legend" id="legend"></div>
    </div>
    <div class="panel"><div class="chart" id="timeline"></div></div>
  </section>

  <section aria-labelledby="h-heat">
    <div class="sechead">
      <div><h2 id="h-heat">Each channel on its own</h2><div class="muted" style="font-size:13px">One row per sensor. An event that lights up every row at once is shared, not local to one channel.</div></div>
      <div class="seg" id="heatseg" role="group" aria-label="Heatmap metric"></div>
    </div>
    <div class="panel"><div class="chart" id="heat"></div></div>
  </section>

  <section aria-labelledby="h-cl">
    <div class="sechead"><h2 id="h-cl">Clients and their connection attempts</h2></div>
    <div class="twocol">
      <div style="display:flex;flex-direction:column;gap:10px">
        <div class="filters" id="filters"></div>
        <div class="tablewrap"><table aria-label="Clients"><thead><tr><th>Client</th><th>Network</th><th style="text-align:right">Tries</th><th style="text-align:right">Failed</th><th>How it failed</th><th style="text-align:right">AP kicks</th><th style="text-align:right">Ch</th></tr></thead><tbody id="tbody"></tbody></table></div>
      </div>
      <div class="panel" style="display:flex;flex-direction:column;gap:10px">
        <div><h3 id="lad-title">Frame sequence</h3><div class="muted" id="lad-sub" style="font-size:13px"></div></div>
        <div class="ladder" id="ladder"></div>
        <div id="lad-more"></div>
      </div>
    </div>
  </section>

  <section aria-labelledby="h-ev">
    <h2 id="h-ev">Evidence and limits</h2>
    <div class="ev">
      <div class="panel"><h3 style="margin-bottom:8px">Read from headers</h3><ul id="ev-yes"></ul></div>
      <div class="panel"><h3 style="margin-bottom:8px">Not provable from headers</h3><ul>
        <li>Why the authentication server is silent: down, unreachable from the controller, or misconfigured. The frames only show that the APs never get an answer.</li>
        <li>Anything a client sends when no sensor can hear it. Attempts that start with the AP's reply are partial views.</li>
        <li>Packet loss at the receiver. A retry bit means the sender retransmitted; it does not say the frame was lost.</li>
        <li>Business impact. The captures contain no payloads or layer-3 traffic.</li>
      </ul></div>
      <div class="panel"><h3 style="margin-bottom:8px">Capture quality</h3><div style="overflow-x:auto"><table class="qt" id="qt"></table></div></div>
    </div>
  </section>
  <footer>Generated by airframe_analyze.py and airframe_dashboard.py. Header-only analysis: nothing was transmitted, no payload or layer-3 data was read.</footer>
</div>

<script>
const D = /*__DATA__*/null;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt = n => n == null ? '–' : Number(n).toLocaleString('en-US');
const NS = 'http://www.w3.org/2000/svg';
const state = {win:null, heat:'probe_resp', group:'all', failing:true, q:'', client:null, ladN:60};

/* ---------- header, kpis ---------- */
(function(){
  const s = D.sensors, first = s.reduce((a,b)=>Math.min(a,b.first),Infinity), last = s.reduce((a,b)=>Math.max(a,b.last),0);
  const tfmt = t => new Date(t*1000).toLocaleTimeString('en-GB',{timeZone:D.tz||undefined,hour:'2-digit',minute:'2-digit'});
  const date = new Date(first*1000).toLocaleDateString('en-GB',{timeZone:D.tz||undefined,day:'numeric',month:'short',year:'numeric'});
  $('#meta').innerHTML = `<span>${date}, ${tfmt(first)}–${tfmt(last)} <span class="mono">${esc(D.tz)}</span></span>
    <span>${D.kpis.sensors} sensors</span>${D.masked ? '<span>identifiers pseudonymised</span>' : '<span style="color:var(--crit)">raw identifiers: do not share</span>'}
    <span class="chips" aria-label="Channels">${s.map(x=>`<span class="ch">ch ${x.channel}</span>`).join('')}</span>`;
  const k = D.kpis, pct = k.attempts ? Math.round(100*k.failed/k.attempts) : 0;
  $('#kpis').innerHTML = [
    [fmt(k.frames), 'frames analyzed'],
    [fmt(k.attempts), 'connection attempts'],
    [`<b class="bad">${fmt(k.failed)}</b>`, `failed (${pct}%)`],
    [`${fmt(k.success)}<span style="font-size:18px;color:var(--ink-3)"> + ${fmt(k.probable)}</span>`, 'succeeded + probable'],
    [fmt(k.clients), 'clients seen'],
    [fmt(k.aps), 'access points involved'],
  ].map(([v,l]) => `<div class="kpi">${v.startsWith('<b')?v:`<b>${v}</b>`}<span>${l}</span></div>`).join('');
})();

/* ---------- findings ---------- */
function renderFindings(){
  const icon = {critical:'!', serious:'!', warning:'!', info:'i'};
  $('#findings').innerHTML = D.findings.map((f,i)=>`
    <article class="finding" data-sev="${f.sev}">
      <span class="sev"><i aria-hidden="true">${icon[f.sev]}</i>${esc(f.label)}</span>
      <h3>${esc(f.title)}</h3>
      <p>${esc(f.lead)}</p>
      <dl class="facts">${f.facts.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <div class="actions">
        ${f.window && f.window[0]!=null ? `<button data-win="${i}" aria-pressed="false">Show on timeline</button>`:''}
        ${f.example ? `<button data-ex="${esc(f.example)}">Open example client</button>`:''}
      </div>
    </article>`).join('');
  $('#findings').onclick = e => {
    const b = e.target.closest('button'); if(!b) return;
    if(b.dataset.win){
      const f = D.findings[+b.dataset.win], on = b.getAttribute('aria-pressed')!=='true';
      document.querySelectorAll('[data-win]').forEach(x=>x.setAttribute('aria-pressed','false'));
      b.setAttribute('aria-pressed', on);
      state.win = on ? [f.window[0], f.window[1] ?? f.window[0]] : null;
      drawTimeline(); drawHeat();
      if(on) $('#h-time').scrollIntoView({behavior:'smooth',block:'start'});
    }
    if(b.dataset.ex){ selectClient(b.dataset.ex, true); }
  };
}

/* ---------- svg helpers ---------- */
function el(tag, attrs, parent){ const e=document.createElementNS(NS,tag); for(const k in attrs) e.setAttribute(k,attrs[k]); if(parent) parent.appendChild(e); return e; }
function labelStep(){ for(const s of [5,10,15,30,60,120,240,480,720,1440]) if(D.n/s<=12) return s; return 2880; }
function niceMax(v){ if(!v) return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); for(const m of [1,2,2.5,5,10]) if(m*p>=v) return m*p; return 10*p; }

/* ---------- timeline ---------- */
const L = 46, R = 14;
function xScale(W){ const n=D.n, bw=(W-L-R)/n; return {bw, x:i=>L+i*bw}; }
const PANELS = [
  {key:'probe', title:'Probe responses', sub:'scanning load', type:'area', series:[{v:D.series.probe, c:'--s-probe', name:'Probe responses'}]},
  {key:'fail', title:'Failed connection attempts', sub:'by how the AP ended them', type:'stack', series:[
     {v:D.series.fail.r23, c:'--s-r23', name:'Reason 23: 802.1X failed'},
     {v:D.series.fail.r2, c:'--s-r2', name:'Reason 2: auth no longer valid'},
     {v:D.series.fail.other, c:'--s-other', name:'Stalled / other'}]},
  {key:'dis', title:'AP disconnects outside a connection attempt', sub:'by reason code', type:'stack', series:[
     {v:D.series.dis.r23, c:'--s-r23', name:'Reason 23: 802.1X failed'},
     {v:D.series.dis.r2, c:'--s-r2', name:'Reason 2: auth no longer valid'},
     {v:D.series.dis.other, c:'--s-other', name:'Other reasons'}]},
  {key:'retry', title:'Retry rate', sub:'% of frames with the Retry bit', type:'lines', unit:'%', series:[
     {v:D.series.retry_all, c:'--s-ink', name:'All frames'},
     {v:D.series.retry_presp, c:'--s-probe', name:'Probe responses only', dash:'5 3'}]},
];
function renderLegend(){
  $('#legend').innerHTML = `
    <span><i class="sw" style="background:var(--s-probe)"></i>Probe responses</span>
    <span><i class="sw" style="background:var(--s-r23)"></i>Reason 23</span>
    <span><i class="sw" style="background:var(--s-r2)"></i>Reason 2</span>
    <span><i class="sw" style="background:var(--s-other)"></i>Other</span>
    <span><i class="swl" style="border-color:var(--s-ink)"></i>Retry, all frames</span>
    <span><i class="swl" style="border-color:var(--s-probe);border-top-style:dashed"></i>Retry, probe responses</span>`;
}
function markers(){ // onset lines for findings with a window
  return D.findings.filter(f=>f.window && f.window[0]!=null).map(f=>({i:f.window[0], label:f.kind==='wave'?'Rejection wave':f.kind==='storm'?'Probe storm':f.title}));
}
function drawTimeline(){
  const host = $('#timeline'); host.innerHTML='';
  const W = Math.max(320, host.clientWidth), PH = W<560?70:84, GAP=34, TOP=22;
  const H = TOP + PANELS.length*(PH+GAP) + 4;
  const svg = el('svg',{viewBox:`0 0 ${W} ${H}`,role:'img','aria-label':'Per-minute timeline'},host);
  const {bw,x} = xScale(W);
  const mk = markers();
  // highlight band + markers
  if(state.win) el('rect',{x:x(state.win[0]),y:TOP-8,width:(state.win[1]-state.win[0]+1)*bw,height:H-TOP+4,fill:'var(--band)'},svg);
  PANELS.forEach((p,pi)=>{
    const y0 = TOP + pi*(PH+GAP) + 18, yb = y0+PH;
    el('text',{x:L-40,y:y0-8,class:'plabel'},svg).textContent = p.title;
    const tw = p.title.length*7.2;
    el('text',{x:L-40+tw+8,y:y0-8,class:'psub'},svg).textContent = W>520 ? p.sub : '';
    let max=0;
    if(p.type==='stack') for(let i=0;i<D.n;i++) max=Math.max(max,p.series.reduce((a,s)=>a+(s.v[i]||0),0));
    else p.series.forEach(s=>s.v.forEach(v=>{ if(v!=null) max=Math.max(max,v); }));
    max = niceMax(max);
    const y = v => yb - (v/max)*PH;
    [0,.5,1].forEach(f=>{ el('line',{x1:L,x2:W-R,y1:y(max*f),y2:y(max*f),class:f?'grid':'base'},svg);
      el('text',{x:L-6,y:y(max*f)+4,class:'ax','text-anchor':'end'},svg).textContent = fmt(Math.round(max*f*10)/10)+(p.unit&&f?p.unit:''); });
    if(p.type==='area'){
      const s=p.series[0]; let d='';
      s.v.forEach((v,i)=>{ d+=(i?'L':'M')+(x(i)+bw/2).toFixed(1)+','+y(v||0).toFixed(1); });
      el('path',{d:d+`L${(x(D.n-1)+bw/2).toFixed(1)},${yb}L${(x(0)+bw/2).toFixed(1)},${yb}Z`,style:`fill:var(${s.c});opacity:.18`},svg);
      el('path',{d,style:`fill:none;stroke:var(${s.c});stroke-width:2;stroke-linejoin:round`},svg);
      const mi = s.v.indexOf(Math.max(...s.v));
      el('circle',{cx:x(mi)+bw/2,cy:y(s.v[mi]),r:4,style:`fill:var(${s.c});stroke:var(--surface);stroke-width:2`},svg);
    } else if(p.type==='stack'){
      const w = Math.max(1, bw-2);
      for(let i=0;i<D.n;i++){ let acc=0; const segs=p.series.filter(s=>s.v[i]);
        segs.forEach((s,si)=>{ const v=s.v[i], top=y(acc+v), bot=y(acc); const h=Math.max(0,bot-top-(si?1.5:0));
          el('rect',{x:x(i)+1,y:top,width:w,height:h,rx:si===segs.length-1?Math.min(3,w/2):0,style:`fill:var(${s.c})`},svg); acc+=v; }); }
    } else {
      p.series.forEach(s=>{ let d='',pen=false; s.v.forEach((v,i)=>{ if(v==null){pen=false;return;} d+=(pen?'L':'M')+(x(i)+bw/2).toFixed(1)+','+y(v).toFixed(1); pen=true; });
        el('path',{d,style:`fill:none;stroke:var(${s.c});stroke-width:2;stroke-linejoin:round${s.dash?';stroke-dasharray:'+s.dash:''}`},svg); });
    }
    if(pi===PANELS.length-1){ const step = labelStep();
      D.labels.forEach((l,i)=>{ if(i%step===0 || i===D.n-1 && D.n%step>2) el('text',{x:x(i)+bw/2,y:yb+16,class:'ax','text-anchor':'middle'},svg).textContent=l; }); }
  });
  mk.forEach(m=>{ const xx=x(m.i); el('line',{x1:xx,x2:xx,y1:TOP-6,y2:H-4,class:'mark-line'},svg);
    el('text',{x:xx+4,y:TOP-10+ (m.label==='Probe storm'?0:0),class:'mark-text'},svg).textContent=m.label; });
  // hover layer
  const cross = el('line',{y1:TOP,y2:H-4,class:'cross',visibility:'hidden'},svg);
  const hit = el('rect',{x:L,y:0,width:W-L-R,height:H,fill:'transparent'},svg);
  const tip = document.createElement('div'); tip.className='tip'; tip.hidden=true; host.appendChild(tip);
  const move = ev=>{ const r=svg.getBoundingClientRect(), sx=(ev.clientX-r.left)*W/r.width; const i=Math.max(0,Math.min(D.n-1,Math.floor((sx-L)/bw)));
    const cx=x(i)+bw/2; cross.setAttribute('x1',cx); cross.setAttribute('x2',cx); cross.setAttribute('visibility','visible');
    const row=(c,n,v,line)=>`<div class="r"><span>${line?`<i class="swl" style="border-color:var(${c})"></i>`:`<i class="sw" style="background:var(${c})"></i>`}${n}</span><b>${v}</b></div>`;
    tip.innerHTML = `<div style="font:600 13px var(--f-display);margin-bottom:4px">${D.labels[i]}</div>`+
      row('--s-probe','Probe responses',fmt(D.series.probe[i]))+
      row('--s-r23','Failed, reason 23',fmt(D.series.fail.r23[i]))+row('--s-r2','Failed, reason 2',fmt(D.series.fail.r2[i]))+row('--s-other','Failed, other',fmt(D.series.fail.other[i]))+
      row('--s-r2','AP kicks, reason 2',fmt(D.series.dis.r2[i]))+
      row('--s-ink','Retry, all frames',(D.series.retry_all[i]??'–')+'%',1)+row('--s-probe','Retry, probe resp.',(D.series.retry_presp[i]??'–')+'%',1);
    tip.hidden=false; const px=(cx/W)*r.width; tip.style.left = (px+tip.offsetWidth+16>r.width? px-tip.offsetWidth-10 : px+12)+'px'; tip.style.top='8px'; };
  hit.addEventListener('pointermove',move); hit.addEventListener('pointerleave',()=>{tip.hidden=true;cross.setAttribute('visibility','hidden');});
}

/* ---------- heatmap ---------- */
const HEAT = {probe_resp:['Probe responses','per minute'], failed_attempts:['Failed attempts','per minute'], disconnects:['AP disconnects','deauth + disassoc per minute'], retry:['Retry, all frames','% of frames']};
function renderHeatSeg(){
  $('#heatseg').innerHTML = Object.entries(HEAT).map(([k,[n]])=>`<button data-h="${k}" aria-pressed="${state.heat===k}">${n}</button>`).join('');
  $('#heatseg').onclick = e=>{ const b=e.target.closest('button'); if(!b) return; state.heat=b.dataset.h; renderHeatSeg(); drawHeat(); };
}
function drawHeat(){
  const host=$('#heat'); host.innerHTML='';
  const W=Math.max(320,host.clientWidth), RH=22, TOP=6, S=D.heat_sensors, H=TOP+S.length*RH+44;
  const svg=el('svg',{viewBox:`0 0 ${W} ${H}`,role:'img','aria-label':'Per-channel heatmap'},host);
  const {bw,x}=xScale(W), M=D.heat[state.heat];
  let max=0; M.forEach(r=>r.forEach(v=>{ if(v!=null) max=Math.max(max,v); })); max=max||1;
  if(state.win) el('rect',{x:x(state.win[0])-1,y:TOP-3,width:(state.win[1]-state.win[0]+1)*bw+2,height:S.length*RH+6,style:'fill:none;stroke:var(--accent);stroke-width:2',rx:2},svg);
  S.forEach((s,si)=>{ const yy=TOP+si*RH;
    el('text',{x:L-6,y:yy+RH/2+4,class:'ax','text-anchor':'end'},svg).textContent='ch '+s.channel;
    M[si].forEach((v,i)=>{ if(v==null) return; const f=Math.pow(v/max,.75);
      el('rect',{x:x(i)+.5,y:yy+1,width:Math.max(1,bw-1),height:RH-2,rx:1.5,style:`fill:color-mix(in oklab, var(--heat-hi) ${(f*100).toFixed(0)}%, var(--heat-lo))`},svg); }); });
  const yb=TOP+S.length*RH, step=labelStep();
  D.labels.forEach((l,i)=>{ if(i%step===0) el('text',{x:x(i)+bw/2,y:yb+14,class:'ax','text-anchor':'middle'},svg).textContent=l; });
  // scale legend
  const lg=el('g',{},svg), lx=W-R-160, ly=yb+24;
  for(let k=0;k<20;k++) el('rect',{x:lx+k*8,y:ly,width:8,height:8,style:`fill:color-mix(in oklab, var(--heat-hi) ${Math.round(Math.pow(k/19,.75)*100)}%, var(--heat-lo))`},lg);
  el('text',{x:lx-6,y:ly+8,class:'ax','text-anchor':'end'},lg).textContent='0';
  el('text',{x:lx+164,y:ly+8,class:'ax'},lg).textContent='';
  el('text',{x:lx+160,y:ly+20,class:'ax','text-anchor':'end'},lg).textContent=fmt(Math.round(max*10)/10)+(state.heat==='retry'?'%':'');
  el('text',{x:L,y:ly+8,class:'psub'},svg).textContent=HEAT[state.heat][0]+', '+HEAT[state.heat][1]+
    (D.sensors.length>S.length?` · ${S.length} of ${D.sensors.length} sensors, most failures first`:'');
  const tip=document.createElement('div'); tip.className='tip'; tip.hidden=true; host.appendChild(tip);
  const hit=el('rect',{x:L,y:TOP,width:W-L-R,height:S.length*RH,fill:'transparent'},svg);
  hit.addEventListener('pointermove',ev=>{ const r=svg.getBoundingClientRect(), sx=(ev.clientX-r.left)*W/r.width, sy=(ev.clientY-r.top)*H/r.height;
    const i=Math.max(0,Math.min(D.n-1,Math.floor((sx-L)/bw))), si=Math.max(0,Math.min(S.length-1,Math.floor((sy-TOP)/RH)));
    const v=M[si][i]; tip.innerHTML=`<div style="font:600 13px var(--f-display)">ch ${S[si].channel} · ${S[si].name}</div><div class="r"><span>${D.labels[i]} · ${HEAT[state.heat][0]}</span><b>${v==null?'–':fmt(v)+(state.heat==='retry'?'%':'')}</b></div>`;
    tip.hidden=false; const px=(sx/W)*r.width, py=(sy/H)*r.height; tip.style.left=(px+tip.offsetWidth+16>r.width?px-tip.offsetWidth-10:px+12)+'px'; tip.style.top=(py+14)+'px'; });
  hit.addEventListener('pointerleave',()=>tip.hidden=true);
}

/* ---------- clients ---------- */
function gname(g){ const o=D.oui[g]; return o? `${g} (${o})` : g; }
function renderFilters(){
  $('#filters').innerHTML = `<button data-g="all" aria-pressed="${state.group==='all'}">All groups</button>`+
    D.groups.map(([g,n])=>`<button data-g="${g}" aria-pressed="${state.group===g}">${esc(gname(g))} · ${n}</button>`).join('')+
    `<button data-f="1" aria-pressed="${state.failing}">Failing only</button>
     <label for="q" class="muted" style="font-size:13px;margin-left:4px">Find</label><input id="q" type="search" placeholder="MAC address" value="${esc(state.q)}">`;
  $('#filters').onclick=e=>{ const b=e.target.closest('button'); if(!b) return;
    if(b.dataset.g) state.group=b.dataset.g; if(b.dataset.f) state.failing=!state.failing; renderFilters(); renderTable(); };
  $('#q').oninput=e=>{ state.q=e.target.value.toLowerCase(); renderTable(); };
}
function howFailed(c){
  if(!c.fail) return c.prob? '<span class="pill ok">probable success</span> AP sent M3, client not heard' : (c.ok?'<span class="pill ok">connected</span>':'');
  const t=c.top||''; const m=t.match(/\((\d+):/); const code=m?` <span class="pill bad">reason ${m[1]}</span>`:'';
  const short=t.replace(/\s*\(\d+:.*$/,'').replace('EAP identity loop: ','Identity loop: ').replace(' (client not audible to sensor)',', client not heard');
  return esc(short)+code;
}
function renderTable(){
  const maxf=Math.max(1,...D.clients.map(c=>c.fail));
  const rows=D.clients.filter(c=>(state.group==='all'||c.g===state.group)&&(!state.failing||c.fail>0)&&(!state.q||c.mac.includes(state.q)))
    .sort((a,b)=>b.fail-a.fail||b.dis-a.dis||b.att-a.att);
  $('#tbody').innerHTML = rows.map(c=>`<tr tabindex="0" data-mac="${c.mac}" aria-selected="${state.client===c.mac}">
    <td class="mono">${c.mac}</td><td>${esc(c.ssid)}</td><td class="n">${c.att}</td>
    <td class="n">${c.fail}<i class="bar" style="width:${Math.round(34*c.fail/maxf)}px"></i></td>
    <td class="why">${howFailed(c)}</td><td class="n">${c.dis||''}</td><td class="n">${esc(c.ch)}</td></tr>`).join('') ||
    `<tr><td colspan="7" class="muted">No clients match these filters.</td></tr>`;
  if(D.clients_total>D.clients.length) $('#tbody').insertAdjacentHTML('beforeend',
    `<tr><td colspan="7" class="muted">Showing the ${D.clients.length} clients with the most failures of ${fmt(D.clients_total)}. All clients are in clients.csv.</td></tr>`);
  $('#tbody').onclick=e=>{ const tr=e.target.closest('tr[data-mac]'); if(tr) selectClient(tr.dataset.mac); };
  $('#tbody').onkeydown=e=>{ if(e.key==='Enter'){ const tr=e.target.closest('tr[data-mac]'); if(tr) selectClient(tr.dataset.mac); } };
}
function selectClient(mac, scroll){
  state.client=mac; state.ladN=60;
  const c=D.clients.find(x=>x.mac===mac);
  if(c && state.failing && !c.fail){ state.failing=false; renderFilters(); }
  if(c && state.group!=='all' && c.g!==state.group){ state.group='all'; renderFilters(); }
  renderTable(); drawLadder();
  if(scroll) $('#h-cl').scrollIntoView({behavior:'smooth',block:'start'});
}

/* ---------- ladder ---------- */
const KIND = {AUTH_REQ:'Auth request',AUTH_RESP:'Auth response',ASSOC_REQ:'Assoc request',ASSOC_RESP:'Assoc response',EAP_REQ:'EAP request',EAP_RESP:'EAP response',
  EAP_SUCCESS:'EAP success',EAP_FAILURE:'EAP failure',EAPOL_START:'EAPOL start',KEY_M1:'Key M1',KEY_M2:'Key M2',KEY_M3:'Key M3',KEY_M4:'Key M4',DEAUTH:'Deauth',DISASSOC:'Disassoc',KEY_OTHER:'Key (other)'};
function detailText(k,d){
  const o={}; (d||'').split(' ').forEach(p=>{ const [a,b]=p.split('='); if(b!==undefined) o[a]=b; });
  if(k==='EAP_REQ'||k==='EAP_RESP') return `${o.eap_type==='1'?'Identity':'type '+(o.eap_type||'?')} · id ${o.eap_id}`;
  if(k==='DEAUTH'||k==='DISASSOC') return `reason ${o.reason}`+( {2:' · auth no longer valid',3:' · leaving',23:' · 802.1X failed'}[o.reason]||'');
  if(k==='AUTH_RESP'||k==='ASSOC_RESP') return o.status==='0'?'status 0 · ok':'status '+o.status;
  if(k.startsWith('KEY_')) return o.key_info||'';
  return '';
}
function drawLadder(){
  const host=$('#ladder'); host.innerHTML=''; $('#lad-more').innerHTML='';
  const mac=state.client, ev=(D.tl[mac]||[]), total=(D.tl_counts||{})[mac]||ev.length;
  if(!mac){ $('#lad-title').textContent='Frame sequence'; $('#lad-sub').textContent='Pick a client in the table to see every connection frame between it and its AP.'; return; }
  const c=D.clients.find(x=>x.mac===mac)||{};
  $('#lad-title').innerHTML=`<span class="mono" style="font-size:16px">${mac}</span>`;
  const aps=[...new Set(ev.map(e=>e[4]))];
  $('#lad-sub').innerHTML=`${esc(c.ssid||'')} · ${ev.length} frames · ${c.fail||0} failed of ${c.att||0} attempts · AP <span class="mono">${aps.slice(0,2).join(', ')}${aps.length>2?' +'+(aps.length-2):''}</span>`;
  const show=ev.slice(0,state.ladN), W=Math.max(300,host.clientWidth-4), narrow=W<470, RH=narrow?40:30, TOP=38;
  const cx=Math.round(W*0.30), ax=W-16, H=TOP+show.length*RH+10;
  const svg=el('svg',{viewBox:`0 0 ${W} ${H}`,role:'img','aria-label':'Frame sequence'},host);
  el('text',{x:cx,y:14,class:'lane-h','text-anchor':'middle'},svg).textContent='Client';
  el('text',{x:ax,y:14,class:'lane-h','text-anchor':'end'},svg).textContent='Access point';
  el('text',{x:ax,y:28,class:'lane-s','text-anchor':'end'},svg).textContent=aps[0]||'';
  el('line',{x1:cx,x2:cx,y1:TOP-6,y2:H,class:'lane'},svg); el('line',{x1:ax,x2:ax,y1:TOP-6,y2:H,class:'lane'},svg);
  const defs=el('defs',{},svg);
  [['a-ap','--ink-2'],['a-cl','--accent'],['a-bad','--crit']].forEach(([id,c])=>{ const m=el('marker',{id,viewBox:'0 0 8 8',refX:7,refY:4,markerWidth:7,markerHeight:7,orient:'auto-start-reverse'},defs); el('path',{d:'M0,0L8,4L0,8Z',style:`fill:var(${c})`},m); });
  let prevT=null;
  show.forEach((e,i)=>{ const [t,dir,k,d,b]=e, y=TOP+i*RH+14;
    const secs = (s=>{const [h,m,x]=s.split(':'); return +h*3600+ +m*60+ +x;})(t);
    if(prevT!=null && secs-prevT>20) el('text',{x:(cx+ax)/2,y:y-17,class:'gapnote','text-anchor':'middle'},svg).textContent=`${Math.round(secs-prevT)} s later`;
    prevT=secs;
    const bad = k==='DEAUTH'||k==='DISASSOC'||k==='EAP_FAILURE';
    const col = bad?'--crit':dir===1?'--accent':'--ink-2', mid = bad?'a-bad':dir===1?'a-cl':'a-ap';
    const x1 = dir===1?cx:ax, x2 = dir===1?ax-2:cx+2;
    el('text',{x:cx-10,y:y+4,class:'lad-t','text-anchor':'end'},svg).textContent=t.slice(0,12);
    el('line',{x1,x2,y1:y,y2:y,style:`stroke:var(${col});stroke-width:${bad?2:1.5}`,'marker-end':`url(#${mid})`},svg);
    const lbl=el('text',{x:cx+10,y:y-5,class:'lad-k'},svg); lbl.textContent=KIND[k]||k; if(bad) lbl.style.fill='var(--crit)';
    const dt=detailText(k,d); if(dt){ const t2=el('text',narrow?{x:cx+10,y:y+13,class:'lad-d'}:{x:ax-8,y:y-5,class:'lad-d','text-anchor':'end'},svg); t2.textContent=dt; }
  });
  if(!ev.length){ host.innerHTML='<p class="muted">Frames for this client are not embedded in the page (only the clients with the most failures are). Filter timelines.csv by this MAC.</p>'; return; }
  if(total>ev.length && state.ladN>=ev.length) $('#lad-more').innerHTML=`<p class="muted" style="font-size:13px">First ${ev.length} of ${fmt(total)} frames shown. The rest are in timelines.csv.</p>`;
  if(ev.length>state.ladN){ $('#lad-more').innerHTML=`<button id="more">Show next ${Math.min(60,ev.length-state.ladN)} of ${ev.length-state.ladN} more frames</button>`;
    $('#more').onclick=()=>{ state.ladN+=60; drawLadder(); }; }
}

/* ---------- evidence ---------- */
(function(){
  const o=D.outcomes, yes=[];
  yes.push(`${fmt(D.kpis.frames)} frames parsed from ${D.kpis.sensors} sensors; per-frame type, direction, Retry bit, sequence number, signal.`);
  yes.push(`Connection state machine per client: authentication, association, EAP, 4-way handshake, and the reason or status code whenever the AP ended an attempt.`);
  yes.push(`Frames heard by several sensors are counted once; clients are followed across access points and channels.`);
  yes.push(`Every failure carries a confidence: high when a frame proves it (deauth, rejection), medium when it is inferred from silence.`);
  $('#ev-yes').innerHTML=yes.map(t=>`<li>${esc(t)}</li>`).join('');
  $('#qt').innerHTML=`<thead><tr><th>Sensor</th><th>Ch</th><th style="text-align:right">Frames</th><th style="text-align:right">Bad</th><th style="text-align:right">Gaps</th></tr></thead><tbody>`+
    D.sensors.slice().sort((a,b)=>(b.gaps-a.gaps)).slice(0,50).map(s=>{ const q=s.quality||{}, bad=(q.bad_radiotap||0)+(q.bad_80211||0)+(q.truncated_records||0);
      return `<tr><td class="mono">${s.name}</td><td class="n">${s.channel}</td><td class="n">${fmt(s.records)}</td><td class="n">${bad}</td><td class="n">${s.gaps}</td></tr>`; }).join('')+'</tbody>';
})();

/* ---------- boot ---------- */
renderFindings(); renderLegend(); renderHeatSeg(); renderFilters(); renderTable();
drawTimeline(); drawHeat();
const firstEx = (D.findings.find(f=>f.example)||{}).example; if(firstEx) { state.client=firstEx; renderTable(); }
drawLadder();
let rt; new ResizeObserver(()=>{ clearTimeout(rt); rt=setTimeout(()=>{ drawTimeline(); drawHeat(); drawLadder(); },120); }).observe(document.querySelector('.wrap'));
</script>
'''


def write(folder, fragment=False):
    data = build(folder)
    body = TEMPLATE.replace('/*__DATA__*/null', json.dumps(data, separators=(',', ':')).replace('</', '<\\/'))
    if fragment:
        html = body
    else:
        html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                # the page can make no network requests at all: data never leaves the machine
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
                'style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; img-src data:">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">' + body + '</body></html>')
    out = os.path.join(folder, 'dashboard.html')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    print('wrote', out, f'({len(html) // 1024} KB)')
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    write(args[0] if args else 'airframe_results', '--fragment' in sys.argv)


if __name__ == '__main__':
    main()
