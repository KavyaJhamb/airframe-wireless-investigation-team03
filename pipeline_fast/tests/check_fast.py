#!/usr/bin/env python3
"""
Runs the fast pipeline through the same checks as the Wireshark-based pipeline's test suite:
  - the 16 generated scenarios with known answers (pipeline_tshark/tests/scenarios.py, needs scapy)
  - the 16 public captures from the Wireshark and aircrack-ng test suites (downloaded on first run)
  - privacy: with --mask, no raw MAC address or SSID from any scenario appears in any output file

Usage:  python3 pipeline_fast/tests/check_fast.py            (about 30 s; exit code 1 if anything fails)
Outcome names differ between the two engines; the mapping is written out in each check.
"""
import collections, csv, glob, gzip, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, '..', 'airframe_analyze.py')
TSHARK_TESTS = os.path.join(HERE, '..', '..', 'pipeline_tshark', 'tests')
sys.path.insert(0, TSHARK_TESTS)


def analyze(src, out, *extra):
    """Raw identifiers (--no-mask) so checks can name devices, unless extra asks for the default masking."""
    extra = extra or ('--no-mask',)
    p = subprocess.run([sys.executable, ENGINE, src, '--out', out, '--jobs', '1', '--tz', 'UTC', *extra],
                       capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip().splitlines()[-1])


class R:
    def __init__(self, out):
        def rd(n):
            p = os.path.join(out, n)
            return list(csv.DictReader(open(p, encoding='utf-8'))) if os.path.getsize(p) else []
        self.findings, self.attempts, self.tl = rd('findings.csv'), rd('attempts.csv'), rd('timelines.csv')
        self.summary = json.load(open(os.path.join(out, 'summary.json'), encoding='utf-8'))

    def cat(self, c):
        return [f for f in self.findings if f['category'] == c]

    def for_client(self, m):
        return [f for f in self.findings if f['client'] == m]

    def outcomes(self, m=None):
        return dict(collections.Counter(a['outcome'] for a in self.attempts if m is None or a['client'] == m))

    def att(self, m):
        return [a for a in self.attempts if a['client'] == m]


# ------------------------------------------------------------------ the 16 scenarios (tests/test_scenarios.py)
def s_normal_roam(r, t):
    assert r.summary['roams'] == 1
    assert not r.cat('Deauth / disassoc loop')
    assert {f['severity'] for f in r.findings} <= {'info'}


def s_deauth_loop(r, t):
    loop = r.cat('Deauth / disassoc loop')
    assert len(loop) == 1 and loop[0]['client'] == t['client'] and int(loop[0]['count']) >= 12
    assert 'every ~10 s' in loop[0]['title'], loop[0]['title']


def s_single_deauth(r, t):
    assert not r.cat('Deauth / disassoc loop')
    assert r.outcomes(t['client']).get('success', 0) == 2                  # theirs: connected


def s_eap_failure(r, t):
    f = r.cat('802.1X / EAP failure')
    assert len(f) == 1 and f[0]['client'] == t['client'] and 'answered' in f[0]['explanation']
    assert r.outcomes(t['client']) == {'eap_failure': 3}                  # theirs: eap_failed


def s_eap_timeout(r, t):     # theirs: eap_no_response x3; here: deauth_during_setup at the Identity step
    a = r.att(t['client'])
    assert len(a) == 3 and all(x['outcome'] == 'deauth_during_setup' and 'EAP identity loop' in x['stage_detail']
                               for x in a)
    assert 'AP side only' in r.cat('802.1X / EAP failure')[0]['tags']


def s_wrong_psk(r, t):       # theirs: handshake_failed x2; here: deauth_during_setup after M2
    f, a = r.cat('4-way handshake failure'), r.att(t['client'])
    assert len(f) == 1 and len(a) == 2 and all(x['outcome'] == 'deauth_during_setup' and x['max_key'] == '2' for x in a)
    assert 'M1M2' in f[0]['explanation'] and 'reason 15' in f[0]['explanation']


def s_ap_full(r, t):
    f = r.cat('Join failure')
    assert len(f) == 1 and 'AP full' in f[0]['explanation']
    assert r.outcomes(t['client']) == {'assoc_rejected': 3}


def s_same_event_two_sensors(r, t):
    f = r.for_client(t['client'])
    assert len(f) == 1 and set(f[0]['sensors'].split(';')) == {'sA', 'sB'}
    assert len(r.attempts) == t['attempts']
    ev = [e for e in r.tl if e['client'] == t['client']]
    assert ev and all(e['copies'] == '2' for e in ev)


def s_probe_storm(r, t):
    assert [x['client'] for x in r.cat('Probe storm')] == [t['noisy']]


def s_silent_ap(r, t):
    f = r.cat('AP silent / beacon loss')
    assert len(f) == 1 and f[0]['ap'].startswith(t['silent']) and f[0]['count'] == '2'


def s_congestion(r, t):
    assert [x['channels'] for x in r.cat('Congestion / channel health')] == [str(t['bad_channel'])]


def s_systemic_8021x(r, t):
    top = r.cat('802.1X / EAP failure')
    parent = [f for f in top if f['severity'] == 'critical' and f['parent'] == '']
    assert len(parent) == 1 and parent[0]['count'] == str(len(t['clients']))
    assert {k['client'] for k in top if k['parent'] == parent[0]['id']} == set(t['clients'])
    for m in t['iot']:
        assert r.outcomes(m) == {'success': 1}


def s_capture_ends_mid_join(r, t):
    assert r.outcomes(t['client']) == {'in_progress_at_capture_end': 1}    # theirs: in_progress
    assert not r.for_client(t['client'])


def s_client_left(r, t):
    assert r.outcomes(t['client']) == {'client_left': 1} and not r.for_client(t['client'])


def s_assoc_comeback(r, t):
    assert r.outcomes(t['client']) == {'assoc_comeback': 1, 'success': 1} and not r.cat('Join failure')


def s_disassoc_flood(r, t):
    f = r.cat('Deauth / disassoc loop')
    assert len(f) == 1 and 'flood' in f[0]['title'] and f[0]['count'] == '200'


# ------------------------------------------------------------------ public captures (tests/test_public.py)
def public_check(name, expect, r):
    oc = r.outcomes()
    rename = {'connected': 'success', 'in_progress': 'in_progress_at_capture_end'}
    if 'connected' in expect:
        assert oc.get('success', 0) >= expect['connected'], oc
    if 'outcomes' in expect:
        assert oc == {rename.get(k, k): v for k, v in expect['outcomes'].items()}, oc
    cats = {f['category'] for f in r.findings}
    for c in expect.get('no_categories', []):
        assert c not in cats, f'false positive: {c}'
    if 'has_category' in expect:
        assert expect['has_category'] in cats
    if 'frames' in expect:
        assert sum(s['quality'].get('records', 0) for s in r.summary['sensors'].values()) == expect['frames']
    if name == 'wep_64_ptw':                                               # test_flood_is_called_a_flood
        loop = [f for f in r.cat('Deauth / disassoc loop') if not f['parent']]
        assert len(loop) == 1 and 'flood' in loop[0]['title'] and int(loop[0]['count']) >= 100


def main():
    results = []

    def run(label, fn):
        try:
            fn()
            results.append((label, None))
        except Exception as e:                                             # noqa: BLE001 - report every failure
            results.append((label, f'{type(e).__name__}: {e}'[:300]))
        print(('PASS  ' if results[-1][1] is None else 'FAIL  ') + label + ('' if results[-1][1] is None
                                                                           else '  ' + results[-1][1]))

    tmp = tempfile.mkdtemp(prefix='airframe-checks-')
    try:
        import scenarios
    except ImportError as e:
        print(f'SKIP  scenarios: {e} (pip install scapy)')
        scenarios = None
    if scenarios:
        salt = os.path.join(tmp, 'salt')
        for name, build in scenarios.SCENARIOS.items():
            src = os.path.join(tmp, 'scen', name)
            truth = build(__import__('pathlib').Path(src))
            out = os.path.join(tmp, 'out', name)

            def one(name=name, src=src, out=out, truth=truth):
                analyze(src, out)
                globals()['s_' + name](R(out), truth)
            run(f'scenario  {name}', one)

            def private(name=name, src=src, truth=truth):                 # tests/test_privacy.py
                out = os.path.join(tmp, 'masked', name)
                analyze(src, out, '--salt-file', salt)                  # masking is the default
                raw = {str(x).lower() for v in truth.values() for x in (v if isinstance(v, list) else [v])
                       if isinstance(x, (str, bytes))}
                raw = {x[2:-1] if x.startswith("b'") else x for x in raw}
                text = ''.join((gzip.open(f, 'rt', encoding='utf-8') if f.endswith('.gz') else
                                open(f, encoding='utf-8')).read().lower() for f in glob.glob(out + '/*'))
                leaks = sorted(x for x in raw if x and x in text)
                assert not leaks, f'raw identifiers in masked output: {leaks[:3]}'
            run(f'privacy   {name}', private)
    import public_captures as pc
    for name, (url, what, expect) in pc.CAPTURES.items():
        def one(name=name, expect=expect):
            if not pc.download([name], quiet=True):
                raise RuntimeError('could not download (offline?)')
            out = os.path.join(tmp, 'pub', name)
            analyze(str(pc.path_for(name).parent), out)
            public_check(name, expect, R(out))
        run(f'public    {name}', one)
    bad = [label for label, err in results if err]
    print(f'\n{len(results) - len(bad)}/{len(results)} passed')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
