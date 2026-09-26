#!/usr/bin/env python3
"""
Run both Airframe pipelines on the eleven new sample cases and check each against its ground truth.

    python3 sample_cases/run_sample_cases.py            # needs scapy (and tshark for that engine); about 1 minute

Writes a PASS/FAIL table to stdout and to sample_cases/results.txt. The same checks are applied to both
engines; outcome and severity names are mapped where the engines use different words.
"""
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "pipeline_tshark"))

import extract  # noqa: E402  (Wireshark pipeline, for the masked-label function)
from sample_cases import CASES  # noqa: E402

SALT = "sample-case-salt"
SUCCESS = {"connected", "success", "probable_success_client_unheard", "assoc_comeback"}
FAILED = {  # both engines' failure outcomes
    "auth_rejected", "assoc_rejected", "stalled_after_auth", "stalled_after_assoc", "incomplete", "eap_failed",
    "eap_no_response", "handshake_failed", "eap_failure", "deauth_during_setup", "stalled", "restarted"}


def rows(path):
    return list(csv.DictReader(open(path, encoding="utf-8"))) if path.exists() and path.stat().st_size > 1 else []


class Engine:
    """Common view of one engine's output for one case."""

    def __init__(self, name, out, label):
        self.name, self.out, self.label = name, out, label
        self.findings = rows(out / "findings.csv")
        self.attempts = rows(out / "attempts.csv")
        self.summary = json.loads((out / "summary.json").read_text())

    def f(self, category=None, mac=None, problems_only=False):
        c = self.label(mac) if mac else None
        return [r for r in self.findings if (category is None or r["category"] == category)
                and (c is None or r.get("client", "") == c)
                and (not problems_only or r["severity"] != "info")]

    def top(self, category):
        return [r for r in self.findings if r["category"] == category and not r.get("parent")]

    def outcomes(self, mac):
        c = self.label(mac)
        return [a["outcome"] for a in self.attempts if a["client"] == c]

    def text(self):
        return "\n".join(p.read_text(errors="ignore") for p in self.out.iterdir()
                         if p.suffix in (".csv", ".json", ".txt", ".md")).lower()


def run_tshark(pcaps, out):
    salt_file = out.parent / "salt"
    salt_file.write_text(SALT)
    for cmd in ([sys.executable, str(ROOT / "pipeline_tshark" / "extract.py"), "--pcaps", str(pcaps), "--out", str(out),
                 "--salt-file", str(salt_file), "--workers", "2"],
                [sys.executable, str(ROOT / "pipeline_tshark" / "detect.py"), "--out", str(out)]):
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode:
            raise RuntimeError(p.stderr.strip().splitlines()[-1])
    return Engine("tshark", out, lambda m: "C-" + extract.mask_mac(m, SALT)[:6])


def run_fast(pcaps, out, mask=False):
    cmd = [sys.executable, str(ROOT / "pipeline_fast" / "airframe_analyze.py"), str(pcaps), "--out", str(out),
           "--jobs", "1", "--tz", "UTC"] + (["--salt-file", str(out.parent / "fsalt")] if mask else ["--no-mask"])
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip().splitlines()[-1])
    return Engine("fast", out, lambda m: m.lower())


# ------------------------------------------------------------------ checks: list of (description, fn(engine, truth))
def no_problems_for(e, macs):
    return all(not e.f(mac=m, problems_only=True) for m in macs)


CHECKS = {
    "partial_credential_reject": [
        ("each refused client has an 802.1X finding", lambda e, t: all(e.f("802.1X / EAP failure", m) for m in t["bad"])),
        ("not reported as network-wide (3 of 10)", lambda e, t: not [r for r in e.top("802.1X / EAP failure") if r["severity"] == "critical"]),
        ("the 7 good clients all connect, no findings", lambda e, t: all(set(e.outcomes(m)) <= SUCCESS and e.outcomes(m) for m in t["good"]) and no_problems_for(e, t["good"])),
    ],
    "sensor_gap": [
        ("a sensor gap is not reported as silent APs", lambda e, t: not e.f("AP silent / beacon loss")),
        ("no congestion reported", lambda e, t: not e.f("Congestion / channel health")),
    ],
    "clock_skew_same_channel": [
        ("one finding for the client, not two", lambda e, t: len(e.f(mac=t["client"], problems_only=True)) == 1),
        ("3 attempts, not doubled", lambda e, t: len(e.outcomes(t["client"])) == t["attempts"]),
    ],
    "spoofed_flood": [
        ("flood is reported", lambda e, t: any("flood" in (r["title"] + r["explanation"]).lower() for r in e.f("Deauth / disassoc loop", t["client"]))),
        ("does not claim the AP really sent it", lambda e, t: all("not spoofed" not in r["explanation"].lower() and "sent by the real ap" not in r["explanation"].lower()
                                                                  for r in e.f("Deauth / disassoc loop", t["client"]))),
    ],
    "ping_pong_roam": [
        ("no problem findings", lambda e, t: not [r for r in e.findings if r["severity"] != "info"]),
        ("all 10 joins succeed", lambda e, t: len(e.outcomes(t["client"])) == 10 and set(e.outcomes(t["client"])) <= SUCCESS),
        ("9 roams recognised", lambda e, t: int(e.summary.get("roams", 0)) == t["roams"]),
    ],
    "hidden_ssid_wrong_psk": [
        ("wrong-passphrase client has a handshake finding", lambda e, t: bool(e.f("4-way handshake failure", t["bad"]))),
        ("the other client connects, no findings", lambda e, t: set(e.outcomes(t["ok"])) <= SUCCESS and e.outcomes(t["ok"]) and no_problems_for(e, [t["ok"]])),
    ],
    "randomized_mac_timeout": [
        ("802.1X finding for the randomised-MAC client", lambda e, t: bool(e.f("802.1X / EAP failure", t["client"]))),
    ],
    "mixed_incident": [
        ("network-wide 802.1X finding covering the 6 clients", lambda e, t: any(r["severity"] == "critical" and int(r["count"]) == 6 for r in e.top("802.1X / EAP failure"))),
        ("separate loop finding for the PSK client", lambda e, t: bool(e.f("Deauth / disassoc loop", t["looper"]))),
        ("congestion found on channel 44 only", lambda e, t: [r["channels"].strip("[]'\" ") for r in e.f("Congestion / channel health")] == ["44"]),
        ("healthy IoT devices: connected, no findings", lambda e, t: all(set(e.outcomes(m)) <= SUCCESS and e.outcomes(m) for m in t["iot"]) and no_problems_for(e, t["iot"])),
    ],
    "eap_ok_handshake_timeout": [
        ("reported as a handshake failure", lambda e, t: bool(e.f("4-way handshake failure", t["client"]))),
        ("not reported as an 802.1X failure", lambda e, t: not e.f("802.1X / EAP failure", t["client"])),
    ],
    "already_connected_then_leaves": [
        ("no failure, no findings", lambda e, t: not (set(e.outcomes(t["client"])) & FAILED) and no_problems_for(e, [t["client"]])),
    ],
    "retry_mix_trap": [
        ("no congestion from probe-response retries", lambda e, t: not e.f("Congestion / channel health")),
    ],
}


def main():
    work = Path(tempfile.mkdtemp(prefix="airframe_cases_"))
    have_tshark = shutil.which("tshark") is not None      # without it, the fast engine is still checked
    lines, tally = [], {"tshark": [0, 0], "fast": [0, 0]}
    for name, build in CASES.items():
        pcaps = work / name / "pcaps"
        truth = build(pcaps)
        engines = []
        for runner, en in ((run_tshark, "tshark"), (run_fast, "fast")):
            if en == "tshark" and not have_tshark:
                engines.append(None)
                continue
            try:
                engines.append(runner(pcaps, work / name / f"out_{en}"))
            except Exception as ex:  # an engine crash is a failed case, not a crashed run
                engines.append(ex)
        lines.append(f"\n{name}")
        for desc, fn in CHECKS[name]:
            res = []
            for en, e in zip(("tshark", "fast"), engines):
                if e is None:
                    res.append("SKIP")
                    continue
                ok = False if isinstance(e, Exception) else bool(fn(e, truth))
                tally[en][0] += ok
                tally[en][1] += 1
                res.append("PASS" if ok else ("CRASH" if isinstance(e, Exception) else "FAIL"))
            lines.append(f"  {res[0]:5} {res[1]:5}  {desc}")
        if name == "randomized_mac_timeout":   # privacy: masked runs must not contain the raw MAC or SSID
            fm = run_fast(pcaps, work / name / "out_fast_masked", mask=True)
            leaks = [e.name for e in (engines[0], fm) if e is not None
                     and (truth["client"] in e.text() or "corpnet" in e.text())]
            for en in ("tshark", "fast") if have_tshark else ("fast",):
                ok = en not in leaks
                tally[en][0] += ok
                tally[en][1] += 1
            ts = ('PASS' if 'tshark' not in leaks else 'FAIL') if have_tshark else 'SKIP'
            lines.append(f"  {ts:5} {'PASS' if 'fast' not in leaks else 'FAIL':5}  masked output has no raw MAC or SSID")
    head = "Sample cases: both engines against ground truth\n  tshark fast\n"
    foot = "\n" + "  ".join(f"{en}: {p}/{n} pass" if n else f"{en}: skipped (not installed)"
                            for en, (p, n) in tally.items())
    text = head + "\n".join(lines) + "\n" + foot + "\n"
    print(text)
    if have_tshark:                                        # the shipped results.txt covers both engines
        (HERE / "results.txt").write_text(text)


if __name__ == "__main__":
    main()
