"""Synthetic scenarios with exact ground truth, one per detector and judgment rule."""


def test_normal_roam_is_not_a_failure(scenario):
    r, t = scenario("normal_roam")
    assert r.summary["roams"] == 1
    assert len(r.cat("Deauth / disassoc loop")) == 0
    assert set(r.findings.severity) <= {"info"}, r.findings[["category", "title"]]


def test_deauth_loop_is_one_finding(scenario):
    r, t = scenario("deauth_loop")
    loop = r.cat("Deauth / disassoc loop")
    assert len(loop) == 1, "one client in a loop = one finding"
    assert loop.client.iloc[0] == r.client(t["client"])
    assert loop["count"].iloc[0] >= 12
    assert "every ~10 s" in loop.title.iloc[0]


def test_single_deauth_is_not_a_loop(scenario):
    r, t = scenario("single_deauth")
    assert len(r.cat("Deauth / disassoc loop")) == 0
    assert r.outcomes(t["client"]).get("connected", 0) == 2


def test_eap_failure_client_answered(scenario):
    r, t = scenario("eap_failure")
    f = r.cat("802.1X / EAP failure")
    assert len(f) == 1 and f.client.iloc[0] == r.client(t["client"])
    assert r.outcomes(t["client"]) == {"eap_failed": 3}
    assert "answered" in f.explanation.iloc[0]


def test_eap_timeout_ap_side_only(scenario):
    r, t = scenario("eap_timeout")
    assert r.outcomes(t["client"]) == {"eap_no_response": 3}
    f = r.cat("802.1X / EAP failure")
    assert "AP side only" in f.tags.iloc[0]


def test_wrong_psk_handshake(scenario):
    r, t = scenario("wrong_psk")
    f = r.cat("4-way handshake failure")
    assert len(f) == 1 and r.outcomes(t["client"]) == {"handshake_failed": 2}
    assert "M1M2" in f.explanation.iloc[0] and "reason 15" in f.explanation.iloc[0]


def test_ap_full_join_failure(scenario):
    r, t = scenario("ap_full")
    f = r.cat("Join failure")
    assert len(f) == 1 and "AP full" in f.explanation.iloc[0]
    assert r.outcomes(t["client"]) == {"assoc_rejected": 3}


def test_same_event_two_sensors_counted_once(scenario):
    r, t = scenario("same_event_two_sensors")
    f = r.for_client(t["client"])
    assert len(f) == 1, "same client seen by two sensors must be one finding"
    assert set(f.sensors.iloc[0].split(";")) == {"sA", "sB"}
    assert len(r.attempts) == t["attempts"], "attempts double-counted across sensors"
    ev = r.events[r.events.client == r.client(t["client"])]
    assert (ev.copies == 2).all()


def test_probe_storm_only_noisy_client(scenario):
    r, t = scenario("probe_storm")
    f = r.cat("Probe storm")
    assert list(f.client) == [r.client(t["noisy"])]


def test_silent_ap(scenario):
    r, t = scenario("silent_ap")
    f = r.cat("AP silent / beacon loss")
    assert len(f) == 1
    assert f.ap.iloc[0].startswith(r.ap(t["silent"]))
    assert f["count"].iloc[0] == 2          # minutes 2 and 3


def test_congestion_only_bad_channel(scenario):
    r, t = scenario("congestion")
    f = r.cat("Congestion / channel health")
    assert list(f.channels.astype(str)) == [str(t["bad_channel"])]


def test_systemic_8021x_rollup(scenario):
    r, t = scenario("systemic_8021x")
    top = r.cat("802.1X / EAP failure")
    parent = top[(top.severity == "critical") & (top.parent == "")]
    assert len(parent) == 1 and parent["count"].iloc[0] == len(t["clients"])
    kids = top[top.parent == parent.id.iloc[0]]
    assert set(kids.client) == {r.client(m) for m in t["clients"]}
    for m in t["iot"]:                     # the PSK network is fine
        assert r.outcomes(m) == {"connected": 1}


def test_capture_end_is_not_a_failure(scenario):
    r, t = scenario("capture_ends_mid_join")
    assert r.outcomes(t["client"]) == {"in_progress": 1}
    assert len(r.for_client(t["client"])) == 0


def test_client_leaving_is_not_a_failure(scenario):
    r, t = scenario("client_left")
    assert r.outcomes(t["client"]) == {"client_left": 1}
    assert len(r.for_client(t["client"])) == 0


def test_assoc_comeback_is_not_a_failure(scenario):
    r, t = scenario("assoc_comeback")
    assert r.outcomes(t["client"]) == {"assoc_comeback": 1, "connected": 1}
    assert len(r.cat("Join failure")) == 0


def test_disassoc_flood(scenario):
    r, t = scenario("disassoc_flood")
    f = r.cat("Deauth / disassoc loop")
    assert len(f) == 1 and "flood" in f.title.iloc[0] and f["count"].iloc[0] == 200
