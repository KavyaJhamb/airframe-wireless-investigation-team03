"""Real-world captures from the Wireshark and aircrack-ng test suites (downloaded on first run)."""
import pytest

from public_captures import CAPTURES


@pytest.mark.parametrize("name", list(CAPTURES), ids=list(CAPTURES))
def test_public_capture(public, name):
    r = public(name)
    expect = CAPTURES[name][2]
    outcomes = r.outcomes()

    if "connected" in expect:
        assert outcomes.get("connected", 0) >= expect["connected"], outcomes
    if "outcomes" in expect:
        assert outcomes == expect["outcomes"]
    found = set(r.findings.category) if len(r.findings) else set()
    for cat in expect.get("no_categories", []):
        assert cat not in found, f"false positive: {cat}\n{r.findings[['category', 'title']]}"
    if "has_category" in expect:
        assert expect["has_category"] in found
    if "frames" in expect:
        assert r.summary["frames"] == expect["frames"]


def test_flood_is_called_a_flood(public):
    r = public("wep_64_ptw")
    loop = r.cat("Deauth / disassoc loop")
    assert len(loop) == 1 and "flood" in loop.title.iloc[0]
    assert loop["count"].iloc[0] >= 100


def test_utf8_ssid_is_masked(public):
    r = public("Chinese-SSID-Name")
    assert r.summary["ssids"], "SSID not picked up"
    import subprocess, public_captures as pc
    raw = subprocess.run(["tshark", "-r", str(pc.path_for("Chinese-SSID-Name")), "-T", "fields",
                          "-e", "wlan.ssid"], capture_output=True, text=True).stdout.strip()
    ssid = bytes.fromhex(raw).decode("utf-8", "replace") if raw else ""
    assert ssid and ssid.lower() not in r.all_text()
