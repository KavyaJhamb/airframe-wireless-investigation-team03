"""No raw MAC address or SSID may appear in any output file."""
import pytest

from scenarios import SCENARIOS


def raw_identifiers(truth):
    macs = []
    for v in truth.values():
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and x.count(":") == 5:
                macs.append(x)
    ssids = [s.decode() for s in truth.get("ssids", [])]
    return macs, ssids


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_no_raw_identifiers_in_outputs(scenario, name):
    r, truth = scenario(name)
    text = r.all_text()
    macs, ssids = raw_identifiers(truth)
    assert macs or ssids
    for mac in macs:
        assert mac.lower() not in text, f"raw MAC {mac} leaked"
        assert mac.replace(":", "").lower() not in text, f"raw MAC {mac} (no colons) leaked"
    for ssid in ssids:
        assert ssid.lower() not in text, f"raw SSID {ssid} leaked"


def test_no_eap_identity_field_extracted():
    import extract
    fields = [f for _, f in extract.FIELDS]
    assert not any("identity" in f for f in fields)
