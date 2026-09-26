"""The dashboard renders every tab without errors on scenario and real-world outputs."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("which", ["systemic_8021x", "deauth_loop", "normal_roam", "public:wpa-eap-tls",
                                   "public:Chinese-SSID-Name"])
def test_dashboard_renders(scenario, public, which):
    testing = pytest.importorskip("streamlit.testing.v1")
    r = public(which.split(":")[1]) if which.startswith("public:") else scenario(which)[0]
    os.environ["AIRFRAME_OUT"] = str(r.out)
    old = sys.argv
    sys.argv = ["dashboard.py"]
    try:
        at = testing.AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=60)
        at.run()
        assert not at.exception, [e.value for e in at.exception]
        for t in at.toggle:
            t.set_value(not t.value)
        at.run()
        assert not at.exception, [e.value for e in at.exception]
    finally:
        sys.argv = old
        os.environ.pop("AIRFRAME_OUT", None)
