import gzip
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

import extract  # noqa: E402

SALT = "airframe-test-salt"


class Result:
    """Loaded outputs of one pipeline run, with helpers to look things up by raw MAC."""

    def __init__(self, out: Path, log: str):
        self.out, self.log = out, log
        read = lambda n: pd.read_csv(out / n) if (out / n).stat().st_size > 1 else pd.DataFrame()
        self.findings = read("findings.csv")
        self.attempts = read("attempts.csv")
        self.events = read("events.csv")
        self.channels = read("channel_minutes.csv")
        self.aps = read("aps.csv")
        self.roams = read("roams.csv")
        self.summary = json.loads((out / "summary.json").read_text())
        for c in ["parent", "client", "ap", "tags", "sensors", "channels", "explanation", "title"]:
            if c in self.findings:
                self.findings[c] = self.findings[c].fillna("").astype(str)

    @staticmethod
    def token(mac: str) -> str:
        return extract.mask_mac(mac, SALT)

    def client(self, mac: str) -> str:
        return f"C-{self.token(mac)[:6]}"

    def ap(self, mac: str) -> str:
        row = self.aps[self.aps.token == self.token(mac)]
        return row.ap.iloc[0] if len(row) else "?"

    def cat(self, category: str) -> pd.DataFrame:
        return self.findings[self.findings.category == category] if len(self.findings) else self.findings

    def for_client(self, mac: str) -> pd.DataFrame:
        return self.findings[self.findings.client == self.client(mac)] if len(self.findings) else self.findings

    def outcomes(self, mac: str = None) -> dict:
        a = self.attempts
        if mac:
            a = a[a.client == self.client(mac)]
        return a.outcome.value_counts().to_dict() if len(a) else {}

    def all_text(self) -> str:
        """Every output file as text (frames.csv.gz decompressed) - for privacy checks."""
        parts = []
        for f in self.out.iterdir():
            if f.name.endswith(".gz"):
                parts.append(gzip.open(f, "rt").read())
            elif f.suffix in (".csv", ".json"):
                parts.append(f.read_text())
        return "\n".join(parts).lower()


def run_pipeline(pcap_dir: Path, out: Path) -> Result:
    salt_file = out.parent / f"{out.name}.salt"
    salt_file.write_text(SALT)
    logs = []
    for cmd in ([sys.executable, str(ROOT / "extract.py"), "--pcaps", str(pcap_dir), "--out", str(out),
                 "--salt-file", str(salt_file), "--workers", "2"],
                [sys.executable, str(ROOT / "detect.py"), "--out", str(out)]):
        p = subprocess.run(cmd, capture_output=True, text=True)
        logs.append(p.stdout + p.stderr)
        assert p.returncode == 0, f"{Path(cmd[1]).name} failed:\n{p.stdout}\n{p.stderr}"
    return Result(out, "\n".join(logs))


@pytest.fixture(scope="session", autouse=True)
def _need_tshark():
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed", allow_module_level=True)


@pytest.fixture(scope="session")
def scenario(tmp_path_factory):
    """scenario("deauth_loop") -> (Result, ground_truth). Built and analysed once per session."""
    scenarios = pytest.importorskip("scenarios", reason="scapy needed for synthetic scenarios")
    base = tmp_path_factory.mktemp("scenarios")
    cache = {}

    def get(name):
        if name not in cache:
            truth = scenarios.SCENARIOS[name](base / name / "pcaps")
            cache[name] = (run_pipeline(base / name / "pcaps", base / name / "out"), truth)
        return cache[name]
    return get


@pytest.fixture(scope="session")
def public(tmp_path_factory):
    """public("wpa-Induction") -> Result, downloading the capture on first use."""
    import public_captures as pc
    base = tmp_path_factory.mktemp("public")
    cache = {}

    def get(name):
        if name not in cache:
            if not pc.download([name], quiet=True):
                pytest.skip(f"{name}: could not download (offline?)")
            cache[name] = run_pipeline(pc.path_for(name).parent, base / name)
        return cache[name]
    return get
