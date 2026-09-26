#!/usr/bin/env python3
"""
Airframe - step 1: extract + mask.

Runs tshark on every sensor capture, keeps only 802.11 / 802.1X header fields,
replaces every MAC address and SSID with a salted hash, and writes one
combined table for the rest of the pipeline.

Raw MACs and SSIDs never leave this step. EAP identities are never extracted.

Usage:
    python extract.py --pcaps ./hackaton_airframe --out ./out
    python extract.py --lookup aa:bb:cc:dd:ee:ff   # masked label of a known device
"""
import argparse
import csv
import hashlib
import io
import os
import secrets
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

# (column name, tshark field). Header fields only - nothing above layer 2.
FIELDS = [
    ("ts", "frame.time_epoch"),
    ("channel", "wlan_radio.channel"),
    ("rssi", "wlan_radio.signal_dbm"),
    ("subtype", "wlan.fc.type_subtype"),
    ("retry", "wlan.fc.retry"),
    ("protected", "wlan.fc.protected"),
    ("ta", "wlan.ta"),
    ("ra", "wlan.ra"),
    ("bssid", "wlan.bssid"),
    ("seq", "wlan.seq"),
    ("ssid", "wlan.ssid"),
    ("reason", "wlan.fixed.reason_code"),
    ("status", "wlan.fixed.status_code"),
    ("auth_seq", "wlan.fixed.auth_seq"),
    ("eapol_type", "eapol.type"),
    ("eap_code", "eap.code"),
    ("key_msg", "wlan_rsna_eapol.keydes.msgnr"),
    ("length", "frame.len"),
    # used only to derive the device vendor, then dropped
    ("ta_resolved", "wlan.ta_resolved"),
    ("ra_resolved", "wlan.ra_resolved"),
]
MAC_COLS = ["ta", "ra", "bssid"]
INT_COLS = ["channel", "subtype", "seq", "reason", "status", "auth_seq",
            "eapol_type", "eap_code", "key_msg", "length"]
PCAP_EXT = {".pcap", ".pcapng", ".cap"}


def is_capture(p: Path) -> bool:
    """.pcap / .pcapng / .cap, optionally gzip-compressed (tshark reads .gz directly)."""
    if p.name.startswith(".") or not p.is_file():
        return False
    suffixes = [s.lower() for s in p.suffixes]
    if suffixes and suffixes[-1] == ".gz":
        suffixes = suffixes[:-1]
    return bool(suffixes) and suffixes[-1] in PCAP_EXT


def sensor_name(p: Path) -> str:
    name = p.name
    for ext in (".gz", ".pcapng", ".pcap", ".cap"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
    return name


# ---------------------------------------------------------------- masking
def load_salt(salt_file: Path) -> str:
    """Secret salt so hashes can't be reversed by hashing known MACs.
    Keep the salt file private; the dashboard never needs it."""
    if os.environ.get("AIRFRAME_SALT"):
        return os.environ["AIRFRAME_SALT"]
    if salt_file.exists():
        return salt_file.read_text().strip()
    salt = secrets.token_hex(16)
    salt_file.write_text(salt)
    return salt


def token(value: str, salt: str, n: int = 10) -> str:
    return hashlib.sha256((salt + value).encode()).hexdigest()[:n]


def mask_mac(mac: str, salt: str) -> str:
    if not mac:
        return ""
    mac = mac.lower()
    if mac == "ff:ff:ff:ff:ff:ff":
        return "BROADCAST"
    if int(mac[:2], 16) & 0x01:  # group bit -> multicast
        return "MULTICAST"
    return token(mac, salt)


def decode_ssid(raw: str) -> str:
    """tshark 4.x prints SSIDs as hex, older versions as text."""
    if not raw or raw == "<MISSING>":
        return ""  # wildcard / hidden
    try:
        if len(raw) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in raw):
            return bytes.fromhex(raw).decode("utf-8", errors="replace")
    except ValueError:
        pass
    return raw


def vendor_of(mac: str, resolved: str) -> str:
    if not resolved or resolved.lower() == mac.lower() or "_" not in resolved:
        return ""
    return resolved.split("_")[0]


# ---------------------------------------------------------------- tshark
def run_tshark(path: Path) -> pd.DataFrame:
    cmd = ["tshark", "-N", "m", "-r", str(path), "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]
    for _, field in FIELDS:
        cmd += ["-e", field]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"tshark failed on {path.name}: {proc.stderr[:500]}")
    df = pd.read_csv(io.StringIO(proc.stdout), sep="\t", header=None,
                     names=[c for c, _ in FIELDS], dtype=str,
                     keep_default_na=False, quoting=csv.QUOTE_NONE)
    df.insert(0, "sensor", sensor_name(path))
    return df


def to_int(series: pd.Series) -> pd.Series:
    """Handles '0x0017', '23', '' and multi-value '1,2' (keeps first)."""
    def conv(v):
        if not v:
            return None
        v = v.split(",")[0]
        try:
            return int(v, 0)
        except ValueError:
            try:
                return int(float(v))
            except ValueError:
                return None
    lookup = {v: conv(v) for v in series.unique()}  # few unique values -> fast
    return pd.array(series.map(lookup).tolist(), dtype="Int64")


def parse_ts(series: pd.Series) -> pd.Series:
    """Epoch seconds. Some real captures carry invalid sub-second values, which tshark
    prints as '1177961534.(1000046000 nanosec' - recover those instead of dropping them."""
    ts = pd.to_numeric(series, errors="coerce")
    bad = ts.isna() & series.str.contains("nanosec", na=False)
    if bad.any():
        parts = series[bad].str.extract(r"^(\d+)\.\((\d+) nanosec")
        ts[bad] = parts[0].astype(float) + parts[1].astype(float) / 1e9
    return ts


def to_bool(series: pd.Series) -> pd.Series:
    return series.str.lower().isin(["true", "1"])


# ---------------------------------------------------------------- main
def extract(pcap_dir: Path, out_dir: Path, salt_file: Path, workers: int) -> None:
    if shutil.which("tshark") is None:
        sys.exit("tshark not found - install Wireshark/tshark first.")
    files = sorted(p for p in pcap_dir.iterdir() if is_capture(p))
    if not files:
        sys.exit(f"No capture files found in {pcap_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    salt = load_salt(salt_file)

    print(f"Extracting {len(files)} captures with tshark ({workers} in parallel)...")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        parts = list(pool.map(run_tshark, files))
    df = pd.concat(parts, ignore_index=True)
    print(f"  {len(df):,} frames read")

    # --- address table (vendor + randomized flag), built before masking
    addr_rows = {}
    for col, res in (("ta", "ta_resolved"), ("ra", "ra_resolved"), ("bssid", None)):
        pairs = df[[col] + ([res] if res else [])].drop_duplicates()
        for row in pairs.itertuples(index=False):
            mac = row[0].lower()
            if not mac or mac in addr_rows:
                continue
            masked = mask_mac(mac, salt)
            if masked in ("BROADCAST", "MULTICAST"):
                continue
            addr_rows[mac] = {
                "addr": masked,
                "vendor": vendor_of(mac, row[1]) if res else "",
                "randomized": bool(int(mac[:2], 16) & 0x02),
                # same first 5 octets = likely the same physical AP radio
                "radio": token(mac[:14], salt),
            }
    addresses = pd.DataFrame(addr_rows.values())
    addresses = (addresses.sort_values("vendor", ascending=False)
                 .drop_duplicates("addr"))

    # --- mask identifiers
    for col in MAC_COLS:
        uniq = {m: mask_mac(m, salt) for m in df[col].unique()}
        df[col] = df[col].map(uniq)
    ssid_map = {s: (token("ssid:" + decode_ssid(s), salt, 8) if decode_ssid(s) else "")
                for s in df["ssid"].unique()}
    df["ssid"] = df["ssid"].map(ssid_map)
    df = df.drop(columns=["ta_resolved", "ra_resolved"])

    # --- types
    df["ts"] = parse_ts(df["ts"])
    if df["ts"].isna().any():
        print(f"  dropped {int(df['ts'].isna().sum())} frames with unreadable timestamps")
        df = df[df["ts"].notna()]
    df["rssi"] = pd.to_numeric(df["rssi"].str.split(",").str[0], errors="coerce")
    for col in INT_COLS:
        df[col] = to_int(df[col])
    df["retry"] = to_bool(df["retry"])
    df["protected"] = to_bool(df["protected"])
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)

    sensors = (df.groupby("sensor")
               .agg(frames=("ts", "size"), first_ts=("ts", "min"), last_ts=("ts", "max"),
                    channels=("channel", lambda s: ",".join(str(c) for c in sorted(s.dropna().unique()))))
               .reset_index())

    df.to_csv(out_dir / "frames.csv.gz", index=False, compression="gzip")
    addresses.to_csv(out_dir / "addresses.csv", index=False)
    sensors.to_csv(out_dir / "sensors_raw.csv", index=False)
    print(f"  wrote {out_dir/'frames.csv.gz'}  ({len(sensors)} sensors, "
          f"{len(addresses)} unique devices, all identifiers masked)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcaps", type=Path, help="folder with the sensor captures")
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--salt-file", type=Path, default=Path(".airframe_salt"))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--lookup", help="print the masked label for a known MAC address")
    args = ap.parse_args()

    if args.lookup:
        salt = load_salt(args.salt_file)
        t = mask_mac(args.lookup, salt)
        print(f"{args.lookup} -> token {t}  (client label C-{t[:6]})")
        return
    if not args.pcaps:
        ap.error("--pcaps is required")
    extract(args.pcaps, args.out, args.salt_file, args.workers)


if __name__ == "__main__":
    main()
