"""
Public 802.11 captures with known content, from the Wireshark and aircrack-ng test suites
on GitHub. Used as real-world regression tests: different link types (radiotap, plain 802.11,
Prism), security modes (WEP, WPA2-PSK, PMF, WPA3-SAE, OWE, 802.1X/EAP-TLS, Suite-B) and quirks.

Run `python tests/public_captures.py` to download them into tests/data/public/.
"""
import sys
import urllib.request
from pathlib import Path

WS = "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/"
AC = "https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/test/"
DATA = Path(__file__).parent / "data" / "public"

# name -> (url, what is in it, expectations checked by test_public.py)
#   connected:       at least this many attempts must be classified "connected"
#   outcomes:        exact outcome counts
#   no_categories:   finding categories that must NOT appear (false-positive guards)
#   has_category:    a finding category that MUST appear
#   frames:          exact frame count after extraction (nothing silently dropped)
CAPTURES = {
    "wpa-Induction": (WS + "wpa-Induction.pcap.gz",
                      "WPA2-PSK join with full 4-way handshake, then traffic (radiotap)",
                      dict(connected=1, no_categories=["4-way handshake failure", "Join failure",
                                                       "Deauth / disassoc loop", "Congestion / channel health"])),
    "wpa-eap-tls": (WS + "wpa-eap-tls.pcap.gz",
                    "WPA2-Enterprise EAP-TLS: EAP-Success, 4-way handshake, rekey; no beacons captured",
                    dict(connected=1, no_categories=["802.1X / EAP failure", "Congestion / channel health",
                                                     "AP silent / beacon loss"])),
    "wpa-test-decode": (WS + "wpa-test-decode.pcap.gz",
                        "Only M1+M2 captured, then encrypted traffic: sensor missed M3/M4",
                        dict(connected=1, no_categories=["4-way handshake failure"])),
    "wpa2-psk-mfp": (WS + "wpa2-psk-mfp.pcapng.gz", "WPA2-PSK with protected management frames",
                     dict(connected=1, no_categories=["Join failure", "4-way handshake failure"])),
    "wpa3-sae": (WS + "wpa3-sae.pcapng.gz", "WPA3-SAE join (auth commit/confirm)",
                 dict(connected=1, no_categories=["Join failure", "4-way handshake failure"])),
    "wpa3-suiteb-192": (WS + "wpa3-suiteb-192.pcapng.gz",
                        "802.1X Suite-B: 3 joins, each ended by the client itself",
                        dict(outcomes={"connected": 2, "client_left": 1},
                             no_categories=["Join failure", "802.1X / EAP failure", "Deauth / disassoc loop"])),
    "owe": (WS + "owe.pcapng.gz", "Opportunistic Wireless Encryption join, 11 s capture",
            dict(connected=1, no_categories=["Congestion / channel health"])),
    "wep": (WS + "wep.pcapng.gz", "WEP join with sparse beacons",
            dict(connected=1, no_categories=["Congestion / channel health", "AP silent / beacon loss"])),
    "wpa2-psk-linksys": (AC + "wpa2-psk-linksys.cap",
                         "Client kicked by 3 spoofed deauths, rejoins 3x; one assoc refused (status 10)",
                         dict(outcomes={"connected": 3, "assoc_rejected": 1},
                              no_categories=["Deauth / disassoc loop"])),
    "wpa-psk-linksys": (AC + "wpa-psk-linksys.cap", "3 deauths then one successful WPA join",
                        dict(connected=1, no_categories=["Deauth / disassoc loop"])),
    "wep_64_ptw": (AC + "wep_64_ptw.cap",
                   "WEP cracking session: disassoc flood; 6 frames carry invalid timestamps",
                   dict(has_category="Deauth / disassoc loop", frames=65282)),
    "test-pmkid": (AC + "test-pmkid.pcap", "Single M1 (PMKID) and the capture ends",
                   dict(outcomes={"in_progress": 1}, no_categories=["4-way handshake failure"])),
    "n-02": (AC + "n-02.cap", "Assoc 'try again later' (status 30, PMF SA Query) then success",
             dict(outcomes={"assoc_comeback": 1, "connected": 1}, no_categories=["Join failure"])),
    "wpa": (AC + "wpa.cap", "Prism link-layer header (not radiotap)", dict(connected=1)),
    "wpa2.eapol": (AC + "wpa2.eapol.cap", "Bare 4-way handshake, no radio header", dict(connected=1)),
    "Chinese-SSID-Name": (AC + "Chinese-SSID-Name.pcap", "One beacon with a UTF-8 SSID", dict()),
}


def path_for(name: str) -> Path:
    url = CAPTURES[name][0]
    return DATA / name / url.rsplit("/", 1)[1]


def download(names=None, quiet=False) -> list:
    got = []
    for name in names or CAPTURES:
        target = path_for(name)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                urllib.request.urlretrieve(CAPTURES[name][0], target)
            except Exception as e:  # offline, moved file, ...
                if not quiet:
                    print(f"  could not download {name}: {e}")
                target.unlink(missing_ok=True)
                continue
        got.append(name)
        if not quiet:
            print(f"  {name:20} {target.stat().st_size:>9,} bytes  {CAPTURES[name][1]}")
    return got


if __name__ == "__main__":
    print(f"Downloading into {DATA}")
    ok = download()
    print(f"{len(ok)}/{len(CAPTURES)} captures available")
    sys.exit(0 if ok else 1)
