# Airframe: final bundle

Header‑only Wi‑Fi fault finding for the Airframe hackathon challenge. Start with `PROJECT_SUMMARY.md` (also in `docs/` as a PDF).

**What it found in the challenge captures:** all 63 clients on the 802.1X network failed at the login step on every AP and channel. The APs never got an answer from the authentication path, so this is not a Wi‑Fi fault. Critical alert 5 s after the first failure, replayed from the captures. From 14:30:53, APs repeatedly disconnected 18 devices of one vendor. The retry spike at 14:27 is a traffic-mix effect, not the radio.

## What is where

| Path | What it is |
|---|---|
| `PROJECT_SUMMARY.md` | Challenge, findings, both pipelines, review, testing, use case, savings, scale design |
| `docs/Airframe_Project_Summary.pdf` | The summary as a PDF |
| `docs/Airframe_Dashboard.pdf` | The dashboard (all four tabs) as a PDF |
| `dashboard/airframe-dashboard.html` | Interactive dashboard: incident board, use case, savings calculator, method. Opens in any browser |
| `pipeline_fast/` | Recommended demo engine: stdlib‑only parser, findings, alerts and HTML dashboard. It passes the same 16 scenarios and 16 public captures as the Wireshark‑based pipeline (`CHANGES.md`, `tests/check_fast.py`) |
| `pipeline_tshark/` | Wireshark‑based pipeline, Streamlit dashboard and the 56‑test suite (`README.md`) |
| `original_uploads/` | The three uploaded scripts, unmodified |
| `CROSSCHECK_REPORT.md` | What was re-checked in v2, the new sample cases, issues found and fixes made |
| `PITCH_SCRIPT.md` | 5-minute pitch: slide plan, spoken script, sourced numbers, Q&A (also `docs/Airframe_Pitch_Script.pdf`) |
| `sample_cases/` | 11 new ground-truth cases (24 checks) run on both engines: `python3 sample_cases/run_sample_cases.py` (checks only the fast engine if tshark isn't installed) |
| `results/` | Masked outputs from the challenge data: reports, alerts, findings, the fast pipeline's dashboard, both test logs |

## Quick start

```bash
# Fast pipeline (Python 3.9+, no dependencies), ~5 s for the 8 captures on one core, faster on more
cd pipeline_fast
python3 airframe_analyze.py /path/to/captures --out results          # report.txt, findings.csv, CSVs, dashboard.html
python3 airframe_alert.py results                                     # alerts.md, alerts.json (nothing is sent)
python3 tests/check_fast.py                                           # 48 checks, ~30 s (scapy for the scenarios)

# Wireshark-based pipeline (needs tshark), ~2.5 min
cd pipeline_tshark
pip install -r requirements.txt
python extract.py --pcaps /path/to/captures --out out
python detect.py --out out
streamlit run dashboard.py

# Tests (~1 min; downloads 16 public captures on first run)
pip install -r requirements-dev.txt
python -m pytest tests -v
```

Both pipelines use a secret salt file (`.airframe_salt`, created on first use) to mask MAC addresses and SSIDs. Both mask by default; the fast pipeline's `--no-mask` keeps raw identifiers for internal debugging, and its report and dashboard then say so. Keep the salt private and out of any shared copy.

## AI Declaration
- **Code Generation:** AI (Claude) helped write the fast pipeline component . The rest of the product was entirely built by the team.
- **Team Ownership:** The team set the direction, chose the approach, reviewed and ran everything, and checked the findings against the captures. All numbers in the pitch come from running the code on the challenge data.
- **Data Privacy & Confidentiality:** To ensure confidentiality, all test data used during AI interactions was strictly synthetic . The actual challenge captures are not included in this repository, and all outputs have been appropriately masked.
- **Execution Security:** All synthetic data and AI processes were run securely within a local system sandbox to guarantee data isolation and privacy.
  
## Not included

- **The sensor captures:** they may not leave the approved environment.
- **The downloaded public test captures:** the tests fetch them again.
- **The uploaded `real_report.txt`:** it contains raw MAC addresses. `results/fast_pipeline_report.txt` is the same report, with every number identical, with identifiers masked.
- **Salt files** (`.airframe_salt`): the key to the masking. Keep them private; `.gitignore` excludes them.
