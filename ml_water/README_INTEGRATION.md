# SENTINEL water anomaly detector: integration handoff

**What it is.** An advisory early-warning layer for the **water sector only**. The frozen Model C (predictive residual, version `C-1.0.0`) flags hours where tank levels or pressures disagree with what the previous hours and the current pump/valve actuation imply.

**What it is not.** It is not a cyberattack, compromise or outage detector, and it is not validated for any other sector. It writes nothing into the master city files and never populates `vulns.csv` `exploit_prob`.

**Data.** All outputs come from a **historical replay** of BATADAL dataset04, a C-Town benchmark simulation from 2016. This is not live telemetry and not a real installation.

## 1. Setup and commands
```bash
cd ~/Desktop/SENTINEL_DATA/10_ML_WATER_ANOMALY
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # already present; Python 3.14, CPU only
.venv/bin/python -m pytest -q tests                                   # 44 tests
.venv/bin/python -m src.build_integration                             # regenerate integration/ (~75 s, deterministic)
```
- Dependencies (pinned): numpy, pandas, scikit-learn 1.9.1, joblib, threadpoolctl. No GPU, no network.
- **Never re-run** `src.run_final_test`. It is locked (`outputs/FINAL_TEST_DONE.lock`) because the held-out test was evaluated once.

## 2. Files
| File | Use |
|---|---|
| `events/anomaly_events.json` / `.csv` | One record per alert episode (49 in the dataset04 replay), with advisory `risk_engine_evidence` |
| `replay/replay_dataset04_hourly.jsonl` / `.csv` | One record per hour (4,177), chronological: score, threshold, alert, episode, top-3 signals with observed vs predicted |
| `replay/measurements_dataset04.csv` | All 43 observed signals plus Model C predictions (`pred_*`) for historical charts |
| `demo/attack6_historical_replay.json` | Demo scenario: documented BATADAL attack 6 ±12 h (118 hours), with banner and official attack description |
| `signal_asset_mapping.csv` | Signal → hydraulic zone → master-city asset, with explicit `mapping_status` |
| `schemas/*.schema.json` | JSON Schema for the hourly record, event and risk evidence |
| `MODEL_CARD.json` / `provenance.json` | Version, hashes, training and calibration data, validation and test metrics, limitations, input hashes, reproducibility check |

## 3. Live or streaming use (Python)
```python
from src.inference import WaterAnomalyDetector, TemporalOrderError, MissingSignalError
det = WaterAnomalyDetector(data_mode="live", source="my_feed")    # refuses to load if the model hash changed
rec = det.process("2016-12-08 02:00", measurements)               # dict of BATADAL signal -> value, hourly
events = det.episodes()                                           # alert episodes so far
```
- **Strict hourly chronological order.** A duplicate or earlier timestamp raises `TemporalOrderError`. A gap above 1 h resets history (`history_reset_gap_h` is set) and needs 2 more hours before an alert can fire.
- **All 36 informative signals are required.** A missing value or NaN raises `MissingSignalError`; nothing is imputed.
- **Speed:** about 21 ms per observation on CPU.
- **Risk-engine adapter:** `from src.evidence import to_risk_evidence` converts an event into advisory evidence.

## 4. Hourly record (excerpt; demo, attack 6, 2016-12-08 02:00)
```json
{"timestamp": "2016-12-08T02:00:00", "sector": "water", "source_dataset": "BATADAL_dataset04",
 "data_mode": "historical_replay", "detector_name": "predictive_residual_hgb", "model_version": "C-1.0.0",
 "anomaly_score_raw": 112.3513, "alert_threshold": 8.78587, "display_score_0_100": 92.75,
 "log10_score_over_threshold": 1.107, "exceeds_threshold": true, "alert": true,
 "alert_episode_id": "WA-C-1.0.0-20161206T18", "alert_duration_h": 33, "severity": "high",
 "contributing_signals": [{"signal_id": "P_J415", "kind": "junction_pressure", "unit": "m (EPANET SI pressure head)",
   "observed": 64.08, "predicted": 96.981, "residual": -32.901, "abs_z": 112.35, "hydraulic_zone": "zone_T4",
   "mapped_city_asset_ids": [], "mapping_status": "unmapped", "observed_via_city_assets": ["WA02", "WA03"]}, "..."],
 "classification": "advisory_physical_process_anomaly",
 "explanation": "Alert: P_J415 observed 64.08 m ... vs 96.981 predicted ... hydraulic area zone_T4; no master-city asset mapping (C-Town signal only). Advisory physical-process anomaly. Not a confirmed cyberattack, device compromise or service outage; requires investigation."}
```

## 5. Event and risk evidence (excerpt)
```json
{"event_id": "WA-C-1.0.0-20161206T10", "timestamp_start": "2016-12-06T10:00:00", "timestamp_last_alert": "2016-12-06T13:00:00",
 "alert_duration_h": 4, "alert_hours": 2, "anomaly_score_raw_peak": 12.7048, "display_score_peak_0_100": 59.12,
 "severity": "low", "source_signal_ids": ["L_T4", "L_T6", "L_T7", "P_J14", "P_J256"], "hydraulic_zones": ["zone_T4", "..."],
 "mapped_city_asset_ids": [], "mapping_status": "unmapped", "observed_via_city_assets": ["WA02", "WA03"],
 "documented_attack_overlap": 6,
 "reference_note": "overlaps documented BATADAL attack 6 ...; reference for evaluation/demo only, not a detector conclusion",
 "risk_engine_evidence": {"evidence_type": "physical_process_anomaly", "advisory": true, "city_asset_ids": [],
   "telemetry_path_assets": ["WA02", "WA03"], "deviation_severity": "low", "investigation_priority_hint": "review",
   "must_not_be_used_as": ["confirmed_cyberattack", "device_compromise", "service_outage", "exploit_prob"]}}
```
`documented_attack_overlap` comes from the official BATADAL table. It is for demo and evaluation only, and the detector never sees it. Hide it or label it "reference" in the UI.

## 6. Field rules for the frontend and the risk engine
- **Alerts use `anomaly_score_raw > alert_threshold` for 2 consecutive hours.** Display `display_score_0_100` (= 100·r/(1+r), r = raw/threshold; 50 at the threshold) or `log10_score_over_threshold`. Raw scores are heavy-tailed (peaks above 1,000) and stay stored unchanged.
- **`severity`** (`low` ≥ 1×, `medium` ≥ 3×, `high` ≥ 10× threshold) measures statistical deviation, not impact.
- **Show events as episodes** (`alert_episode_id`, `alert_duration_h`), not as a continuous "under attack" state. Coverage inside long attacks is partial.
- **Asset mapping is partial.** Only `L_T1` → **WA04** and `F/S_PU1`, `F/S_PU2` → **WA01** are mapped. These are `design_mapping_illustrative`: the city was modelled on C-Town T1/PU1/PU2. 38 signals are `unmapped`. Only 14 of 49 events touch a mapped asset; most fall in C-Town zone T4. `observed_via_city_assets` (WA02 telecontrol, WA03 HMI) is the illustrative telemetry path. **Render `hydraulic_zone`** so unmapped anomalies remain visible.
- **The anomaly location can be downstream of the attacked component** when sensors are replayed (attack 4 surfaced at the V2/PU9/PU10 pressures). Word it as "unexpected hydraulic behaviour in zone X".
- **Risk engine.** Use `risk_engine_evidence` only to raise investigation priority for the listed assets and telemetry path, and to correlate with their vulnerabilities and attack paths. Do **not** change CVSS, EPSS or KEV, do not write `exploit_prob`, and do not mark assets compromised or services down.

## 7. Performance (frozen settings; full detail in `MODEL_CARD.json`)
- **Validation, attacks 1–3:** 3/3 detected at 1 / 0 / 20 h; 1.37 false alarms per 7 days; PR-AUC 0.743.
- **Held-out test, attacks 4–7 (evaluated once):** 4/4 detected at 2 / 1 / 3 / 0 h (attack 7 is 6 h if both persistence hours must fall inside the window); 1.37 false alarms per 7 days strict; precision 0.95, recall 0.68, PR-AUC 0.868.
- **Scope:** one simulated network and 7 attacks. This is not evidence for real utilities or other sectors.
