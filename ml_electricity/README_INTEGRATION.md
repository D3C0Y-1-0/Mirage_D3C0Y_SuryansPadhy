# SENTINEL electricity attack-screening: integration handoff

**What it is.** An advisory **screening** classifier for the electricity sector. It was trained on the MSU–ORNL Power System Attack Dataset (three-class release) and sorts one measurement sample into *normal operation / natural disturbance / cyberattack*.

> ⚠️ **About 40% coverage.** On held-out benchmark data the model flagged **39.6%** of attack observations. **No flag never means safe.** A flag is evidence to investigate, not proof of an attack, compromise or outage.

The data is **benchmark samples, not SENTINEL telemetry**: 1% random snapshots of a two-line, four-IED test system, with **no timestamps**. Present it as a *sample explorer*, never as a live feed or a time replay.

## Frozen model (do not retrain)
| Item | Value |
|---|---|
| Model | `models/frozen/model.joblib`: RandomForest (100 trees, min_samples_leaf 5), read-only, SHA-256 `59151fb4…82dff7` |
| Features | `models/frozen/features.json`: 89 load-invariant features from 80 raw columns (`src/invariant.py`) |
| Rule | **cyberattack** if P(cyberattack) ≥ **0.655311**, otherwise the larger of normal / natural |
| Held-out (data13–15, evaluated once) | attack precision **0.946**, recall **0.396**; natural→attack **7.2%**; normal→attack **0%**; normal recall 0.940; macro-F1 0.578 |

## Setup and commands
```bash
cd ~/Desktop/SENTINEL_DATA/11_ML_ELECTRICITY
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt     # already present; Python 3.14, CPU only
.venv/bin/python -m pytest -q tests                                     # 43 tests
.venv/bin/python -m src.build_integration                               # regenerate integration/ (~3 s, deterministic)
```
**Never** run `src.run_final_test` again (it is locked), `src.freeze`, or any training script.

## Files ready for the frontend (static, no Python needed)
| File | Use in Cascade |
|---|---|
| `integration/explorer/explorer_summary.json` | Explorer landing view: 15 label blocks (3 files × 5) with flag rate, mean P(cyberattack) and prediction mix |
| `integration/explorer/electricity_samples_validation.csv` | Sample table (16,044 rows: file, row, block, benchmark label, prediction, 3 probabilities, flag, outcome, top-3 evidence) |
| `integration/demo/electricity_demo_samples.json` | 45 full records (≤ 3 per file × outcome: attack_flagged, attack_missed, false_attack_flag, correct, non_attack_confusion) for the demo page |
| `integration/MODEL_CARD.json` | Performance, held-out confusion matrix, false-alarm figures, source attribution, limitations, warning |
| `integration/mapping/illustrative_asset_mapping.json` | Optional link to SENTINEL assets (all *illustrative* or *unresolved*) |
| `integration/schemas/*.schema.json` | JSON Schema for a sample record and an explorer block |
| `integration/examples/api_examples.json` | Example responses for the proposed API routes, including a missed-attack example and a 422 error |
| `integration/provenance.json` | Hashes of the frozen model, manifest, inputs, code and every output; confirms the held-out data was not re-scored |

## Live inference (Python, for a future FastAPI route)
```python
import sys; sys.path.insert(0, "<path>/11_ML_ELECTRICITY")
from src.elec_inference import ElectricityScreeningModel, InputSchemaError
model = ElectricityScreeningModel()          # verifies model, features and feature-code hashes; refuses tampered files
records = model.screen(df_or_row_dict, source_file="data10.csv", row_in_file=17)   # list of records
```
- **Input:** the MSU–ORNL column names. 80 are required (listed in `features.json`); extra columns and column order don't matter.
- **Rejected with `InputSchemaError`:** missing columns, NaN or non-numeric values, and ±inf anywhere except apparent impedance `R#-PA:Z` (+inf there is real data).
- **Speed:** about 30 ms per sample with explanation; batch about 0.1 ms per row.
- **Suggested routes** (not implemented; the backend was not modified):
  - `POST /api/electricity/screen`: wrap `model.screen()` and return 422 on `InputSchemaError`.
  - `GET /api/electricity/explorer` and `GET /api/electricity/model_card`: serve the static JSON.

## Record fields (excerpt; full schema in `schemas/`)
```json
{"sample_ref": {"dataset": "MSU-ORNL ...", "source_file": "data10.csv", "row_in_file": 2000, "label_block": 2},
 "data_mode": "benchmark_sample", "sector": "electricity",
 "predicted_class": "cyberattack", "probabilities": {"normal_operation": 0.0, "natural_disturbance": 0.0, "cyberattack": 1.0},
 "attack_screening_flag": true, "attack_threshold": 0.655311, "benchmark_label": "cyberattack",
 "evidence": [{"feature": "R3_VA_over_Vpos", "description": "R3 phase A voltage relative to positive sequence",
               "value": 1.0015, "influence_on_attack_probability": 0.0806, "direction": "toward_attack", "benchmark_device": "R3"}],
 "attack_probability_baseline": 0.30, "explanation": "Attack-screening flag raised: ...",
 "explanation_note": "Feature influence = this model's additive contribution to P(cyberattack) ...",
 "warning": "Advisory screening only ... a missing flag never means the grid is safe ...",
 "model_version": "electricity-rf-compact-59151fb44e49", "classification": "advisory_screening"}
```
- **`evidence`** shows the model's own **tree-path contributions** to P(cyberattack). They sum exactly to the prediction with the baseline, and tests check this. Label them "what drove this score", **not** "what caused the event".
- **`benchmark_label`** is the dataset's official label. Use it only for the explorer and demo outcome badges; it isn't available for live data.
- **`label_block`** is a contiguous same-label run inside a source file. It is **not** a scenario number and **not** time.

## UI rules
1. Show the ⚠️ coverage warning wherever results appear. Never show "no attack", "safe" or a green all-clear when there's no flag.
2. A flag reads "likely cyber-physical attack signature: investigate". Don't say "attack detected" or "compromised".
3. Show probabilities, and the top influences with their direction. Note that influences aren't causes.
4. Treat benchmark devices R1–R4 as **illustrative** stand-ins for SENTINEL **EL06** (Substation Protection IEDs). Relay and control logs relate to **EL05** (RTU) / **EL04** (SCADA). Snort, generators and lines have no SENTINEL counterpart. Never show benchmark samples as measurements from EL05 or EL06.
5. Don't feed model output into CVSS, EPSS, KEV or `exploit_prob`. In the risk engine, use only to raise *investigation priority* for EL04–EL06.

## Manual integration steps (not done in this session)
1. Copy (or serve) `integration/` into the website's static data area, or add read-only API routes.
2. Build an "Electricity screening" page: explorer blocks → sample table → record detail (probabilities, evidence, warning, model card link).
3. If live scoring is wanted, add `POST /api/electricity/screen` in the backend. It needs `src/`, `models/frozen/` and this `.venv`'s pinned packages (numpy, pandas, scikit-learn 1.9.1, scipy, joblib).
4. Optionally link the screening view to EL04–EL06 in the twin, using the illustrative mapping with its disclaimer.
