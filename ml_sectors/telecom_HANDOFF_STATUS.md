# Telecom ML: handoff status (CLOSED, NO-GO at Checkpoint 3)

**Closed:** 2026-11-01

**Decision:** **No telecom ML model is approved for website integration.**

**About the dataset:** UNSW-NB15 is a **research network-intrusion benchmark** (UNSW Canberra Cyber Range, 2015, synthetic IXIA traffic). It is **not** telecom-operator, mobile-core or 5G telemetry, and not traffic from Cascade's telecom assets.

| Checkpoint | Result |
|---|---|
| 1. Data audit | **Conditional GO.** `id` is an ordering leak (excluded). 42% of train rows are duplicates (grouped validation). 10.4% of test rows are identical to train vectors. The TTL testbed artefact is excluded. 940 rows have conflicting labels. |
| 2. LR baseline | Recorded: validation recall 0.70 at 1.2% FPR; fails V2, V4, V5, V6 |
| 3. RF / HGB comparison | **NO-GO.** Best (HGB): ROC-AUC 0.993, FPR 1.03%, precision 0.995, but recall 0.882 < 0.90, unique-vector recall 0.745 < 0.85, Fuzzers recall 0.36 < 0.50 |
| 4. Frozen held-out test | **Not run.** The official testing file was never parsed or scored (byte hash unchanged) |
| 5. Integration package | **Not created** |

## Guidance for Cascade
- Telecom should continue to use Cascade's existing **vulnerability intelligence, infrastructure dependencies and attack simulation**, with no ML detector.
- **Allowed wording:** "Flow classifiers evaluated on the UNSW-NB15 research benchmark did not meet pre-declared detection criteria once testbed artefacts and duplicate records were controlled for."
- **Do not claim:** a telecom intrusion detector, any held-out test performance, or any operator or 5G validation.

## Files (preserved; reports are read-only)
- `DATA_AUDIT.md`, `reports/cp1_audit.json`, `src/audit.py`
- `config/protocol.json`, `reports/protocol_declaration.json`
- `src/common.py`, `src/run_models.py`, `reports/cp2_results.json`, `reports/cp3_results.json`, `reports/checkpoint2_3_report.md`
- `models/` (unfrozen LR, RF and HGB plus caches; **not approved for use**)
- `tests/test_telecom.py` (11 pass), `requirements.txt`
- `raw/` (unmodified)
