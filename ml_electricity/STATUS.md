# 11_ML_ELECTRICITY status

| Checkpoint | Status | Output |
|---|---|---|
| 1 Dataset audit | PASS (binary `raw/`); triple release verified | `ELECTRICITY_DATA_AUDIT.md`, `reports/triple_verification.md`, `reference/input_hashes*.json` |
| 2+3 on binary `raw/` | Gate FAILED (kept for record) | `reports/checkpoint2_report.md`, `reports/checkpoint3_report.md` |
| **2+3 on three-class `triple/`** | **Gate PASSED, verified after the threshold fix** | `reports/triple_checkpoint3_report.md`, `reports/triple_cp23_results.json` (pre-fix copy kept) |
| Compact comparison + FREEZE | DONE: compact RF (100 trees, leaf 5) passed the gate and comparability; frozen 2026-11-01 | `models/frozen/`, `reports/compact_comparison.json`, `reports/frozen_model_handoff.md` |
| 4 Frozen final evaluation | DONE once 2026-11-01 00:09 (locked) | `reports/checkpoint4_report.md`, `reports/checkpoint4_final_test.json`, `outputs/FINAL_TEST_DONE.lock` |
| 5 Integration package | DONE 2026-11-01 | `integration/` (see `integration/README_INTEGRATION.md`), `src/elec_inference.py`, `src/build_integration.py` |

FROZEN: Random Forest (100 trees, min_samples_leaf 5) on 89 load-invariant features, τ = 0.655311, 46.9 MB, SHA-256 59151fb4…82dff7. Validation: attack precision 0.928, attack recall 0.381, natural→attack 8.79%, normal recall 0.937, macro-F1 0.576.
HELD-OUT (data13–15): attack precision 0.946, attack recall 0.396, natural→attack 7.17%, normal→attack 0%, normal recall 0.940, macro-F1 0.578.
Tests: 43/43 pass (`.venv/bin/python -m pytest -q tests`).
