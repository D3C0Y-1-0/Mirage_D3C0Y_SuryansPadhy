# Transportation ML: handoff status (CLOSED, NO-GO)

**Closed:** 2026-11-01

**Decision:** **No transportation ML model is approved for website integration.**

## Summary
| Item | Status |
|---|---|
| Synthetic simulator v1 | Built. Checkpoint 2 **NO-GO**: LR ROC-AUC 0.533; cycle-length whitelist shortcut (precision 1.0); too few attack-free runs. Preserved in `archive/v1/` (hash-verified) and in place. |
| Synthetic simulator v2 | **Completed and passed its integrity tests:** 21/21 simulator tests and all 8 pre-declared Stage A audit gates (no single-feature, whitelist or small-combination shortcut; negative controls within the null). |
| ML candidates (v2) | LR baseline, Random Forest and HistGradientBoosting **all failed** the pre-declared validation gates: harmful-event coverage < 0.80, false alarms during natural detector faults > 5%, worst-run FPR > 3%. Best: HGB, ROC-AUC 0.745 and harmful coverage 0.70. |
| Final held-out test | **Never evaluated.** The v2 test split was never opened, parsed or scored: hash unchanged, no lock file, no frozen model. The v1 test split was also never scored, and is superseded. |
| Integration package | **None created.** There is no `integration/` directory. |

## Guidance for Cascade
- The transportation sector should continue to use Cascade's existing **vulnerability intelligence, infrastructure dependencies and attack simulation**, with no dedicated ML detector.
- **Allowed wording:** "A synthetic traffic-control security testbed was built; detectors evaluated on it did not meet operational false-alarm and coverage criteria."
- **Do not claim:** a working transportation attack detector, any test performance, or any real-world traffic-controller validation.

## Records (preserved unchanged)
- **v1:**
  - `SIMULATOR.md`, `EVALUATION_PROTOCOL.md`
  - `reports/checkpoint1_report.md`, `reports/checkpoint2_report.md`, `reports/checkpoint2_results.json`, `reports/checkpoint2_diagnostics.json`
  - `archive/v1/ARCHIVE_MANIFEST.json`
- **v2:**
  - `v2/SIMULATOR_V2.md`, `v2/EVALUATION_PROTOCOL_V2.md`
  - `v2/reports/stageA_audit.json`, `v2/reports/stageB_results.json`, `v2/reports/stageC_results.json`, `v2/reports/v2_final_report.md`
  - `v2/STATUS.json`

**Possible future work (needs a new simulator version and protocol):** detector-health cross-checks, authenticated preemption logs and command-source metadata.
