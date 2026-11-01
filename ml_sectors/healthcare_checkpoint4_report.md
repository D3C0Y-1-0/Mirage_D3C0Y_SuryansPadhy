# Checkpoint 4: held-out evaluation of the frozen Data Alteration advisory detector. FAIL → NO-GO

- **Frozen** 2026-11-01 01:16:57, **before** any held-out access.
  - Location: `models/frozen/` (read-only).
  - Model: Clip → RandomForest, network + biometric features, SHA-256 `a38e6c6f…a9ccc`.
  - Decision: τ = 0.01636, rule n = 1, k = 1.
  - The manifest records hashes of the config, code, raw data and feature order.
- **Evaluated once:** 01:17:22. `reports/FINAL_TEST_DONE.lock` holds the report hash, and a re-run is refused (tested).
- **Unchanged afterwards:** no retraining, no threshold change, no reselection.
- **The broad detector's NO-GO** (`reports/checkpoint3_report.md`) is unchanged; a test hash-verifies it.

## Held-out block (rows 13,054–16,317): 2,859 normal, 175 Data Alteration in 7 bursts, 230 Spoofing (out of scope)
| Criterion (declared before the test) | Result | Pass |
|---|---|---|
| Normal false-positive rate ≤ 1% | **7.07%** (202 / 2,859) | ✗ |
| Data Alteration recall ≥ 90% | **100%** (175 / 175) | ✓ |
| All 7 bursts detected | **7/7**, each from its first row | ✓ |
| Data Alteration precision ≥ 80% | **46.4%** | ✗ |

**Confusion** (normal vs Data Alteration): TN 2,657, FP 202, FN 0, TP 175. F1 0.634.

**Per burst:**

| Burst (run) | Rows | First alert | Row recall |
|---|---|---|---|
| 150 | 24 | row 0 | 1.00 |
| 152 | 28 | row 0 | 1.00 |
| 154 | 18 | row 0 | 1.00 |
| 156 | 31 | row 0 | 1.00 |
| 158 | 27 | row 0 | 1.00 |
| 164 | 22 | row 0 | 1.00 |
| 166 | 25 | row 0 | 1.00 |

**False alarms by 500-row window:** 1.2%, 2.2%, 9.2%, 8.2%, 7.2%, **13.3%**, 8.5%. They come in sustained runs (for example rows 14,317–14,337, 15,648–15,677, 15,812–15,833) rather than isolated rows.

Spoofing rows alerted: 2.2% (out of scope).

## Why it failed: distribution shift in normal network latency
| Block | Slow normal flows (Dur > 0.05 s) | Slow-normal alert rate | Normal FPR |
|---|---|---|---|
| Train | 3.2% | n/a | n/a |
| Validation | 7.9% | 7.4% | 0.69% |
| **Held-out** | **11.3%** (322 rows) | **60.6%** | **7.07%** |

- **The attack signature is stable.** Data Alteration medians are almost identical across blocks: `Dur` about 0.148 s, `SIntPkt` about 48–49 ms, `DstJitter` about 47–48. The lowest Data Alteration score on held-out was 0.90.
- **Typical normal traffic is stable too** (`Dur` 0.012 s, `Rate` about 485). Vital-sign medians match validation.
- **What changed:** the held-out period has more, and more sustained, latency episodes on the normal link. The model treats them as man-in-the-middle delay.
- **This was flagged in advance.** The experiment report noted thin headroom under the 1% cap and unstable slow-flow false alarms across folds. Validation did not contain enough of these episodes to expose the problem.

## Network-only model (reported separately, not evaluated here)
The network-only Random Forest **failed the declared validation gate**:
- G1: normal FPR 1.23% > 1%
- G5: slow-normal FPR 13.5% > 10%

It was not frozen and **was not run on the held-out block**. Doing so after seeing these results would be model reselection on test data.

## Decision
**NO-GO** for integrating this model as a Data Alteration advisory detector.
- It finds every Data Alteration burst, but would raise a false alarm on about **1 in 14 normal flows** during latency-heavy periods.
- **More than half of its alerts would be false.** That is not acceptable for a monitoring module, even as an advisory.

**Recommendation:** keep healthcare on SENTINEL's existing vulnerability-intelligence and attack-graph engine **without dedicated ML**. Record WUSTL-EHMS-2020 as a documented negative result:
- the man-in-the-middle delay signature is real and consistently present
- but on this single recording it can't be separated from normal latency episodes at a usable false-alarm rate
- Spoofing isn't detectable without the attacker MAC

A credible healthcare detector would need data with many recording sessions and explicitly labelled normal congestion or latency conditions.
