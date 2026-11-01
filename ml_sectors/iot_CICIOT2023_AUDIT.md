# CICIoT2023 (Parquet) audit: NO-GO under the existing IoT protocol (nothing trained, nothing scored)

**Audit date:** 2026-11-01. The files were read only.
- **Script:** `src/ciciot_audit.py`.
- **Full numbers:** `reports_ciciot2023/ciciot2023_audit.json`.
- **TON_IoT records unchanged:** the TON_IoT audit (`DATA_AUDIT.md`), `EVALUATION_PROTOCOL.md` and `reference/source_inventory.json` were not modified.

**What the data is:** CICIoT2023 comes from the Canadian Institute for Cybersecurity's lab IoT testbed (2023). It is benchmark traffic, not Cascade device traffic.

## 1. Files
| File | SHA-256 | Rows | Normal / attack |
|---|---|---|---|
| `train-00000-of-00001.parquet` | `4a9c585c…9cc1d` | 1,073,851 | 159,990 / 913,861 |
| `validation-00000-of-00001.parquet` | `28177d73…9146e` | 134,232 | 19,999 / 114,233 |
| `test-00000-of-00001.parquet` | `dbbaa3a7…58ac2` | 268,463 | 39,998 / 228,465 |
| `test-00000-of-00001-2.parquet` | `5296fb16…42292` | 134,231 | 19,999 / 114,232 |

- **Schema:** identical in all four: 39 numeric features, `Label` (32 fine classes), `attack_class` (8 groups) and binary `label`. There are no missing or non-finite values, and `label`, `Label` and `attack_class` are mutually consistent.
- **A curated derivative, not the original release:**
  - 32 of the original 34 classes, capped at about 40,000 rows each (Benign about 160,000).
  - 7 of the 46 original features are absent: `flow_duration`, `Srate`, `Drate`, `Magnitue`, `Radius`, `Covariance`, `Weight`.
  - `Duration` has been renamed `Time_To_Live`.
- **Features are on their raw scale,** so there is no global-scaling leak.

## 2. The two "test" files
- **They are not distinct test data and not duplicate downloads.**
- **`test-00000-of-00001.parquet` is exactly the row multiset union** of `validation` and `test-00000-of-00001-2.parquet`: 134,232 + 134,231 = 268,463, with every full row (features + labels) matched, in shuffled order.
- **So `test-…-2` is the half of `test` that excludes the validation rows.** The coherent split is train / validation / `test-…-2`.
- **`test-00000-of-00001.parquet` must never be used for final scoring:** 50% of it is the validation set.
- **The files must not be combined.** Combining them would double-count 134,231 rows.

## 3. Duplicates, overlap and label conflicts
- **Exact duplicate feature vectors within a split:** train 9.7%, validation 3.0%, `test-…-2` 3.2%. In train, these are concentrated in DDoS (25.6%) and DoS (24.1%).
- **Overlap with train:** 13.0% of validation rows and 12.9% of `test-…-2` rows have a feature vector that also occurs in train: DDoS 25%, DoS 24%, Spoofing 5%, Benign 0.5%.
- **Overlap between validation and test-2:** 7,340 `test-…-2` rows have a vector present in validation, and 4,275 full rows are identical.
- **Label conflicts:**
  - 17,296 train vectors carry more than one fine `Label`, mostly among DDoS/DoS sub-types that look identical.
  - Only 195 vectors (2,602 rows) carry conflicting binary labels.

## 4. Leakage and confounds
| Finding | Evidence | Consequence |
|---|---|---|
| **Window-size extraction artefact (`Number`)** | `Number` = 10 for **100%** of Benign, BruteForce, Recon, Spoofing and Web-based rows, and = 100 for **99.4–99.8%** of DDoS, DoS and Mirai rows. The rule "Number = 100" flags 70% of all attack rows with **zero** benign false positives. | This is a capture-processing setting (packet-window size chosen per attack capture), not attack behaviour. Window-dependent aggregates (`Tot sum`, `Std`/`Variance`, the flag counts 0–100, `Rate`, `IAT`) inherit it. `Number` + `IAT` + `Tot sum` in a depth-4 tree give binary AUC 0.891. |
| **No session, capture, flow, IP, port or time fields** | None present | **The split by session or day required by `EVALUATION_PROTOCOL.md` §2 is impossible,** and the session-confound check (§5.3) can't be run. |
| **The provided splits are random row splits of the same captures** | The class mix is identical across splits; nearest-neighbour label agreement on unique train vectors is 0.874 (binary) and 0.666 (32-class) | Validation and test measure **in-distribution** performance on the same lab captures. They don't measure generalisation to new captures, devices or networks. |
| Single features | Highest binary AUC: `HTTPS` 0.867, `Number` 0.851, `ack_flag_number` 0.842, `IAT` 0.803 | No single perfect feature, but the artefact above is effectively a shortcut for flood attacks. |
| `IAT` | A 32-class lookup on rounded IAT gives only 17.7% accuracy | Not the strong timestamp leak known from the original release; still window-dependent. |

## 5. Decision
**NO-GO under the existing IoT GO/NO-GO rules. No model was trained and no split was scored.**
- **The protocol fixed in advance requires session- or day-grouped splits and a session-confound check.** This derivative provides neither session metadata nor any way to group captures.
- **Its random splits share captures across train, validation and test.**
- **One feature (`Number`) exposes the capture's processing configuration** and, by itself, identifies most attacks.
- **Any score would be an in-distribution benchmark figure** inflated by these artefacts. It wouldn't be a meaningful independent evaluation.

## 6. Options (each needs your decision)
1. **Original CICIoT2023 with capture provenance** (per-attack pcap or CSV source files), so splits can be grouped by capture and window size can be controlled or re-extracted uniformly. Then re-audit under the existing protocol.
2. **TON_IoT network dataset** (`Train_Test_Network.csv`), as recommended in the TON_IoT audit. It has timestamps, IPs and ports, which allow time- and host-grouped splits after the identifiers are dropped as features.
3. **Explicitly authorised experimental benchmark demonstration on this derivative** (like telecom's): train / validation / `test-…-2` only, with `Number` and window-dependent artefacts reported separately or excluded. It would carry the label "random-split in-distribution benchmark, not an independent evaluation", and the IoT gates would still be reported as unmet.
