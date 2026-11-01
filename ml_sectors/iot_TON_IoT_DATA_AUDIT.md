# IoT data audit (Checkpoint 1): TON_IoT telemetry, Train_Test subset

**Audit date:** 2026-11-01. The files were read only and **nothing was trained.** The inventory with hashes is in `reference/source_inventory.json`.

## 1. What is in `raw/`
| File | Rows | Columns | Size |
|---|---|---|---|
| `Train_Test_IoT_GPS_Tracker.csv` | 38,960 | date, time, latitude, longitude, label, type | 2.1 MB |
| `Train_Test_IoT_Modbus.csv` | 31,106 | date, time, FC1_Read_Input_Register, FC2_Read_Discrete_Value, FC3_Read_Holding_Register, FC4_Read_Coil, label, type | 1.7 MB |
| `Train_Test_IoT_Weather.csv` | 39,260 | date, time, temperature, pressure, humidity, label, type | 2.6 MB |

- **Source (verified online):** TON_IoT, UNSW Canberra Cyber Range and IoT Labs (Alsaedi, Moustafa, Tari, Mahmood, Anwar), *IEEE Access* 2020. These are 3 of the 7 device files in the official `Train_Test_datasets` folder. Fridge, Garage Door, Motion Light and Thermostat are not present.
- **All three files come from one testbed and one timeline.** Attack sessions start at the same minute on all three devices (for example, injection 2019-04-25 07:49 and scanning 2019-04-23 20:20).
- **Signal type:** IoT/IIoT **device telemetry**: sensor readings and Modbus register values logged by the services. It is **not** network-flow or packet data, and not OS logs.
- **Format quirks:** UTF-8 with a byte-order mark; some `time` values are padded with spaces. All values parse; there are no missing values and no infinite values.

## 2. Labels
- `label`: 0 = normal, 1 = attack. `type`: normal or the attack sub-class. `label` and `type` agree perfectly in all files.
- **Class counts:**
  - Modbus: normal 15,000; injection, backdoor and password 5,000 each; xss 577; scanning 529.
  - GPS: normal 15,000; ddos, backdoor, injection and password 5,000 each; ransomware 2,833; xss 577; scanning 550.
  - Weather: as GPS, with ransomware 2,865 and xss 866.
- **What a label means.** Each attack *type* occupies one contiguous time window (one session), so `label = 1` means **"recorded during an attack session against the testbed"**. It does not necessarily mean the reading itself was manipulated. Network attacks such as scanning or password guessing need not change a temperature reading. The labels are therefore session labels, not per-reading ground truth of compromise.
- **There is no device ID or session ID.** The only metadata is `date` and `time`.

## 3. Findings that decide feasibility
| Finding | Evidence | Consequence |
|---|---|---|
| **Time reveals the label perfectly** | Normal rows were all recorded on **2019-03-31** (Modbus 12:40–12:44, **3.8 min**; Weather 4.0 min; GPS 31 Mar to 1 Apr). Each attack type sits in its own non-overlapping window on 23–28 April | `date`/`time` must never be features. And because normal and attack come from different sessions, **any feature that drifts between sessions is a proxy label** |
| **One normal session, one session per attack type** | No class appears in more than one session | No session-held-out split can contain both classes in train and test. Generalisation to a new session can't be measured for "normal" |
| **Modbus registers carry no usable signal** | All four registers span the full 0–65,535 range with similar medians in both classes. After removing duplicates, the nearest neighbour's label agrees **51.0%** of the time (chance) | A Modbus model could only learn artefacts (duplication, sampling rate). **Not meaningful despite the Modbus priority** |
| **Modbus duplication and sampling artefacts** | 13,314 exact duplicate rows (43%); only 8,865 unique register vectors of 31,106. Normal was logged at **72 rows/s**, attacks at about 1 row/s | Inflated accuracy under random splits; class identifiable by density |
| **GPS values are physically impossible and session-specific** | Latitude up to 549 and longitude up to 555. 31.5% of attack rows (9.2% of normal) are outside ±90/±180. Median latitude by type: normal 1.6, scanning 193.5, ddos 125.6, ransomware 20.0 | The simulated position drifts per session, so separation reflects session identity, not attack behaviour |
| **Near-duplicate neighbours inside sessions** | Nearest-neighbour label agreement on unique rows: GPS **0.941** (median distance 0.0003), Weather **0.979** (0.0087) | Random row splits put near-copies of the same session in train and test, producing near-perfect but meaningless scores |
| **Label conflicts** | Modbus 0; Weather 0; GPS 1 vector covering 304 rows | Negligible |
| **Class imbalance** | Attack 52–62% of rows; xss and scanning only 529–866 rows each | Per-type results for rare types would be very noisy |

## 4. Can these files support a defensible model?
- **No, not as an intrusion or attack detector.**
  - Every evaluation option either leaks session identity (random or row splits) or can't hold out a normal session, because there is only one.
  - High scores would come from time and session drift (GPS coordinates, Weather drift) or duplication and sampling (Modbus).
  - We would be unable to claim that detection reflects attack behaviour.
- **Combining the three files** doesn't help. It adds devices from the same sessions, and the session confound stays.
- **Per-device-type models** inherit the same problem.
- **A telemetry anomaly detector** trained on normal only would learn one 4-minute (Modbus/Weather) or 30-hour (GPS) normal session. Every later session would look anomalous because of drift, so its "detections" would again be session effects.
- **Multiclass attack-family classification** is not supported: each family is one session, so the classifier would learn session identity.

## 5. Recommendation
1. **Preferred: obtain the TON_IoT network dataset** (`Train_Test_Network.csv`, network-flow records from the same project). That matches SENTINEL's goal of *IoT network intrusion detection*, and has many connections per session with traffic features rather than device state. It needs approval to download and its own audit: drop identifiers such as IPs, ports and timestamps, and check for session leakage.
2. **Alternative: obtain the remaining device files or the `Processed_datasets` telemetry** and check whether normal traffic was recorded on several days, interleaved with attacks. Only then could session-held-out evaluation work.
3. **Not recommended: train on the present three files.** If you want a demonstration anyway, it must be labelled "session-separability demo, not a validated detector", with the protocol below. It would not meet the water or electricity standard.

## 6. Proposed protocol (if a suitable dataset or new evidence is approved); see `EVALUATION_PROTOCOL.md`
Summary:
- **Task:** binary benign vs attack first. Multiclass only if each family has several independent sessions.
- **Leakage controls:** split by session or day, deduplicate before splitting, and drop identifiers and time.
- **Session-confound check:** a "time/session-only" model must perform worse than the real model.
- **Models:** logistic regression baseline, then Random Forest and HistGradientBoosting.
- **Gate fixed before training:** false-positive-rate cap, recall above baseline on validation **and** in grouped CV, and passing the confound check.
