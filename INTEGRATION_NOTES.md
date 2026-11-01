# Master city integration: reply to the SENTINEL backend handoff

Dataset checked: `master_city/data` MD5s match the handoff (assets 3a473e52…, links 18728376…, services f73ab1cf…,
vulns bd754756…). Loaded into `data_master/` unchanged, plus `metadata/asset_metadata.csv` copied beside it for the
twin's sector grouping. The example data in `data/` is untouched.

The handoff was written against the step-5 backend. Several items were already changed in passes 3 to 5.

## Results now (all three datasets)

| Dataset | test_risk | test_simulate | test_optimize | test_pass3 |
|---|---|---|---|---|
| data (6 example) | 3/3 | 8/8 | 4/4 | 5/5 |
| data_district28 | 3/3 | 8/8 | 4/4 | 5/5 |
| data_master (33) | 3/3 | 8/8 | 4/4 | 5/5 |

`test_simulate` gained a test: removing exposure never increases expected or worst-case harm.
No fix raises expected harm on any dataset.

## Each handoff item

| Item | Status | What was done |
|---|---|---|
| Issue A: patching a monitored asset raises harm (EL02, IO01) | Resolved, differently from Fix 1 | Pass 5 replaced global containment with zone containment: a monitored asset's alarm isolates only its zone (plus the network-wide catch-all at T+04:00). With that model, patching EL02 or IO01 no longer raises harm, and the monotonicity test passes. Fix 1 (alert on first attempt) was not adopted: the handoff itself notes it is optimistic (every monitored neighbour of an entry alarms at T+10). |
| Issue B: WA04 worst case irreducible | Resolved with Fix 2, scoped | New fix `restrict_exposure` ("Remove direct internet access to …"), 4 staff hours, offered only in zones `field` and `control` (WA04, IO02, IO03 on this data). The optimizer shortlist now always includes the best single fix against each entry point, so combinations like this one are found. Single attacker, 3 fixes, 2 windows: worst case 27.0M → 7.7M (−71%), attacker moves to EL07. Not zero, because EL07 (vendor-hosted, `cloud` zone) is not offered this fix, by design. |
| Hard-coded A01 | Fixed | `simulate.py __main__` reads entry points from the data; the segment test runs over every real entry point. |
| Fix 3: zero-population services | Adopted | `harm.py` and `optimize.py` ignore population-0 services for "first failure". SV07 can be added back to `services.csv` by regenerating the dataset; it was not hand-edited here. |
| SV07 as frontend status | Not built | Add SV07 to the dataset (with Fix 3 merged it is harmless), and it appears in the services rail automatically. |

## Numbers that changed versus the handoff, and why

The handoff numbers (expected 1.85M, worst 10.8M via WA04, first failure T+36.5) came from the global-containment
model. With zone containment: expected 34.8M, worst 27.0M via EL01, first failure T+36.5. Zone containment is
more pessimistic: one alarm no longer stops attacks in other sectors.

"Likely harm, all ways in" can exceed the single worst case: it adds every entry point weighted by its likelihood
(7 entries, several near 0.9). The UI now says so in plain words.

## What was not needed

- The missing `01/NVD` zip (two large JSON files): the backend and twin read only the four contract CSVs, so they run
  without it. It is needed only to regenerate the master city (`build_master_city.py`) and possibly for the ML
  model's training data.
- Empty folders received: 00_MANIFEST, 06_OPTIONAL_SECTORS, 07_READY_FOR_HACKATHON, 08_DATA_DOCUMENTATION, CPE,
  ICS_ADVISORIES, and SWaT, WADI, EPIC inside 02. If they were meant to have content, it did not arrive.

## For the ML handoff

The backend reads an optional `exploit_prob` column (0 to 1) in `vulns.csv`, same `cve_id` values. If present it
replaces the KEV/EPSS rule for that CVE. No other change is needed.
