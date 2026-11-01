# PS03 Data Contract v3 (shared by both teammates)

Changes in v3 (no column changes; every v2 dataset still loads):
- Optional `asset_metadata.csv` in the same folder (columns `asset_id`, `sector`, `ui_cluster`). If every asset has a
  `ui_cluster`, the twin groups buildings into sector pads named after `sector`.
- `layout_x`/`layout_y`: if EVERY asset has both, the twin uses them (any canvas size; scaled automatically).
- New fix the backend can recommend: "Remove direct internet access" (`restrict_exposure`), offered only for assets
  in the `field` and `control` zones that are `internet_facing` or `vendor_access`.
- Services with `population_affected` = 0 are allowed (status only): they never count as "first service lost".
- New asset types with their own 3D model and response wording: rtu, hmi, pacs, ad_server, iccc, emergency_comms,
  iot_gateway, cloud, workstation. Any other type still works (generic server building, generic action).

Changes in v2: new optional `monitored` column in assets.csv; clarified which link types are attack paths;
`version` must be stored as text (e.g. `5.10`, not `5.1`).

Rule: everything the backend reads is one of the CSV files below, in the `data/` folder, with EXACTLY these column names.
Lists inside a cell use `;` as the separator (example: `CVE-2023-1111;CVE-2024-2222`).
Booleans are `0` or `1`. Empty value = leave blank.
Do not rename columns without telling the other person.

## data/assets.csv  (one row per asset = one node in the graph)
| column | type | meaning / allowed values |
|---|---|---|
| asset_id | text, unique, no spaces | e.g. `A01` |
| name | text | e.g. `Hospital EHR Server` |
| type | text | substation, generator, scada, plc, hospital_network, ehr_server, medical_iot, water_controller, pump_scada, traffic_ctrl, camera, telecom_gateway, vpn_gateway, vendor_portal, cloud, workstation, ad_server (add others if needed) |
| zone | text | `enterprise`, `dmz`, `control`, `field`, `vendor`, `cloud` |
| criticality | int 1-5 | 5 = life/safety critical |
| exposure | float 0-1 | 1 = directly internet-facing, 0 = isolated |
| internet_facing | 0/1 | |
| vendor_access | 0/1 | third party can reach it |
| software | text | product name, e.g. `Siemens SIMATIC S7-1500` |
| version | text | firmware/software version |
| cve_ids | list | CVE IDs affecting this asset (must exist in vulns.csv) |
| patchable_without_downtime | 0/1 | 0 = needs a maintenance window |
| downtime_hours_to_patch | float | |
| config_flags | list | from: `default_creds`, `no_mfa`, `open_mgmt_port`, `flat_network`, `unencrypted_protocol` |
| monitored | 0/1 | (added v2) asset already has security monitoring; blank = 0 |
| layout_x, layout_y | float | optional, reserved for the future UI |

## data/links.csv  (one row per connection = one edge)
| column | type | meaning / allowed values |
|---|---|---|
| src | asset_id | must exist in assets.csv |
| dst | asset_id | must exist in assets.csv |
| link_type | text | `network`, `dependency`, `vendor`, `physical`. IMPORTANT: only `network` and `vendor` links are attack paths. Use `dependency`/`physical` for "needs power/data from" relations the attacker cannot travel along. |
| protocol | text | e.g. `modbus`, `https`, `rdp`, `vpn` |
| bidirectional | 0/1 | 1 = attacker can move both ways |
| base_traverse_min | float | minutes an attacker needs to cross this link (assumption, tunable) |
| segmented | 0/1 | already has a segmentation control |
| firewall_level | int 0-3 | 0 none, 3 strict |

## data/services.csv  (essential services that fail when assets are lost)
| column | type | meaning / allowed values |
|---|---|---|
| service_id | text, unique | e.g. `S01` |
| name | text | e.g. `Hospital Power` |
| population_affected | int | people affected |
| required_logic | text | boolean expression on asset_ids, e.g. `A02 OR A03` or `A05 AND (A06 OR A07)` |
| buffer_min | float | minutes of backup before the service actually fails |

## data/vulns.csv  (one row per CVE; the ML teammate owns this file)
| column | type | meaning |
|---|---|---|
| cve_id | text, unique | |
| cvss | float 0-10 | |
| vector | text | CVSS vector string |
| cwe | text | |
| vendor, product | text | |
| kev | 0/1 | in CISA KEV list |
| epss | float 0-1 | EPSS score if available |
| ics_flag | 0/1 | affects ICS/OT product |
| patch_available | 0/1 | |
| patch_type | text | `patch`, `workaround`, `none` |

## Water anomaly ML (SENTINEL Model C), folder `ml_water/` (or set CASCADE_WATER)
- `events/anomaly_events.json`, `replay/replay_dataset04_hourly.csv`, `replay/measurements_dataset04.csv`,
  `demo/attack6_historical_replay.json`, `signal_asset_mapping.csv`, `MODEL_CARD.json`, `reference/*.csv`.
- Advisory evidence only. It never writes `exploit_prob`, never changes CVSS/EPSS/KEV, never marks assets compromised.
- (The optional `exploit_prob` column in vulns.csv is still read if present, but no team model produces it.)

## Later (not needed for step 1)
- controls.csv, scenarios.json, telemetry_sim.csv (see blueprint Section 5)

## Division of work
- Backend owner: loads these files, builds the graph, risk, simulation, fixes.
- Data/ML owner: produces assets/links/services/vulns in this format, and the SENTINEL water anomaly detector (integration package in `ml_water/`). EPSS stays the exploitation prediction.
- The "master dataset" = these four files. Do NOT merge raw datasets into one giant table.
