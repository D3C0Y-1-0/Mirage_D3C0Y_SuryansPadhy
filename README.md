# Cascade: PS03 critical infrastructure cyber-risk platform

By Dhruv Salunkhe and Suryans Padhy. GitHub link and credits: `frontend/static/site-config.js` (one file).

Three parts, one server:
- `http://localhost:8000/` the project site (scrollable landing page)
- `http://localhost:8000/app` the platform: 16 pages in a sidebar (overview, digital twin, inventory, services,
  vulnerabilities, multi-attacker simulation, incidents, timeline, risk register, graphs, ML, optimiser, response,
  project, architecture, security and 2FA)
- `http://localhost:8000/twin` the original 3D twin, unchanged (the platform's Digital twin tab embeds this page)

A simulated cyber digital twin of a hospital and power district. It replays how an attack spreads over time,
ranks fixes by how much harm and time they buy, and finds the best fix bundle for a budget, assuming the attacker
switches to the best remaining way in.

## Quick start (Windows)

Double-click `run.bat`. It activates the virtual environment if it finds one, starts the server and opens the
browser. `run_master.bat` starts it on the SENTINEL master city (33 systems, six sectors, 44 real CVEs).
`run_district28.bat` does the same on the 28-system demo district (fallback dataset, also used to test
performance). To use another dataset folder, set `CASCADE_DATA` to its name before starting.

In the app: **Present** runs a six-step guided demo with live numbers (arrow keys to move, Esc to end).
**Graphics** (or the P key) shows frames per second and switches between High, Balanced and Low graphics.

## Run it by hand (Windows PowerShell)

```
cd ps03
venv\Scripts\activate            # or: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass first
pip install -r requirements.txt  # once; adds fastapi and uvicorn
python -m uvicorn api:app --app-dir backend --port 8000
```

Open http://localhost:8000 in Chrome or Edge. Stop the server with Ctrl+C.

## Use it

- **Attack replay:** pick a ready-made attack (worst case, through a supplier, two at once, inside job) and a type of
  attacker, or click any building in the city: attack from here, add as a second attack, see why it is at risk, or
  protect it with its best fix. Press play (or Space) and drag the timeline. Tab to a building label and press Enter
  to open its menu from the keyboard.
- **Fix ranking:** every fix tested against every entry point. Tick a fix to apply it to the replay.
- **Response plan:** run an attack, then see each action with its deadline and which ones fall before you would notice.
- **Can you trust this order?** At the bottom of Fix ranking, test every estimate 30% down and up.
- **Optimizer:** set fixes, maintenance windows, staff hours and one or two simultaneous entry points.
  "Compare before and after" shows two twins side by side; "Apply to replay" carries the bundle over.

## Multi-attacker simulation (`backend/multi.py`)

Several attackers, each with its own entry point, start time, speed, path history and containment, in the same city at
the same time. Alarms and zone isolation are shared. Also: adaptive attackers (re-pick the best way in after your
fixes) and maintenance windows (a system offline while it is patched). Ready-made scenarios A-H are built from the
loaded dataset (`GET /api/multi/presets`), plus I (one attacker, two ways in), J (four attackers) and K (failsafe
island mode). `test_multi.py` proves the new engine gives exactly the old engine's answer for one attacker and for two
attackers starting together.

One attacker can hold several ways in: `{"id": "A", "entries": [{"asset": "EL01", "start": 0}, {"asset": "WA04", "start": 10}]}`
(`entry` + `start` still work). The 3D twin replays any scenario through `/api/multi`: one colour per attacker, a beam
at each way in that drops at its own start time, an outer ring where a second attacker also got in, attributed events.
From the platform, "Replay in 3D twin" passes the whole scenario (attackers, starts, containment, maintenance,
failsafe, fixes). In the twin, click a building for "Add as a new attacker" or "Add as another way in", with a start
minute.

## Live attack demo (`/app#/live`): step by step

**What is real and what is not.**
- **Real:** the Modbus/TCP traffic, the detection, the isolation and the recovery. The attack script sends real protocol frames over a real socket; Cascade inspects each one as it arrives; isolation closes and refuses the attacker's connection; recovery rewrites the controller's registers.
- **Emulated:** the controller. It's a small Python program (`backend/live.py`) standing in for `WA01` Pumping Station PLC, with a toy tank model.
- **Simulated:** everything beyond the controller (the rest of the city).

The page, the top bar and the twin all say this.

**On one laptop (about 2 minutes on stage):**
1. Start Cascade (`run_master.bat`). The emulated controller starts with it on `127.0.0.1:5020`.
2. Open `http://localhost:8000/app#/live`. For the first 30 seconds it learns normal behaviour from the HMI's own traffic (pipeline stage 1), then shows **Normal. Watching every request.**
3. Optional: open `http://localhost:8000/twin` in a second window or on a second screen.
4. Open a second terminal in the project folder and run `attack.bat recon` (or `python tools\live\attack.py recon`). Two **notices** appear: an unknown device (T0848 Rogue Master) and an address scan (T0861 Point & Tag Identification). No alarm yet: reading is suspicious, not damaging.
5. Run `attack.bat` (the full attack). Within a second:
   - The page shows **ALARM** with alerts for T1692.001, T0878, T0836 and T0831.
   - Every page's top bar shows **LIVE ALARM WA01**.
   - The twin marks WA01 as the way in and replays the simulated spread: District Water Supply, 60,000 people, lost at T+03:00 if nobody stops it.
   - The tank starts filling: the attacker forced the pump on in manual mode.
6. Either click **Isolate now**, or wait 20 seconds and the **failsafe** isolates on its own. The attacker's terminal prints that the controller closed the connection. Running the attack again shows *refused (isolated)*.
7. Point out that the tank is still at risk: isolation stops the attacker but does not undo what they wrote. Click **Restore known-good configuration**: setpoints, alarm and auto mode come back, and the tank drains.
8. Click **Close incident**. Every decision is in the hash-chained audit log (`/api/ops/verify`).

The independent safety trip (SIS) checkbox shows defence in depth. With it on, the pump is forced off at 490 cm whatever the attacker writes, because a real SIS isn't reachable over Modbus. Switch it off to let the tank overflow.

**From a second laptop (more convincing):** start Cascade with `run_master_lan.bat` (it sets `CASCADE_LIVE_HOST=0.0.0.0` and prints this laptop's IP address; allow Python on private networks when Windows asks). On the other laptop, copy `tools\live\attack.py` (Python 3, standard library only) and run `python attack.py --host <IP>`. The page then shows the attacker's real IP address.

**If something goes wrong:**
- **Port 5020 is busy:** set `CASCADE_LIVE_PORT=5021` before starting, and use `--port 5021`.
- **You need the testbed off:** set `CASCADE_LIVE=0`.
- **Safety:** the script only works against this emulated controller. Never point it at real equipment.

## Recovery (`/app#/recovery`) and the assumptions register (`/app#/assumptions`)

**Recovery** answers what comes after the 6-hour window. Once the attacker is cut off from a system (its zone isolated, or the whole network), a crew restores it:
- Restore times are per type of system, ×3 with no tested backup.
- 1–8 crews work in parallel.
- Crews go to the systems that bring back the most people first. Low-value work waits if it would block a service-critical system.

The page shows a restoration timeline, when each service is back, people-hours lost (including after the window), and a crews × backups grid.

Finding on the worst case: water and power are back at T+07:15, but cleaning could not start before T+04:15, because nothing on that path is monitored and isolation waited for the network-wide cut. Monitoring shortens recovery, not just detection. Restore times are planning assumptions and are labelled as such.

**Assumptions register:** every number the model uses, with its meaning, an honest basis and how it was tested. Example: the 240-minute time to detect without monitoring is marked optimistic, because industry reports put attacker dwell time in days.

**MITRE ATT&CK for ICS:** every fix type now lists its ATT&CK for ICS mitigations and the techniques it counters (Compliance page). Every live alert names its technique and the mitigation that would stop it. IDs were checked against attack.mitre.org; note that "Unauthorized Command Message" is now **T1692.001**, not T0855.

## What's new in PASS 16 (twin traffic, graph and data fixes)

**Digital twin: traffic signals that are tied to the model.**
- Every grid junction outside the district now has four signal heads, zebra crossings and stop lines: 61 junctions on `data_master`, 66 on `data_district28`.
- The signals run a 14-second cycle with a green wave along the diagonals.
- Cars drive on the left, stop at red and queue behind each other. Cars now have a body, a cabin, headlights and tail lights.
- **The one link to the data:** when the dataset's junction-signal controller is reached in the simulation, every signal in the city blinks the attacker's colour. That controller is `TR02` on `data_master` and `D26` on `data_district28`. Blinking means the twin can no longer vouch for the lights. While it lasts, cars stop obeying the lights, because nobody can trust them. The controller's own model shows the same cycle.
- The Variable Message Sign controller (`TR04`) is now a gantry with an LED board. It shows a generic message ("KEEP LEFT / DRIVE SAFE") and switches to "SIGN CONTROLLER REACHED IN SIM" only when that asset is reached.
- The legend says plainly that city traffic and street signals are scenery, apart from that one link.
- **Fixed:** with reduced motion or low graphics on, every car was stacked at the district centre. Cars are now placed once and stay still.
- **Fixed:** a building label could draw over the "Simulated" pill in the top bar.

**Graphs and data.**
| Bug | Fix |
|---|---|
| `niceTicks` could stop below the data maximum, so lines overshot the plot (service disruption chart). It affected every chart's top tick. | The top tick always covers the data. Horizontal bars end their scale on the last tick. |
| End-of-line labels drew on top of each other (propagation chart) or above the plot. | Labels are clamped inside the plot, right-aligned near the edge and stacked so they never overlap. |
| Time axes used 100-minute ticks (T+01:40, T+03:20). | Whole hours, or every 2 h when the plot is narrow. The last label is kept inside the chart. |
| Propagation chart: "detection on" and "nobody stops it" were identical with no explanation. | A takeaway computed from the numbers: detection fires at T+00:28, but isolation only cuts off that zone, so the attacker still reaches all 6 systems. That's a finding, not a glitch. |
| Burn-down spaced weeks 0, 1, 2, 4, 8 and 13 evenly. | Spaced by real week number. |
| Water held-out test: Attack 7 (0 h) looked like a missing bar. | Value labels on vertical bars; the subtitle explains that 0 h means flagged in the first hour. |
| Horizontal-bar labels with wide letters ran past the left edge on phones. | Measured truncation, with the full name kept as a tooltip. |
| "Likely harm" (34.8M) is larger than "worst case" (27.0M) on the overview and exposure pages, with no explanation. | It's a sum of likelihood × harm over every way in, so it can exceed one attack. That's now said wherever the number appears. |

Data audit: all 31 GET endpoints were checked for NaN, infinity, negative counts and probabilities outside 0–1, and cross-checked against each other. Overview equals analytics, the summed figure matches the per-entry data, Monte Carlo has P10 ≤ P50 ≤ P90, the roadmap is non-increasing, and all strategies share one baseline. No issues.

## What's new in PASS 12 (bug fixes)

| Bug | Root cause | Fix | Proven by |
|---|---|---|---|
| Landing zoom: the background matched one callout only | One static screenshot (T+02:30), callouts at fixed screen positions, zoom to one fixed point | Five real frames captured from the twin (`tools/capture_twin_frames.js`), hotspots projected from the twin's 3D positions into `twin-frames.json`; crossfade per step, per-step pan and zoom, each callout pinned beside its hotspot with a connector | `tools/e2e/landing_zoom.js`: 10 scroll positions × 3 widths, frame = step, connector ends 0 px from the hotspot |
| "Try it": nothing happens, or lines that are not the attack | `/api/public/attack` returned only times, so the page joined any two compromised neighbours; no loading or error state | Endpoint returns `parents`, `events`, isolations, services with `backup_from`; map grows each parent edge between the two times on one clock with play/pause and scrubber; services, events and harm tick on the same clock; loading, first-time optimiser and error messages; keyboard | `test_api.py`; `tools/e2e/landing_tryit.js` (pink set and edges at 5 minutes, before and after) |
| Domes before any fix | `paint()` showed the dome for `monitored = 1` in the dataset as well as for applied fixes | Dome only for fixes applied in this session; monitored systems get a dashed ground ring with its own legend entry | `tools/e2e/matrix.js` (dome rows) |
| "Who got where" did not play properly | Results opened below the fold, edges appeared only on arrival, small crowded map | Auto-scroll to results, edges grow in flight, contested outer ring, per-attacker offsets, bigger map, label collision avoidance | `tools/e2e/sim2d.js`, `tools/e2e/matrix.js` |
| Twin could not show two attackers | It called `/api/simulate`, which merges every entry point into one attacker | `/api/multi` whenever a scenario needs it; attacker colours, letters on beams and pulses, contested rings, attributed rail and ticker | `tools/e2e/matrix.js` (10 rows, 2D and 3D) |
| "T+00:60", "2h 60m left" | Minutes rounded after splitting hours | Round first, then split | visible in the captured frames |
| Attack paths: route not exact, no replay | Unnumbered segments; choke-point test used the worst entry even if its route did not cross that link | Numbered hops with arrows, "Replay this route" (per-hop minutes from the API), choke points run before and after from a way in whose route crosses them | `tools/e2e/sec5.js` |
| Incidents and timeline | Waiting, blocked and failsafe states missing; blocked attackers vanished; ticks off-centre; marker static | Correct states; blocked attackers stay listed; ticks centred; shared replay marker with a scrubber; truncation with tooltips; failsafe and later ways in on the lanes | `tools/e2e/sec5.js` |
| Try it: before and after identical | Protect applied the optimiser's single city-wide bundle; for 18 of 22 harmful starting points it changed nothing | Protect now searches the best 3 fixes against the attack you picked; if no fix helps (the attacker starts on the critical device itself) the page says so instead of showing two identical maps | `tools/e2e/landing_tryit.js` fails if Protect does not lower harm |
| Account menu not clickable | The top bar sat under the page (page animations create stacking contexts) | Top bar raised above the page; the menu now says whether sign-in is on | click sweep; `tools/e2e/auth_flow.js` |
| Second sign-in within 30 s of turning on 2FA failed with "not valid" | Replay protection refuses a reused code, but said "not valid" | Says "already used, wait for the next code" | `tools/e2e/auth_flow.js` (full sign-in, 2FA, recovery code once) |
| Twin water tab never lit anything during the attack-6 replay | Every anomalous signal there is unmapped to a city building | Faint amber ring on the systems that carry those signals (SCADA, HMI), labelled "sees water anomaly", never "caused" | `tools/e2e/twin_water.js` |
| Table headers invisible inside dark cards in the light theme | Light-theme rule painted all table headers white | Headers inside dark cards stay dark | `tools/e2e/themes.js` (both themes, contrast check) |
| Bad input gave 500 or was accepted | Unvalidated `speed`, roadmap params, water dates | Pydantic limits and explicit 400s | `tools/e2e/api_badinput.py` (35 cases, all 4xx) |

## What's new in v3

- **Landing page** (`/`): bright blue theme, smooth scroll, a pinned "zoom into the city" section with an X-ray of the
  worst way in, live numbers from `/api/public/*`, an "attack the city, then protect it" demo with a before/after
  divider, a water ML spotlight, FAQ.
- **Platform**: light theme by default (moon/sun button switches), Ctrl+K search for pages and systems, skeleton
  loading, animated KPIs. New pages: Exposure and roadmap (0-100 score, 13-week plan, rupee cost, P10/P50/P90
  uncertainty from 200 runs), Attack paths (crown jewels, fastest routes, choke points), Drill mode (scored operator
  training), Incident report (print or PDF), Compliance mapping (guidance only). Attacker profiles on Attack
  simulation; water anomaly badges in the risk register; hash-chained audit trail with "Verify chain".
- **Twin**: labels never overlap each other or the panels, shorter names, "Simulated, 33 systems" note fixed,
  Risk heatmap button (H).
- **Layout audit**: `node tools/audit_layout.js 1440,1280,1024,768,390 --twin` (server running) checks every page.

## Water anomaly monitoring (`backend/water.py`, `ml_water/`)

SENTINEL Model C (Suryans Padhy) output on historical BATADAL data, plus an independent rule layer (hard limits,
pump/flow consistency, rate of change, frozen sensors) learned from a period with no documented attack. Platform page
"Water anomaly monitoring" (operator console that stops at each alarm and waits for a human) and a "Water anomalies"
tab in the 3D twin (amber ring = advisory, never pink). Only WA01 and WA04 are mapped; everything else is shown by
C-Town zone.

## Electricity attack screening (`/app#/electricity`, `ml_electricity/`) and the sector ML status

Module 11 from the ML team: a frozen Random Forest that sorts one MSU-ORNL power-system benchmark sample into normal,
natural disturbance or cyberattack. Held-out (data13-15, scored once by the model owner): attack precision 0.946,
attack recall 0.396, natural disturbance called attack 7.2%, normal called attack 0%. The platform serves the owner's
static outputs as a sample explorer (`/api/electricity/summary`, `/samples`, `/demo`); the model itself is not run
here, so no scikit-learn version pin is needed. A flag reads "investigate"; no flag never reads "safe".

`/api/ml/sectors` and the ML insights page list all six sector modules with their decisions, taken from each module's
own handoff report (`ml_sectors/`): water and electricity approved; healthcare, telecom and transportation NO-GO at their
pre-declared gates; IoT shown only as a demonstration benchmark.

`/app#/evaluation` (Model evaluation) shows every criterion against every score (`ml_sectors/evaluation.json`).
The IoT demonstration (`ml_iot_demo/`, `tools/iot_demo/run_iot_demo.py`) follows option 3 of the IoT audit: the
protocol was declared in `DECLARATION.json` before training, the capture artefact `Number` and window-dependent
aggregates were removed, and the test half was scored once (a lock file refuses a second run). Result: recall 0.889 at
4.0% benign false positives, 0.786 on test rows never seen in training; it fails G4 and cannot satisfy G3, so it is
labelled a random-split in-distribution benchmark, not an independent evaluation. `test_api.py` checks that no unapproved model is ever presented as
approved, and that the explorer agrees with the electricity model card (threshold and confusion matrix).

## Unknown-attack response (`/app#/novel`, `GET /api/novel/whatif`)

For an attack with no CVE and no signature: (1) the water layers learned normal behaviour; (2) an hour deviates;
(3) the threshold raises an alarm; (4) Cascade asks "what if this is an attacker?" and simulates it from the suspected
foothold (the system the signal belongs to, or the systems that carry it to operators, or any system you pick);
(5) it compares no action, operator isolation, failsafe island mode and both, and waits for a human decision with the
failsafe timer running. Every decision goes into the hash-chained audit trail. Honest limit: the foothold is an
assumption, stated on the page; an unknown attack has no CVE, so how it got in is not modelled. Linked from the water
console's alarm box and from the twin's water tab. Test: `node tools/e2e/novel.js`.

The 3D twin now also has a night sky with stars and the moon, roads that run around the district instead of under it,
streetlights, moving traffic, a bay and a distant skyline (decorative only; nothing there carries data).

## Failsafe and human intervention

Alarm ladder: watch, advisory, alarm, failsafe, recovery. The operator approves protective actions; if nobody
answers within `OPERATOR_ACK_MIN` (config.py) the failsafe cuts internet and vendor access ("island mode").
`POST /api/multi` takes `island_at` to test this on any attack; decisions are logged to `.cascade/audit.jsonl`.

## Sign-in and 2FA (`backend/auth.py`)

Open until the first account exists. Create it on the Security page, then turn on 2FA (QR code for any authenticator
app, 8 recovery codes). From then on the platform and API need password + code. Secrets live in `.cascade/`
(git-ignored). Locked out: `python backend\auth.py --reset`. Emergency off switch: `set CASCADE_AUTH=off`.
For a fixed encryption key across machines: `set CASCADE_SECRET=some-long-random-text`.

## Project layout

| Path | What it is |
|---|---|
| `data/*.csv` | The 6-system example. Format in `DATA_CONTRACT.md`. |
| `data_master/` | SENTINEL master city: the four contract files plus optional `asset_metadata.csv` (sectors for the twin). |
| `data_district28/` | 28-system demo district (`tools/make_demo_district.py`), DEMO vulnerability IDs. |
| `backend/config.py` | Every modelling assumption in one place. |
| `backend/load_graph.py` | Step 1: load and validate data. |
| `backend/risk.py` | Step 2: per-asset display score. |
| `backend/simulate.py` | Step 3: attack spread, detection, service failure. |
| `backend/harm.py`, `fixes.py` | Step 4: harm in people-minutes, fix ranking. |
| `backend/optimize.py` | Step 5: budget optimizer with adaptive attacker. |
| `backend/containment.py` | Response plan: what to do, by when, versus when you would detect it. |
| `backend/sensitivity.py` | Moves every estimate 30% down and up and checks the fix order still holds. |
| `backend/multi.py` | Multi-attacker engine with attribution, presets A-H. |
| `backend/auth.py` | Password + TOTP 2FA, standard library only. |
| `backend/api.py` | API for the twin and the platform, page routes, access gate. |
| `frontend/index.html` | The 3D twin (Three.js, bloom, fonts in `frontend/vendor`, works offline). Unchanged. |
| `frontend/landing.html` | Project site. |
| `frontend/app.html`, `frontend/static/` | Platform shell (`core.js`), pages (`pages-*.js`), SVG charts (`charts.js`), 2D network map (`netmap.js`). |
| `frontend/static/site-config.js` | GitHub link, project title, team. |
| `frontend/static/img/twin-step-*.jpg`, `twin-frames.json` | Landing zoom frames and hotspots, captured from the twin (`node tools/capture_twin_frames.js`, server running). |
| `tools/e2e/` | Browser and API checks: scenario matrix, landing sync, section 5, click-everything, bad input. |
| `DESIGN.md` | Design contract: colours, type, layout, rules for anyone changing the UI. |

## Tests

```
python backend\test_risk.py
python backend\test_simulate.py
python backend\test_optimize.py
python backend\test_pass3.py
python backend\test_multi.py
python backend\test_auth.py
python backend\test_water.py
python backend\test_insights.py
python backend\test_api.py
python backend\test_pass17.py
```
63 tests; all pass on `data`, `data_master` and `data_district28` (`set CASCADE_DATA=data_master` first).

Browser checks (server running on `data_master`, `npm i playwright` once if Node does not find it):
```
node tools\e2e\matrix.js          # scenario matrix, 2D page and 3D twin
node tools\e2e\sim2d.js           # 2D replay matches the backend at 5 minutes for every preset
node tools\e2e\landing_zoom.js    # zoom frames, hotspots, connectors
node tools\e2e\landing_tryit.js   # Try it spread tree, before and after
node tools\e2e\sec5.js            # attack paths, incidents, timeline, state across reloads
node tools\e2e\click_all.js       # every button and link
node tools\e2e\themes.js          # both themes: errors, "undefined", invisible text
node tools\e2e\auth_flow.js       # sign-in and 2FA end to end (own temporary server on port 8011)
node tools\e2e\twin_water.js      # twin water rings follow the replay
node tools\e2e\twin_signals.js    # cars never run a red; signals follow the junction-signal controller
node tools\e2e\live_attack.js     # real attack script vs the live testbed: notices, alarm, pill, twin, isolate, recover, failsafe
python tools\e2e\api_badinput.py  # every endpoint answers bad input with a 4xx
node tools\audit_layout.js 1440,1280,1024,768,390 --twin
```

## Honest limits

All infrastructure data is simulated. Spread times, detection times and the harm window are assumptions in
`config.py`; change them and re-run to see how much the results depend on them.

Not real telemetry, not a penetration test: no real system is scanned or attacked. The only attack code is
`tools/live/attack.py`, which reads a few registers and sends four ordinary Modbus writes to Cascade's own emulated
controller (no exploit; Modbus has no authentication, which is the point). The live testbed proves detection and
response on real protocol traffic; it does not prove anything about a real utility's network. The ML is the SENTINEL water anomaly detector (Model C, BATADAL), shown as historical replay in `ml_water/`. CVE
exploitation likelihood is FIRST EPSS plus CISA KEV; the team did not train a CVE model.
