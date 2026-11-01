"""Recovery: after the attacker is cut off, how long until each essential service is back?

The harm metric everywhere else stops at the 6-hour window and assumes a lost service stays lost. This module
adds the part after that: restoring what the attacker touched, with a limited number of crews.

Model (all of it assumptions, stated in RESTORE_HOURS / BASIS and returned with every answer):
  - A compromised system can only be cleaned once the attacker is cut off from it: when its zone is isolated, or
    the whole network is (from the same detection model as the simulator).
  - Each system takes a fixed restore time by type (rebuild or reimage, reload known-good config, verify, reconnect).
    Without a tested offline backup it takes NO_BACKUP_FACTOR times longer (rebuild from scratch).
  - CREWS teams work in parallel; one system at a time each.
  - Order: the system that brings back the most people soonest goes first (people restored per crew-hour, greedy).
    A system that only partly helps a service is credited a share of that service.
  - A service is back when its dependency rule (services.csv) is true again.
"""
from simulate import compile_model, simulate_full

RESTORE_HOURS = {      # with a tested offline backup: reimage or reload, verify, reconnect
    "plc": 2, "rtu": 2, "water_controller": 2, "substation": 3, "iot_gateway": 2, "medical_iot": 2, "camera": 1,
    "generator": 1, "pump_scada": 4, "scada": 4, "hmi": 3, "workstation": 3, "traffic_ctrl": 4, "iccc": 4,
    "emergency_comms": 3, "telecom_gateway": 3, "vpn_gateway": 3, "hospital_network": 4, "pacs": 6, "ehr_server": 8,
    "ad_server": 8, "cloud": 6, "vendor_portal": 6,
}
DEFAULT_HOURS = 4
NO_BACKUP_FACTOR = 3.0
BASIS = ("Planning assumptions for this demo, not measurements. Field devices (PLC, RTU, controller) are reflashed and "
         "their logic reloaded and checked; servers are reimaged from a known-good backup; directory servers and "
         "clinical systems take longest (real Active Directory forest recovery can take days). Replace these with the "
         "restore times your utilities have actually tested in drills.")
ATTACK_MITIGATIONS = [   # MITRE ATT&CK for ICS mitigations this stage relates to (IDs checked against attack.mitre.org)
    {"id": "M0953", "name": "Data Backup"}, {"id": "M0811", "name": "Redundancy of Service"},
    {"id": "M0810", "name": "Out-of-Band Communications Channel"}]


def restore_hours(asset_type, backups=True):
    h = RESTORE_HOURS.get(asset_type, DEFAULT_HOURS)
    return h if backups else h * NO_BACKUP_FACTOR


def _rule_ok(rule, ids, down):
    up = {a: a not in down for a in ids}
    return eval(rule, {"__builtins__": {}}, {"up": up})


def plan(tables, entry, crews=2, backups=True, speed=1.0):
    m = compile_model(tables)
    assets = tables["assets.csv"].set_index("asset_id")
    r = simulate_full(tables, {entry: 0}, speed)
    hit = r["compromised"]
    # when each system can be worked on: its zone isolated, or the whole network
    zone_cut = {i["zone"]: i["at"] for i in r["isolations"] if i["zone"] is not None}
    net_cut = min([i["at"] for i in r["isolations"] if i["zone"] is None], default=None)
    ready, ready_by = {}, {}
    for a in hit:
        z = zone_cut.get(m["zone"][a])
        cands = [x for x in (z, net_cut) if x is not None]
        ready[a] = min(cands) if cands else None          # None: never contained in the model (no detection)
        ready_by[a] = None if not cands else ("zone" if z is not None and z <= (net_cut if net_cut is not None else 1e18) else "network")
    services = [(name, rule, pop) for name, rule, _buf, pop in m["services"]]
    failed = {name: r["failures"][name] for name, _, _ in services if name in r["failures"]}

    # greedy order: people brought back per crew-hour
    down, order = set(hit), []
    remaining = set(hit)
    while remaining:
        def score(a):
            after = down - {a}
            gain = 0.0
            for name, rule, pop in services:
                if name not in failed or _rule_ok(rule, m["ids"], down):
                    continue
                if _rule_ok(rule, m["ids"], after):
                    gain += pop
                elif a in _rule_assets(tables, name):
                    need = len([x for x in _rule_assets(tables, name) if x in down]) or 1
                    gain += pop / need * .5             # partial credit: one of several systems this service waits for
            return gain / restore_hours(assets.at[a, "type"], backups), -(ready[a] or 1e9)
        a = max(sorted(remaining), key=score)
        order.append(a); remaining.discard(a); down.discard(a)

    # dispatch: whenever a crew is free it takes the highest-priority system that is already cut off from the attacker;
    # if none is ready yet it waits for the next one (so no crew idles while there is work it is allowed to do)
    free = [0.0] * max(1, int(crews))
    jobs, todo = [], [a for a in order if ready[a] is not None]
    rank = {a: i for i, a in enumerate(order)}
    while todo:
        k = min(range(len(free)), key=lambda i: free[i])
        now = free[k]
        avail = [a for a in todo if ready[a] <= now + 1e-9]
        if not avail:
            now = min(ready[a] for a in todo)
            avail = [a for a in todo if ready[a] <= now + 1e-9]
        helps_of = lambda x: any(x in _rule_assets(tables, n) for n in failed)
        a = min(avail, key=lambda x: (not helps_of(x), rank[x]))
        if not helps_of(a):        # do not tie a crew up on low-value work if a service-critical system is about to be ready
            until = now + restore_hours(assets.at[a, "type"], backups) * 60
            soon = [ready[x] for x in todo if helps_of(x) and ready[x] < until]
            other_crews = sum(1 for i, f in enumerate(free) if i != k and f < until)
            if len(soon) > other_crews:            # not enough other crews for the critical work that is coming
                free[k] = max(now, min(soon))
                continue
        todo.remove(a)
        start = now
        dur = restore_hours(assets.at[a, "type"], backups) * 60
        end = start + dur
        free[k] = end
        helps = [name for name, _, _ in services if name in failed and a in _rule_assets(tables, name)]
        jobs.append({"asset": a, "name": str(assets.at[a, "name"]), "type": str(assets.at[a, "type"]),
                     "zone": str(assets.at[a, "zone"]), "compromised_at": hit[a], "ready_at": round(ready[a], 1), "ready_by": ready_by[a],
                     "start": round(start, 1), "end": round(end, 1), "hours": round(dur / 60, 1), "crew": k + 1,
                     "helps": helps})
    never = [a for a in order if ready[a] is None]

    # when each failed service comes back
    done = sorted(jobs, key=lambda j: j["end"])
    out_services, people_hours, in_window = [], 0.0, 0.0
    for name, rule, pop in services:
        if name not in failed:
            continue
        down_now, back = set(hit), None
        if _rule_ok(rule, m["ids"], down_now):
            back = failed[name]
        for j in done:
            if back is not None:
                break
            down_now.discard(j["asset"])
            if _rule_ok(rule, m["ids"], down_now):
                back = max(j["end"], failed[name])
        out_h = None if back is None else (back - failed[name]) / 60
        ph = None if out_h is None else pop * out_h
        if ph is not None:
            people_hours += ph
            in_window += pop * max(0.0, min(back, 360) - failed[name]) / 60
        out_services.append({"name": name, "population": int(pop), "failed_at": failed[name],
                             "restored_at": None if back is None else round(back, 1),
                             "outage_hours": None if out_h is None else round(out_h, 1),
                             "people_hours": None if ph is None else round(ph)})
    last = max([s["restored_at"] for s in out_services if s["restored_at"] is not None], default=None)
    return {"entry": entry, "entry_name": str(assets.at[entry, "name"]), "crews": int(crews), "backups": bool(backups),
            "detected_at": r["detected_at"], "contained_at": r["contained_at"],
            "systems_hit": len(hit), "jobs": jobs, "never_contained": never, "services": out_services,
            "all_restored_at": None if never else (max([j["end"] for j in jobs], default=0) if jobs else 0),
            "last_service_back_at": last, "people_hours": round(people_hours),
            "people_hours_in_window": round(in_window), "people_hours_after_window": round(people_hours - in_window)}


_RULE_CACHE = {}


def _rule_assets(tables, service_name):
    key = (id(tables["services.csv"]), service_name)
    if key not in _RULE_CACHE:
        import re
        row = tables["services.csv"][tables["services.csv"]["name"] == service_name].iloc[0]
        ids = set(tables["assets.csv"]["asset_id"])
        _RULE_CACHE[key] = {t for t in re.findall(r"[A-Za-z0-9_]+", row["required_logic"]) if t in ids}
    return _RULE_CACHE[key]


def summary(tables, entry, speed=1.0):
    """Main plan (2 crews, backups) plus a small sensitivity grid: crews 1/2/4, with and without backups."""
    main = plan(tables, entry, 2, True, speed)
    grid = []
    for b in (True, False):
        for c in (1, 2, 4):
            p = main if (b, c) == (True, 2) else plan(tables, entry, c, b, speed)
            grid.append({"crews": c, "backups": b, "last_service_back_at": p["last_service_back_at"],
                         "all_restored_at": p["all_restored_at"], "people_hours": p["people_hours"]})
    return {**main, "grid": grid, "restore_hours": RESTORE_HOURS, "default_hours": DEFAULT_HOURS,
            "no_backup_factor": NO_BACKUP_FACTOR, "basis": BASIS, "attack_mitigations": ATTACK_MITIGATIONS}
