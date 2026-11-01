"""Multi-attacker simulation: several attackers, each with its own identity, entry point, start time, speed,
path history and containment status, moving through the SAME infrastructure at the same time.

Why a second traversal: simulate.simulate_full() is a multi-source shortest path. It is fast (the optimizer calls it
thousands of times) but it forgets WHO reached each asset. Here every attacker keeps its own state, and the
defenders' state (alarms, zone isolation) is shared, because one alarm isolates a zone for everyone.
Both use the same compiled model (compile_model), the same link timings and the same detection rules, and
test_multi.py checks they agree when attribution is ignored.

Rules:
  - Attackers are independent: B cannot use a foothold that A gained (separate crews, separate credentials).
  - Detection is shared: the first compromise of a MONITORED asset by anyone raises the zone alarm.
  - Containing an attacker (contain_at) stops that attacker spreading after that minute. What it already
    compromised stays lost (containment is not recovery).
  - Adaptive attacker: after the defences change, it re-picks the entry point that does the most combined harm.
  - Maintenance window: an asset being patched is OFFLINE for its downtime (counts as down for services, and the
    attacker cannot get in while it is off). After the window it is patched: crossing into it uses patched timings.
  - A service fails when its rule has been false for longer than its buffer. Unlike the single-attacker engine,
    an outage can END (when maintenance finishes and nothing is compromised), so harm counts only the outage minutes.
Run from project root:  python backend/multi.py
"""
import heapq

from config import (HORIZON_MIN, TTD_MONITORED_MIN, TTD_UNMONITORED_MIN, RESPONSE_DELAY_MIN)
from fixes import apply
from load_graph import load_and_validate
from simulate import compile_model

INF = float("inf")
ISLAND_LOST_ZONES = {"cloud", "vendor"}   # unreachable once internet and vendor access are cut


def _norm(attackers):
    """Each attacker may have one way in ("entry" + "start") or several ("entries": [{asset, start}]).
    "entry"/"start" are kept as the first way in / earliest start for backward compatibility."""
    out = []
    for i, a in enumerate(attackers):
        ents = a.get("entries") or []
        ents = [{"asset": e["asset"] if isinstance(e, dict) else e,
                 "start": float((e.get("start") if isinstance(e, dict) else None) or a.get("start", 0) or 0)}
                for e in ents if (e.get("asset") if isinstance(e, dict) else e)]
        if not ents:
            if not a.get("entry"):
                raise ValueError(f"Attacker {a.get('id') or 'ABCDEFGH'[i % 8]} has no entry point")
            ents = [{"asset": a["entry"], "start": float(a.get("start", 0) or 0)}]
        seen, uniq = set(), []
        for e in sorted(ents, key=lambda e: e["start"]):
            if e["asset"] not in seen:
                seen.add(e["asset"]); uniq.append(e)
        if any(e["start"] < 0 for e in uniq):
            raise ValueError("Start times must be 0 or later")
        out.append({"id": str(a.get("id") or "ABCDEFGH"[i % 8]), "entry": uniq[0]["asset"], "entries": uniq,
                    "start": uniq[0]["start"], "speed": float(a.get("speed", 1.0) or 1.0),
                    "contain_at": None if a.get("contain_at") in (None, "") else float(a["contain_at"]),
                    "adaptive": bool(a.get("adaptive", False)), "active": a.get("active", True) is not False})
        if out[-1]["speed"] <= 0:
            raise ValueError("Attacker speed must be above 0")
    return [a for a in out if a["active"]]


def _service_timeline(m, down_intervals):
    """down_intervals: {asset: [(start, end), ...]}. For each service return failure intervals within the horizon
    [(fail_at, restored_at)], where fail_at = start of a continuous rule-false stretch + buffer."""
    points = sorted({0.0} | {t for iv in down_intervals.values() for s, e in iv for t in (s, e) if t < INF})
    out = {}
    for name, rule, buf, pop in m["services"]:
        stretches, cur = [], None
        for p in points:
            up = {aid: not any(s <= p < e for s, e in down_intervals.get(aid, ())) for aid in m["ids"]}
            ok = eval(rule, {"__builtins__": {}}, {"up": up})
            if not ok and cur is None:
                cur = p
            elif ok and cur is not None:
                stretches.append((cur, p)); cur = None
        if cur is not None:
            stretches.append((cur, INF))
        fails = [(s + buf, e) for s, e in stretches if e - s > buf and s + buf < HORIZON_MIN]
        out[name] = {"pop": pop, "buffer": buf, "fails": fails}
    return out


def _culprit(m, rule, down_intervals, at, owner):
    """Which compromise flipped this service off at minute `at`: the asset whose loss at <= at matters most recently."""
    best = None
    for aid, ivs in down_intervals.items():
        for s, e in ivs:
            if s <= at < e and (best is None or s > best[1]):
                up = {x: not any(s2 <= at < e2 for s2, e2 in down_intervals.get(x, ())) for x in m["ids"]}
                up[aid] = True
                if eval(rule, {"__builtins__": {}}, {"up": up}):     # restoring this one alone fixes the service
                    best = (aid, s)
    if best is None:
        return None, None
    return best[0], owner.get(best[0], "maintenance")


def _run(tables, attackers, speed, detection, maintenance):
    m = compile_model(tables)
    maint = {}
    patched_model = None
    if maintenance:
        t2 = tables
        for w in maintenance:
            maint[w["asset"]] = (float(w["start"]), float(w["start"]) + 60 * float(w["hours"]))
            if w.get("patch", True):
                t2 = apply(t2, {"fix": "patch", "target": w["asset"]})
        patched_model = compile_model(t2)
    padj = {}
    if patched_model:
        for s, lst in patched_model["adj"].items():
            for d, mins in lst:
                padj[(s, d)] = mins

    zone = m["zone"]
    cut, global_cut, detections = {}, INF, []
    reach = [dict() for _ in attackers]
    parent = [dict() for _ in attackers]
    heap = []
    for i, a in enumerate(attackers):
        for e in a.get("entries") or [{"asset": a["entry"], "start": a["start"]}]:
            s = e["start"]
            if e["asset"] in maint:             # cannot get in while it is switched off for maintenance
                ws, we = maint[e["asset"]]
                if ws <= s < we:
                    s = we
            heapq.heappush(heap, (s, i, e["asset"], None))
    while heap:
        t, i, node, came_from = heapq.heappop(heap)
        if node in reach[i]:
            continue
        a = attackers[i]
        if a["contain_at"] is not None and t > a["contain_at"]:
            continue
        if detection and (t > global_cut or t > cut.get(zone[node], INF)
                          or (came_from is not None and t > cut.get(zone[came_from], INF))):
            continue
        reach[i][node] = t
        parent[i][node] = came_from
        if detection:
            if global_cut == INF:
                detections.append((t + TTD_UNMONITORED_MIN, None))
                global_cut = t + TTD_UNMONITORED_MIN + RESPONSE_DELAY_MIN
            if m["monitored"][node]:
                d = t + TTD_MONITORED_MIN
                if d + RESPONSE_DELAY_MIN < cut.get(zone[node], INF):
                    cut[zone[node]] = d + RESPONSE_DELAY_MIN
                    detections.append((d, zone[node]))
        for nxt, minutes in m["adj"].get(node, []):
            if nxt in reach[i]:
                continue
            step = minutes / (speed * a["speed"])
            arr = t + step
            if nxt in maint:
                ws, we = maint[nxt]
                if arr >= ws:                    # interrupted by the maintenance: retry once it is back, patched
                    arr = max(t, we) + padj.get((node, nxt), minutes) / (speed * a["speed"])
            heapq.heappush(heap, (arr, i, nxt, node))
    return m, maint, reach, parent, detections, cut, global_cut


def simulate_multi(tables, attackers, speed=1.0, detection=True, maintenance=(), solo=True, island=None):
    """attackers: [{id, entry, start, speed, contain_at, adaptive, active}]
    maintenance: [{asset, start, hours, patch}]
    Returns per-attacker histories, the combined infrastructure state, service outages with attribution, events."""
    attackers = _norm(attackers)
    m = compile_model(tables)
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    bad = [e["asset"] for a in attackers for e in a["entries"] if e["asset"] not in m["ids"]]
    if bad:
        raise ValueError(f"Unknown entry assets: {bad}")
    maintenance = [w for w in (maintenance or []) if w.get("asset") in m["ids"]]

    # adaptive attackers re-pick their entry against the CURRENT defences (one at a time, greedy)
    for a in attackers:
        a["adapted_from"] = None
        if not a["adaptive"]:
            continue
        taken = {b["entry"] for b in attackers if b is not a}
        options = [e for e in m["entries"] if e not in taken] or [a["entry"]]
        if a["entry"] not in options and a["entry"] in m["entries"]:
            options.append(a["entry"])
        scored = []
        for e in options:
            trial = [dict(b, entry=e, entries=[{"asset": e, "start": b["start"]}]) if b is a else b for b in attackers]
            r = _core(tables, trial, speed, detection, maintenance, names)
            scored.append((r["combined"]["harm"], -r["combined"]["first_failure_min"], e == a["entry"], e))
        best = max(scored)[3]
        if best != a["entry"] or len(a["entries"]) > 1:
            a["adapted_from"] = a["entry"] if best != a["entry"] else None
            a["entry"] = best
            a["entries"] = [{"asset": best, "start": a["start"]}]

    # failsafe "island mode": at island["at"] all internet and vendor access is cut
    extra, blocked, fs = {}, [], None
    if island and island.get("at") is not None:
        T = float(island["at"])
        external = set(m["entries"])
        keep = []
        for a in attackers:
            # ways in from outside that open after the cut are closed; an attacker with none left is blocked
            open_ = [e for e in a["entries"] if not (e["asset"] in external and e["start"] >= T)]
            if not open_:
                blocked.append({**a, "status": "blocked by failsafe", "compromised": {}, "parents": {}, "path": [],
                                "reached": 0, "owned": 0, "last_t": None})
                continue
            a["entries"], a["entry"], a["start"] = open_, open_[0]["asset"], open_[0]["start"]
            if any(e["asset"] in external for e in open_) and island.get("c2", True):
                a["contain_at"] = T if a["contain_at"] is None else min(a["contain_at"], T)
                a["contained_by"] = "failsafe"
            keep.append(a)
        attackers = keep
        zone = m["zone"]
        extra = {aid: T for aid in m["ids"] if zone[aid] in ISLAND_LOST_ZONES}
        remote = sorted(aid for aid in external if zone[aid] not in ISLAND_LOST_ZONES)
        fs = {"at": T, "c2": island.get("c2", True), "lost_assets": sorted(extra), "remote_only_cut": remote,
              "blocked_attackers": [b["id"] for b in blocked],
              "note": ("Cloud and vendor systems become unreachable (counted as down for services). Internet-facing "
                       "systems inside the city lose remote access but keep running on local control.")}
    result = _core(tables, attackers, speed, detection, maintenance, names, extra) if attackers or maintenance or extra \
        else _core(tables, [], speed, detection, maintenance, names, extra)
    result["attackers"] += blocked
    result["failsafe"] = fs
    if fs:
        result["events"].append({"t": fs["at"], "kind": "failsafe", "text": "Failsafe: internet and vendor access cut, operator paged"})
        result["events"].sort(key=lambda e: (e["t"], {"attacker_joins": 0, "compromise": 1}.get(e["kind"], 2)))
    result["maintenance"] = maintenance
    if solo and len(attackers) > 1:
        result["solo"] = {a["id"]: {k: v for k, v in _core(tables, [a], speed, detection, maintenance, names)["combined"].items()
                                    if k in ("harm", "first_failure_min", "assets_lost")} for a in attackers}
    return result


def _core(tables, attackers, speed, detection, maintenance, names, extra=None):
    m, maint, reach, parent, detections, cut, global_cut = _run(tables, attackers, speed, detection, maintenance)

    # combined state: first attacker to reach each asset owns it; keep everyone's times
    first = {}
    for i, a in enumerate(attackers):
        for node, t in reach[i].items():
            if node not in first or t < first[node][0]:
                first[node] = (t, a["id"])
    owner = {n: who for n, (t, who) in first.items()}
    contested = []
    for node in first:
        times = {a["id"]: round(reach[i][node], 1) for i, a in enumerate(attackers) if node in reach[i]}
        if len(times) > 1:
            contested.append({"asset": node, "name": names[node], "times": times, "winner": owner[node]})

    down = {n: [(t, INF)] for n, (t, _) in first.items()}
    for aid, (s, e) in maint.items():
        down.setdefault(aid, [])
        if not any(s0 <= s for s0, _ in down[aid]):
            down[aid].append((s, e))
    for aid, t0 in (extra or {}).items():
        down.setdefault(aid, [])
        if not any(s0 <= t0 for s0, _ in down[aid]):
            down[aid].append((t0, INF))
    owner_c = {**{a: "failsafe" for a in (extra or {})}, **owner}
    timeline = _service_timeline(m, down)
    rules = {n: r for n, r, _b, _p in m["services"]}
    services, harm, first_fail = [], 0.0, HORIZON_MIN
    for name, info in timeline.items():
        if not info["fails"]:
            continue
        f_at, restored = info["fails"][0]
        culprit, by = _culprit(m, rules[name], down, f_at - info["buffer"], owner_c)
        # fail times rounded to 0.1 min like simulate_full, so both engines report the same harm
        minutes = sum(max(0.0, min(e, HORIZON_MIN) - round(s, 1)) for s, e in info["fails"])
        harm += info["pop"] * minutes
        if info["pop"] > 0:
            first_fail = min(first_fail, f_at)
        services.append({"service": name, "population": int(info["pop"]), "fail_at": round(f_at, 1),
                         "backup_from": round(f_at - info["buffer"], 1) if info["buffer"] > 0 else None,
                         "restored_at": None if restored == INF else round(restored, 1),
                         "outage_min": round(minutes, 1), "cause_asset": culprit, "cause": by})

    per = []
    for i, a in enumerate(attackers):
        comp = {k: round(t, 1) for k, t in sorted(reach[i].items(), key=lambda kv: kv[1])}
        path = [{"t": comp[n], "asset": n, "name": names[n], "from": parent[i][n],
                 "first": owner.get(n) == a["id"]} for n in comp]
        contained = a["contain_at"] is not None
        per.append({**a, "compromised": comp, "parents": {k: parent[i][k] for k in comp}, "path": path,
                    "reached": len(comp), "owned": sum(1 for p in path if p["first"]),
                    "status": "contained" if contained else ("blocked" if not comp else "active"),
                    "last_t": max(comp.values()) if comp else None})

    detected_at = min((d for d, _ in detections), default=None) if detection else None
    isolations = []
    if detection and first:
        isolations = sorted(([round(at, 1), z] for z, at in cut.items()), key=lambda x: x[0])
        isolations.append([round(global_cut, 1), None])

    events = []
    for p in per:
        for step in p["path"]:
            src = f" from {names[step['from']]}" if step["from"] else " (entry point)"
            events.append({"t": step["t"], "kind": "compromise", "attacker": p["id"], "asset": step["asset"],
                           "from": step["from"], "first": step["first"],
                           "text": f"Attacker {p['id']}: {step['name']} compromised{src}"})
        for k, e in enumerate(p.get("entries") or []):
            if e["start"] > 0:
                events.append({"t": e["start"], "kind": "attacker_joins", "attacker": p["id"], "asset": e["asset"],
                               "text": (f"Attacker {p['id']} starts at {names[e['asset']]}" if k == 0 else
                                        f"Attacker {p['id']} opens another way in at {names[e['asset']]}")})
        if p["contain_at"] is not None:
            events.append({"t": p["contain_at"], "kind": "attacker_contained", "attacker": p["id"],
                           "text": f"Attacker {p['id']} contained (stops spreading)" + (": its command channel over the internet was cut by the failsafe" if p.get("contained_by") == "failsafe" else "")})
    for s in services:
        who = {"maintenance": " (caused by maintenance downtime)", "failsafe": " (cost of the failsafe: cloud or vendor system cut off)",
               None: ""}.get(s["cause"], f" (caused by attacker {s['cause']})")
        events.append({"t": s["fail_at"], "kind": "service_down", "service": s["service"], "attacker": s["cause"],
                       "text": f"{s['service']} lost{who}"})
        if s["restored_at"] is not None and s["restored_at"] < HORIZON_MIN:
            events.append({"t": s["restored_at"], "kind": "service_restored", "service": s["service"],
                           "text": f"{s['service']} restored"})
    for aid, (s, e) in maint.items():
        events.append({"t": s, "kind": "maintenance", "asset": aid, "text": f"{names[aid]} offline for patching"})
        events.append({"t": e, "kind": "maintenance_end", "asset": aid, "text": f"{names[aid]} back online, patched"})
    if detected_at is not None and detected_at <= HORIZON_MIN:
        events.append({"t": round(detected_at, 1), "kind": "detected", "text": "Attack detected"})
    for at, z in isolations:
        if at <= HORIZON_MIN:
            events.append({"t": at, "kind": "isolated", "zone": z,
                           "text": "Whole network isolated" if z is None else f"Zone '{z}' isolated"})
    events = [e for e in events if e["t"] <= HORIZON_MIN]
    order = {"attacker_joins": 0, "compromise": 1}
    events.sort(key=lambda e: (e["t"], order.get(e["kind"], 2)))

    return {"attackers": per,
            "combined": {"first_by": {n: {"t": round(t, 1), "attacker": who} for n, (t, who) in first.items()},
                         "contested": contested, "services": services, "harm": round(harm),
                         "first_failure_min": round(first_fail, 1), "assets_lost": len(first)},
            "detected_at": None if detected_at is None else round(detected_at, 1),
            "isolations": [{"at": at, "zone": z} for at, z in isolations],
            "events": events, "horizon_min": HORIZON_MIN}


# ---------- ready-made scenarios A-H, built from whatever dataset is loaded ----------
def presets(tables, speed=1.0):
    from harm import evaluate
    from fixes import candidates
    m = compile_model(tables)
    ev = evaluate(tables, speed)
    ranked = sorted(ev["per_entry"], key=lambda e: (-ev["per_entry"][e]["harm"], ev["per_entry"][e]["first_failure_min"]))
    if not ranked:
        return []
    a1 = ranked[0]
    a2 = ranked[1] if len(ranked) > 1 else ranked[0]
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    crit = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["criticality"].astype(int)))
    free = {e: _core(tables, [{"id": "A", "entry": e, "start": 0, "speed": 1, "contain_at": None}], speed, False, [], names)
            for e in ranked}
    reach = {e: set(free[e]["combined"]["first_by"]) for e in ranked}
    pairs = [(x, y) for i, x in enumerate(ranked) for y in ranked[i + 1:]]

    out = []
    def add(key, title, text, attackers, fixes=(), maintenance=(), island_at=None):
        out.append({"key": key, "title": title, "text": text, "attackers": attackers,
                    "fixes": list(fixes), "maintenance": list(maintenance), "island_at": island_at})

    add("A", "Simultaneous attacks",
        f"Two crews enter at the same minute: {names[a1]} and {names[a2]}.",
        [{"id": "A", "entry": a1, "start": 0}, {"id": "B", "entry": a2, "start": 0}])
    add("B", "Staggered attacks",
        f"Attacker A is already moving from {names[a1]}. At T+15 attacker B joins from {names[a2]}.",
        [{"id": "A", "entry": a1, "start": 0}, {"id": "B", "entry": a2, "start": 15}])
    if pairs:
        jac = lambda p: len(reach[p[0]] & reach[p[1]]) / max(1, len(reach[p[0]] | reach[p[1]]))
        x, y = min(pairs, key=jac)
        add("C", "Independent attack paths",
            f"{names[x]} and {names[y]} lead into the most separate parts of the network.",
            [{"id": "A", "entry": x, "start": 0}, {"id": "B", "entry": y, "start": 0}])
        best = None
        for x, y in pairs:
            for node in reach[x] & reach[y]:
                if node in (x, y):
                    continue
                px = free[x]["attackers"][0]["parents"].get(node)
                py = free[y]["attackers"][0]["parents"].get(node)
                if px and py and px != py:
                    tx = free[x]["attackers"][0]["compromised"][node]
                    ty = free[y]["attackers"][0]["compromised"][node]
                    key = (crit[node], -abs(tx - ty))
                    if best is None or key > best[0]:
                        best = (key, x, y, node, tx, ty)
        if best:
            _, x, y, node, tx, ty = best
            add("D", "Converging attack paths",
                f"Both attackers head for {names[node]} by different routes.",
                [{"id": "A", "entry": x, "start": 0}, {"id": "B", "entry": y, "start": 0}])
            later = x if tx > ty else y
            add("E", "Competing compromise",
                f"Both race for {names[node]}. The slower one gets a 10-minute head start to make it close.",
                [{"id": "A", "entry": x, "start": 10 if later == x else 0},
                 {"id": "B", "entry": y, "start": 10 if later == y else 0}])
    add("F", "One attacker contained",
        f"Attacker A (from {names[a1]}) is evicted at T+30. Attacker B keeps going.",
        [{"id": "A", "entry": a1, "start": 0, "contain_at": 30}, {"id": "B", "entry": a2, "start": 0}])
    # G: defend the attacker's planned way in until another route becomes better for it (up to 3 fixes),
    # then let the adaptive attacker re-pick. If no 3 fixes achieve that, it honestly stays where it is.
    def solo_harm(t, e):
        return _core(t, [{"id": "A", "entry": e, "start": 0, "speed": 1, "contain_at": None}],
                     speed, True, [], names)["combined"]["harm"]
    t_g, chosen = tables, []
    for _ in range(3):
        others = max((solo_harm(t_g, e) for e in compile_model(t_g)["entries"] if e != a1), default=0)
        if chosen and solo_harm(t_g, a1) < others:
            break
        best = None
        for fx in candidates(t_g):
            if fx["fix"] == "monitor":
                continue
            h = solo_harm(apply(t_g, fx), a1)
            if best is None or h < best[0]:
                best = (h, fx)
        if best is None:
            break
        chosen.append(best[1])
        t_g = apply(t_g, best[1])
    if chosen:
        fids = [f"{fx['fix']}:{fx['target']}" for fx in chosen]
        labels = "', '".join(fx["label"] for fx in chosen)
        add("G", "Adaptive attacker",
            f"You apply '{labels}'. The attacker planned to use {names[a1]}; it re-picks its best way in.",
            [{"id": "A", "entry": a1, "start": 0, "adaptive": True}], fixes=fids)
    # H: patching an OT asset (needs downtime) while an attacker is active
    assets = tables["assets.csv"]
    window = None
    for _, a in assets.iterrows():
        if int(a["patchable_without_downtime"]) == 0 and str(a["cve_ids"]).strip() not in ("", "nan"):
            feeds = any(a["asset_id"] in rule for rule in tables["services.csv"]["required_logic"])
            score = (feeds, float(a["downtime_hours_to_patch"]))
            if window is None or score > window[0]:
                window = (score, a["asset_id"], float(a["downtime_hours_to_patch"]))
    if window:
        _, aid, hours = window
        add("H", "Attack during remediation",
            f"Attacker A is moving in from {names[a1]}. At T+20 {names[aid]} goes offline for {hours:g} h to be patched.",
            [{"id": "A", "entry": a1, "start": 0}], maintenance=[{"asset": aid, "start": 20, "hours": hours, "patch": True}])
    # I: one attacker, two ways in (same identity, one colour)
    if a2 != a1:
        add("I", "One attacker, two ways in",
            f"The same crew holds {names[a1]} and opens a second way in at {names[a2]} at T+10.",
            [{"id": "A", "entries": [{"asset": a1, "start": 0}, {"asset": a2, "start": 10}]}])
    # J: four attackers at once / staggered
    if len(ranked) >= 4:
        add("J", "Four attackers",
            f"Four crews: {names[ranked[0]]} and {names[ranked[1]]} at T+0, {names[ranked[2]]} at T+10, "
            f"{names[ranked[3]]} at T+25.",
            [{"id": "A", "entry": ranked[0], "start": 0}, {"id": "B", "entry": ranked[1], "start": 0},
             {"id": "C", "entry": ranked[2], "start": 10}, {"id": "D", "entry": ranked[3], "start": 25}])
    # K: failsafe island mode while one outside attacker is active and a second would join later
    add("K", "Failsafe island mode",
        f"Attacker A is moving in from {names[a1]}. At T+12 the failsafe cuts internet and vendor access; "
        f"attacker B's later attempt from {names[a2]} at T+20 is refused.",
        [{"id": "A", "entry": a1, "start": 0}, {"id": "B", "entry": a2, "start": 20}], island_at=12)
    return out


if __name__ == "__main__":
    T, errors = load_and_validate()
    if errors:
        raise SystemExit("; ".join(errors))
    for p in presets(T):
        t = T
        for f in p["fixes"]:
            kind, target = f.split(":", 1)
            t = apply(t, {"fix": kind, "target": int(target) if kind == "segment" else target})
        r = simulate_multi(t, p["attackers"], maintenance=p["maintenance"],
                           island=None if p.get("island_at") is None else {"at": p["island_at"], "c2": True})
        print(f"{p['key']} {p['title']}: harm {r['combined']['harm']:,} first failure T+{r['combined']['first_failure_min']}"
              f" contested {[c['asset'] for c in r['combined']['contested']][:4]}"
              f" adapted {[a['adapted_from'] for a in r['attackers']]}")
