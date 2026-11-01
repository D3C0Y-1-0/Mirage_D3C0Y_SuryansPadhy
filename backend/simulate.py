"""Step 3 (+ detection in step 4): attack-spread simulation with a clock.

The attacker starts at one or more entry assets at time 0 (or a given offset). Crossing a link takes time.
Each asset's compromise time is the EARLIEST time the attacker can reach it (multi-source shortest path, Dijkstra).

Detection and containment (zone model, Pass 5):
  - A MONITORED asset raises the alarm TTD_MONITORED_MIN after it is compromised. RESPONSE_DELAY_MIN later its whole
    zone is isolated: nothing new in that zone is compromised and nothing crosses into or out of it.
  - Unmonitored attacks are still noticed eventually: TTD_UNMONITORED_MIN after the first compromise, and then the
    whole network is isolated.
  This replaced an earlier 'any alarm isolates everything' rule, which let one sensor defend the whole city and made
  some fixes look harmful (slowing the attacker on the way to that one sensor delayed everyone's rescue).

A service fails when its rule becomes false, plus its buffer.
Run from project root:  python backend/simulate.py
"""
import heapq
import re

import pandas as pd

from config import (MIN_EXPLOIT_FACTOR, FIREWALL_FACTOR, SEGMENT_FACTOR, SPREAD_LINK_TYPES,
                    TTD_MONITORED_MIN, TTD_UNMONITORED_MIN, RESPONSE_DELAY_MIN)
from load_graph import load_and_validate, split_list
from risk import vulnerability_score


def flag(row, col):
    """Read an optional 0/1 column; missing or blank counts as 0."""
    if col not in row.index or pd.isna(row[col]):
        return 0
    return int(row[col])


def asset_vulnerability(tables):
    """V per asset (0-1), reused from step 2. Higher V = attacker gets in faster."""
    vulns_by_id = {r["cve_id"]: r for _, r in tables["vulns.csv"].iterrows()}
    return {a["asset_id"]: vulnerability_score(split_list(a["cve_ids"]), split_list(a["config_flags"]), vulns_by_id)
            for _, a in tables["assets.csv"].iterrows()}


def edge_minutes(link, v_target, speed):
    """Minutes for the attacker to cross one link into a target with vulnerability v_target."""
    t = float(link["base_traverse_min"]) / (speed * (MIN_EXPLOIT_FACTOR + v_target))
    t *= 1 + FIREWALL_FACTOR * int(link["firewall_level"])
    if int(link["segmented"]) == 1:
        t *= SEGMENT_FACTOR
    return t


def compile_rule(logic, known_ids):
    """Turn 'A05 AND (A06 OR A07)' into compiled Python once, so it can be checked thousands of times fast."""
    parts = []
    for tok in re.findall(r"[A-Za-z0-9_]+|\(|\)", logic):
        if tok.upper() in ("AND", "OR", "NOT"):
            parts.append(tok.lower())
        elif tok in ("(", ")"):
            parts.append(tok)
        elif tok in known_ids:
            parts.append(f"up[{tok!r}]")
        else:
            raise ValueError(f"services.csv: rule '{logic}' mentions unknown asset '{tok}'")
    return compile(" ".join(parts), "<service rule>", "eval")


def compile_model(tables):
    """Read the tables ONCE into fast plain-Python structures. Cached on the tables dict.
    The cache is rebuilt automatically if any table object is replaced (fixes.apply always makes new copies).
    Do not edit a table in place after simulating; use fixes.apply() instead."""
    keys = ("assets.csv", "links.csv", "services.csv", "vulns.csv")
    src = tuple(tables[k] for k in keys)
    cached = tables.get("_model")
    if cached is not None and all(a is b for a, b in zip(cached["_src"], src)):
        return cached

    v = asset_vulnerability(tables)
    assets = tables["assets.csv"]
    ids = set(assets["asset_id"])
    adj = {}
    for _, l in tables["links.csv"].iterrows():
        if l["link_type"] not in SPREAD_LINK_TYPES:
            continue
        pairs = [(l["src"], l["dst"])]
        if int(l["bidirectional"]) == 1:
            pairs.append((l["dst"], l["src"]))
        for s, d in pairs:
            adj.setdefault(s, []).append((d, edge_minutes(l, v[d], 1.0)))   # speed applied at run time
    model = {
        "_src": src,
        "ids": ids,
        "v": v,
        "adj": adj,
        "monitored": {a["asset_id"]: flag(a, "monitored") for _, a in assets.iterrows()},
        "zone": dict(zip(assets["asset_id"], assets["zone"])),
        "exposure": dict(zip(assets["asset_id"], assets["exposure"].astype(float))),
        "entries": [a["asset_id"] for _, a in assets.iterrows()
                    if flag(a, "internet_facing") or flag(a, "vendor_access")],
        "services": [(s["name"], compile_rule(s["required_logic"], ids), float(s["buffer_min"]),
                      float(s["population_affected"])) for _, s in tables["services.csv"].iterrows()],
    }
    tables["_model"] = model
    return model


def simulate_full(tables, entry_points, speed=1.0, detection=True):
    """entry_points: {asset_id: start_offset_min}.
    Returns dict: compromised {asset: min}, failures {service name: min}, detected_at, contained_at."""
    m = compile_model(tables)

    INF = float("inf")
    zone = m["zone"]
    cut = {}                 # zone -> minute it is isolated
    global_cut = INF         # minute the whole network is isolated
    detections = []          # (minute, zone or None for network-wide)
    reach, parent = {}, {}
    heap = [(float(off), aid, None) for aid, off in entry_points.items()]
    heapq.heapify(heap)
    while heap:
        t, node, came_from = heapq.heappop(heap)
        if node in reach:
            continue
        if detection:        # blocked if its zone, the zone it came from, or the whole network was isolated first
            if t > global_cut or t > cut.get(zone[node], INF) or (came_from is not None and t > cut.get(zone[came_from], INF)):
                continue
        reach[node] = t
        parent[node] = came_from           # who infected this asset (None = entry point); used for animation
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
            if nxt not in reach:
                heapq.heappush(heap, (t + minutes / speed, nxt, node))

    compromised = reach
    detected_at = contained_at = None
    isolations = []
    if detection and reach:
        detected_at = min(d for d, _ in detections)
        contained_at = detected_at + RESPONSE_DELAY_MIN
        isolations = sorted(([round(at, 1), z] for z, at in cut.items()), key=lambda x: x[0])
        isolations.append([round(global_cut, 1), None])

    order = sorted(compromised.items(), key=lambda kv: kv[1])
    failures = {}
    for name, rule, buffer_min, _pop in m["services"]:
        up = dict.fromkeys(m["ids"], True)
        if not eval(rule, {"__builtins__": {}}, {"up": up}):
            failures[name] = round(buffer_min, 1)       # already broken before the attack
            continue
        for aid, t in order:
            up[aid] = False
            if not eval(rule, {"__builtins__": {}}, {"up": up}):
                failures[name] = round(t + buffer_min, 1)
                break

    return {"compromised": {k: round(t, 1) for k, t in compromised.items()},
            "parents": {k: parent[k] for k in compromised},
            "failures": failures,
            "detected_at": None if detected_at is None else round(detected_at, 1),
            "contained_at": None if contained_at is None else round(contained_at, 1),
            "isolations": [{"at": at, "zone": z} for at, z in isolations]}   # zone None = whole network


def simulate(tables, entry_points, speed=1.0, detection=True):
    """Short form used by tests: returns (compromised, failures)."""
    r = simulate_full(tables, entry_points, speed, detection)
    return r["compromised"], r["failures"]


def report(tables, entry_points, speed=1.0):
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    r = simulate_full(tables, entry_points, speed)
    print(f"\nEntry: {entry_points}  attacker speed: {speed}x")
    print("  Assets compromised (minutes from start):")
    for aid, t in sorted(r["compromised"].items(), key=lambda kv: kv[1]):
        print(f"    T+{t:>6.1f}  {aid} {names[aid]}")
    never = [names[a] for a in names if a not in r["compromised"]]
    if never:
        print("  Not reached / contained in time:", ", ".join(never))
    print(f"  Detected at T+{r['detected_at']}, contained at T+{r['contained_at']}")
    print("  Service failures:", r["failures"] if r["failures"] else "none")


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    entries = compile_model(tables)["entries"] or list(tables["assets.csv"]["asset_id"])
    report(tables, {entries[0]: 0})                       # one entry point
    report(tables, {entries[0]: 0}, speed=2.0)            # attacker twice as fast
    if len(entries) > 1:
        report(tables, {entries[0]: 0, entries[1]: 0})    # two entry points at once
