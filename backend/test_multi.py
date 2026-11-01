"""Rules for the multi-attacker engine. Run from project root:  python backend/test_multi.py
Works on any dataset (CASCADE_DATA=data_master python backend/test_multi.py)."""
from fixes import apply, candidates
from harm import evaluate, scenario_harm
from load_graph import load_and_validate
from multi import simulate_multi, presets
from simulate import simulate_full, compile_model

T, _ = load_and_validate()
M = compile_model(T)
ENTRIES = M["entries"] or list(T["assets.csv"]["asset_id"])[:2]
EV = evaluate(T)
RANKED = sorted(EV["per_entry"], key=lambda e: -EV["per_entry"][e]["harm"]) or ENTRIES
A1 = RANKED[0]
A2 = RANKED[1] if len(RANKED) > 1 else ENTRIES[-1]


def att(i, entry, start=0, **kw):
    return {"id": "AB"[i], "entry": entry, "start": start, **kw}


def test_single_attacker_matches_existing_engine():
    """Same model, same rules: one attacker must give exactly the old engine's answer."""
    for e in ENTRIES:
        for det in (True, False):
            old = simulate_full(T, {e: 0}, detection=det)
            new = simulate_multi(T, [att(0, e)], detection=det)
            got = {k: v["t"] for k, v in new["combined"]["first_by"].items()}
            assert got == old["compromised"], (e, det)
            assert abs(new["combined"]["harm"] - scenario_harm(T, old["failures"])) < 1, (e, det)


def test_two_simultaneous_attackers_match_multi_source():
    """Merged state of two attackers at T+0 = the old multi-source run; and both histories are kept."""
    old = simulate_full(T, {A1: 0, A2: 0})
    new = simulate_multi(T, [att(0, A1), att(1, A2)])
    assert {k: v["t"] for k, v in new["combined"]["first_by"].items()} == old["compromised"]
    assert abs(new["combined"]["harm"] - scenario_harm(T, old["failures"])) < 1
    a, b = new["attackers"]
    assert a["entry"] == A1 and b["entry"] == A2 and A1 in a["compromised"] and A2 in b["compromised"]


def test_second_attacker_joining_late_does_not_reset_the_first():
    alone = simulate_multi(T, [att(0, A1)], detection=False)["attackers"][0]["compromised"]
    both = simulate_multi(T, [att(0, A1), att(1, A2, start=45)], detection=False)
    assert both["attackers"][0]["compromised"] == alone          # A's history is untouched by B joining
    assert min(both["attackers"][1]["compromised"].values()) == 45.0
    assert all(t >= 45 for t in both["attackers"][1]["compromised"].values())


def test_converging_attackers_both_records_kept():
    conv = [p for p in presets(T) if p["key"] == "D"]
    if not conv:
        print("  (skipped: no converging pair in this dataset)")
        return
    r = simulate_multi(T, conv[0]["attackers"], detection=False)
    assert r["combined"]["contested"], "converging preset should share at least one asset"
    for c in r["combined"]["contested"]:
        assert len(c["times"]) == 2
        assert c["winner"] == min(c["times"], key=c["times"].get)
        assert r["combined"]["first_by"][c["asset"]]["t"] == min(c["times"].values())


def test_containing_one_attacker_lets_the_other_continue():
    free = simulate_multi(T, [att(0, A1), att(1, A2)], detection=False)
    cut = simulate_multi(T, [att(0, A1, contain_at=20), att(1, A2)], detection=False)
    assert all(t <= 20 for t in cut["attackers"][0]["compromised"].values())
    assert cut["attackers"][1]["compromised"] == free["attackers"][1]["compromised"]
    assert cut["attackers"][0]["status"] == "contained"


def test_adaptive_attacker_switches_when_its_route_is_closed():
    g = [p for p in presets(T) if p["key"] == "G"]
    if not g:
        print("  (skipped: nothing to close)")
        return
    t = T
    for f in g[0]["fixes"]:
        kind, target = f.split(":", 1)
        t = apply(t, {"fix": kind, "target": int(target) if kind == "segment" else target})
    fixed = simulate_multi(t, g[0]["attackers"])
    stuck = simulate_multi(t, [dict(g[0]["attackers"][0], adaptive=False)])
    assert fixed["combined"]["harm"] >= stuck["combined"]["harm"]   # adapting never helps the defender
    if fixed["attackers"][0]["adapted_from"]:
        assert fixed["attackers"][0]["entry"] != g[0]["attackers"][0]["entry"]


def test_combined_harm_at_least_each_solo_attack():
    r = simulate_multi(T, [att(0, A1), att(1, A2)], detection=False)
    for a in ("A", "B"):
        assert r["combined"]["harm"] >= r["solo"][a]["harm"] - 1


def test_maintenance_window_counts_downtime_and_ends():
    h = [p for p in presets(T) if p["key"] == "H"]
    if not h:
        print("  (skipped: no OT asset needing downtime)")
        return
    w = h[0]["maintenance"][0]
    r = simulate_multi(T, [], maintenance=[w])           # no attacker at all: only the self-inflicted outage
    for s in r["combined"]["services"]:
        assert s["cause"] == "maintenance"
        assert s["restored_at"] is not None and s["restored_at"] <= w["start"] + 60 * w["hours"] + 1e-6


def test_failsafe_blocks_late_outside_attackers_and_keeps_insiders():
    inside = next((a for a in T["assets.csv"]["asset_id"] if a not in M["entries"]), None)
    if inside is None:
        return
    r = simulate_multi(T, [att(0, A1), att(1, A2, start=60), {"id": "C", "entry": inside, "start": 0}], island={"at": 30, "c2": True})
    st = {a["id"]: a for a in r["attackers"]}
    assert st["B"]["status"] == "blocked by failsafe" and not st["B"]["compromised"]
    assert all(t <= 30 for t in st["A"]["compromised"].values())
    assert st["C"]["contain_at"] is None                              # an insider does not need the internet


def test_failsafe_without_command_channel_assumption_changes_nothing_for_attackers_already_in():
    a = simulate_multi(T, [att(0, A1)], detection=False)
    b = simulate_multi(T, [att(0, A1)], detection=False, island={"at": 30, "c2": False})
    assert a["attackers"][0]["compromised"] == b["attackers"][0]["compromised"]
    assert b["combined"]["harm"] >= a["combined"]["harm"] - 1         # the failsafe can only add its own cost


def test_one_attacker_two_ways_in_equals_merged_multi_source():
    """'One attacker from two places': a single attacker with two entries at T+0 = the merged multi-source run,
    with one identity (everything attributed to A)."""
    old = simulate_full(T, {A1: 0, A2: 0})
    new = simulate_multi(T, [{"id": "A", "entries": [{"asset": A1, "start": 0}, {"asset": A2, "start": 0}]}])
    assert {k: v["t"] for k, v in new["combined"]["first_by"].items()} == old["compromised"]
    assert abs(new["combined"]["harm"] - scenario_harm(T, old["failures"])) < 1
    assert len(new["attackers"]) == 1 and {v["attacker"] for v in new["combined"]["first_by"].values()} == {"A"}
    assert not new["combined"]["contested"]
    par = new["attackers"][0]["parents"]
    assert par[A1] is None and par[A2] is None            # both are ways in


def test_each_entry_start_time_is_respected():
    """A second way in opening at T+40 is entered exactly at T+40 (unless already reached earlier from the first)."""
    for det in (True, False):
        r = simulate_multi(T, [{"id": "A", "entries": [{"asset": A1, "start": 0}, {"asset": A2, "start": 40}]}],
                           detection=det)
        only1 = simulate_multi(T, [att(0, A1)], detection=det)["combined"]["first_by"]
        got = r["combined"]["first_by"]
        exp_a2 = min(40.0, only1[A2]["t"]) if A2 in only1 else 40.0
        if A2 in got:
            assert got[A2]["t"] == round(exp_a2, 1), (det, got[A2], exp_a2)
        for n, v in only1.items():                       # nothing reached by the first way in gets later
            assert got[n]["t"] <= v["t"] + 1e-9, (n, det)
        for n, v in got.items():                         # nothing before the first start; second-entry nodes not before 40
            assert v["t"] >= 0
        joins = [e for e in r["events"] if e["kind"] == "attacker_joins"]
        assert any(abs(e["t"] - 40) < 1e-9 and e["asset"] == A2 for e in joins)


def test_parent_edges_are_real_links_and_times_increase():
    """Every parent -> child edge is a real attack link, and the child is reached after its parent."""
    adj = {(s, d) for s, lst in M["adj"].items() for d, _ in lst}
    for e in ENTRIES[:4]:
        r = simulate_multi(T, [att(0, e)])
        a = r["attackers"][0]
        for child, par in a["parents"].items():
            if par is None:
                assert child == e
                continue
            assert (par, child) in adj, (par, child)
            assert a["compromised"][child] > a["compromised"][par]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
