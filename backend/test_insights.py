"""Rules for the insight layer. Run from project root:  python backend/test_insights.py"""
import json

from fixes import apply, candidates
from harm import evaluate
from insights import exposure_score, monte_carlo, attack_paths, roadmap, COMPLIANCE
from load_graph import load_and_validate

T, _ = load_and_validate()


def test_exposure_score_is_bounded_and_falls_with_a_good_fix():
    s0 = exposure_score(T)["score"]
    assert 0 <= s0 <= 100
    best = min(candidates(T), key=lambda f: evaluate(apply(T, f))["worst_harm"])
    assert exposure_score(apply(T, best))["score"] <= s0 + 1e-9


def test_monte_carlo_is_ordered_and_reproducible():
    a = monte_carlo(T, runs=20)
    b = monte_carlo(T, runs=20)
    r = a["results"]["No fixes"]["worst"]
    assert r["p10"] <= r["p50"] <= r["p90"]
    assert a["results"] == b["results"]                       # fixed seed
    import config                                             # assumptions are restored afterwards
    assert config.SEGMENT_FACTOR == 6.0 and config.TTD_MONITORED_MIN == 10


def test_attack_paths_start_at_entries_and_use_attack_links_only():
    from simulate import compile_model
    m = compile_model(T)
    for j in attack_paths(T)["crown_jewels"]:
        for p in j["paths"]:
            assert p["nodes"][0] in m["entries"] and p["nodes"][-1] == j["id"]
            for a, b in zip(p["nodes"], p["nodes"][1:]):
                assert any(d == b for d, _ in m["adj"].get(a, []))


def test_roadmap_respects_staff_hours_and_windows():
    fx = candidates(T)[:6]
    r = roadmap(T, fx, staff_per_week=4, window_every_weeks=2)
    by_week = {}
    for p in r["plan"]:
        by_week[p["week"]] = by_week.get(p["week"], 0) + p["hours"]
        if p["needs_window"]:
            assert p["week"] % 2 == 0
    assert all(h <= 4 for h in by_week.values())


def test_every_fix_type_has_a_guidance_mapping():
    assert {f["fix"] for f in candidates(T)} <= set(COMPLIANCE)


def test_audit_chain_detects_tampering():
    import api
    import hashlib
    prev, lines = "0" * 64, []
    for i in range(3):
        rec = {"context": "c", "action": f"a{i}", "decision": "note", "reason": "", "sim_time": None, "by": "t", "at": "x", "prev": prev}
        rec["hash"] = hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        prev = rec["hash"]; lines.append(json.dumps(rec))
    assert api.verify_audit_chain(lines)["ok"]
    bad = json.loads(lines[1]); bad["action"] = "edited"; lines[1] = json.dumps(bad)
    assert not api.verify_audit_chain(lines)["ok"]
    assert not api.verify_audit_chain([lines[0], lines[2]])["ok"]          # a deleted entry breaks it too


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
