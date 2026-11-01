"""Rules that must ALWAYS hold for the simulation. Run from project root:  python backend/test_simulate.py
Spread rules are checked with detection OFF (pure spread). Detection rules are checked separately."""
from fixes import apply
from harm import evaluate
from load_graph import load_and_validate
from simulate import simulate, compile_model

T, _ = load_and_validate()
ALL = list(T["assets.csv"]["asset_id"])


def test_entry_point_is_compromised_at_its_start_time():
    for a in ALL:
        comp, _ = simulate(T, {a: 0})
        assert comp[a] == 0


def test_faster_attacker_never_slower():
    for a in ALL:
        slow, _ = simulate(T, {a: 0}, speed=1.0, detection=False)
        fast, _ = simulate(T, {a: 0}, speed=2.0, detection=False)
        for k in slow:
            assert fast[k] <= slow[k] + 0.11, f"{a}->{k}"


def test_more_entry_points_never_slower():
    for a in ALL:
        for b in ALL:
            one, _ = simulate(T, {a: 0}, detection=False)
            two, _ = simulate(T, {a: 0, b: 0}, detection=False)
            for k in one:
                assert two[k] <= one[k] + 0.11


def test_segmenting_a_link_never_speeds_attacker_up():
    for e in compile_model(T)["entries"] or ALL[:1]:     # every real entry point, no hard-coded IDs
        base, _ = simulate(T, {e: 0}, detection=False)
        for i in T["links.csv"].index:
            cut, _ = simulate(apply(T, {"fix": "segment", "target": i}), {e: 0}, detection=False)
            for k, t in cut.items():
                assert t >= base[k] - 0.11


def test_removing_exposure_never_increases_harm():
    from fixes import candidates
    base = evaluate(T)
    for fx in [f for f in candidates(T) if f["fix"] == "restrict_exposure"]:
        after = evaluate(apply(T, fx))
        assert after["expected_harm"] <= base["expected_harm"] + 1e-6 and after["worst_harm"] <= base["worst_harm"] + 1e-6, fx["label"]


def test_detection_never_adds_compromised_assets():
    for a in ALL:
        without, _ = simulate(T, {a: 0}, detection=False)
        with_det, _ = simulate(T, {a: 0}, detection=True)
        assert set(with_det) <= set(without)


def test_monitoring_never_increases_expected_harm():
    base = evaluate(T)["expected_harm"]
    for a in ALL:
        after = evaluate(apply(T, {"fix": "monitor", "target": a}))["expected_harm"]
        assert after <= base + 1e-6, f"monitoring {a} increased harm"


def test_patch_and_harden_never_increase_expected_harm():
    base = evaluate(T)["expected_harm"]
    for a in ALL:
        for kind in ("patch", "harden"):
            after = evaluate(apply(T, {"fix": kind, "target": a}))["expected_harm"]
            assert after <= base + 1e-6, f"{kind} {a} increased harm"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
