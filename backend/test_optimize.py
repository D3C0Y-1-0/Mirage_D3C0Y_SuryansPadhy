"""Rules that must ALWAYS hold for the optimizer. Run from project root:  python backend/test_optimize.py"""
from load_graph import load_and_validate
from optimize import optimize, sort_key

T, _ = load_and_validate()


def test_best_bundle_never_worse_than_doing_nothing():
    base, results = optimize(T, max_fixes=3, windows=2)
    assert sort_key(results[0]) <= sort_key(base)


def test_bigger_budget_never_worse():
    _, r1 = optimize(T, max_fixes=1, windows=2)
    _, r2 = optimize(T, max_fixes=2, windows=2)
    _, r3 = optimize(T, max_fixes=3, windows=2)
    assert sort_key(r2[0]) <= sort_key(r1[0])
    assert sort_key(r3[0]) <= sort_key(r2[0])


def test_staff_budget_is_respected():
    _, results = optimize(T, max_fixes=3, windows=2, staff_budget=5)
    assert all(r["staff_hours"] <= 5 for r in results)


def test_two_entry_points_never_less_harm_than_one():
    base1, _ = optimize(T, max_fixes=1, windows=2, simultaneous=1)
    base2, _ = optimize(T, max_fixes=1, windows=2, simultaneous=2)
    assert base2["worst_harm"] >= base1["worst_harm"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
