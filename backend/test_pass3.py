"""Rules for the containment checklist and the sensitivity check. Run from project root:  python backend/test_pass3.py"""
import config
from containment import containment_plan
from fixes import rank_fixes
from load_graph import load_and_validate
from sensitivity import sensitivity

T, _ = load_and_validate()
ENTRIES = [a for a in T["assets.csv"]["asset_id"]]


def test_checklist_is_in_deadline_order():
    for e in ENTRIES:
        items = containment_plan(T, {e: 0})["items"]
        assert [i["deadline"] for i in items] == sorted(i["deadline"] for i in items)


def test_entry_point_action_is_due_now():
    for e in ENTRIES:
        items = containment_plan(T, {e: 0})["items"]
        entry = [i for i in items if i["kind"] == "asset" and i["target"] == e]
        assert entry and entry[0]["deadline"] == 0.0


def test_every_asset_action_is_due_before_the_attacker_arrives():
    for e in ENTRIES:
        for i in containment_plan(T, {e: 0})["items"]:
            if i["kind"] == "asset":
                assert i["deadline"] <= i["arrival"]


def test_sensitivity_covers_every_assumption_both_ways():
    s = sensitivity(T)
    assert s["total"] == len(s["runs"]) == 18
    assert all(len(r["top3"]) == 3 for r in s["runs"])


def test_sensitivity_leaves_assumptions_unchanged_afterwards():
    before = {k: getattr(config, k) for k in dir(config) if k.isupper()}
    ranking_before = list(rank_fixes({k: v for k, v in T.items() if not k.startswith("_")})[1]["fix"])
    sensitivity(T)
    after = {k: getattr(config, k) for k in dir(config) if k.isupper()}
    ranking_after = list(rank_fixes({k: v for k, v in T.items() if not k.startswith("_")})[1]["fix"])
    assert before == after and ranking_before == ranking_after


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
