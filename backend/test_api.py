"""API-level rules (calls the endpoint functions directly, so no HTTP client is needed).
Run from project root:  python backend/test_api.py   (any dataset via CASCADE_DATA)."""
from fastapi import HTTPException

import api
from simulate import compile_model

T = api.base_tables()
M = compile_model(T)
ADJ = {(s, d) for s, lst in M["adj"].items() for d, _ in lst}
WORST = api.evaluate(T)["worst_entry"] or M["entries"][0]


def _check_attack(r, entry):
    times, par = r["times"], r["parents"]
    assert set(par) == set(times), "every compromised system has a parent record"
    assert par[entry] is None
    for child, p in par.items():
        if p is None:
            assert child == entry
            continue
        assert (p, child) in ADJ, ("not a real attack link", p, child)
        assert times[child] > times[p], (p, child)
    comp = [e for e in r["events"] if e["kind"] == "compromise"]
    assert {e["asset"] for e in comp} == {k for k, v in times.items() if v <= r["horizon_min"]}
    for s in r["services"]:
        assert s["backup_from"] is None or s["backup_from"] <= s["fail_at"]


def test_public_attack_returns_the_real_spread_tree():
    r = api.public_attack(api.PublicAttack(entry=WORST))
    _check_attack(r, WORST)


def test_public_attack_protected_follows_the_same_rules_and_does_less_harm():
    before = api.public_attack(api.PublicAttack(entry=WORST))
    after = api.public_attack(api.PublicAttack(entry=WORST, protect=True))
    _check_attack(after, WORST)
    assert after["harm"] <= before["harm"] and after["fixes"]


def test_bad_inputs_give_clear_400s():
    for call in (lambda: api.public_attack(api.PublicAttack(entry="NOPE")),
                 lambda: api.run_multi(api.MultiRequest(attackers=[{"id": "A", "entry": "NOPE"}])),
                 lambda: api.run_multi(api.MultiRequest(attackers=[{"id": "A"}])),
                 lambda: api.run_multi(api.MultiRequest(attackers=[])),
                 lambda: api.run_multi(api.MultiRequest(attackers=[{"id": "A", "entry": WORST}, {"id": "A", "entry": WORST}])),
                 lambda: api.run_multi(api.MultiRequest(attackers=[{"id": "A", "entries": [{"asset": "NOPE"}]}])),
                 lambda: api.run_multi(api.MultiRequest(attackers=[{"id": "A", "entry": WORST}], fixes=["nope"]))):
        try:
            call()
        except HTTPException as e:
            assert e.status_code == 400 and e.detail
        else:
            raise AssertionError("expected a 400")


def test_multi_endpoint_accepts_entries_list():
    r = api.run_multi(api.MultiRequest(attackers=[{"id": "A", "entries": [{"asset": WORST, "start": 0},
                                                                          {"asset": M["entries"][-1], "start": 30}]}]))
    assert r["attackers"][0]["entries"][0]["asset"] == WORST and len(r["attackers"]) == 1



def test_electricity_explorer_is_consistent_with_its_model_card():
    """Explorer counts add up, every flag sits at or above the frozen threshold, and the validation confusion
    matrix in the model card matches the samples we serve."""
    import electricity
    if not electricity.available():
        return
    S, mc = electricity.samples(), electricity.model_card()
    tau = mc["attack_threshold"]
    assert all((s["p"][2] >= tau) == s["flag"] for s in S)
    att = [s for s in S if s["label"] == "cyberattack"]
    assert sum(s["flag"] for s in att) == mc["validation_data10_12"]["confusion_rows_true_cols_pred"]["matrix"][2][2]
    assert sum(b["rows"] for b in electricity.explorer()["blocks"]) == len(S)
    call = lambda **kw: api.elec_samples(**{"file": None, "block": None, "label": None, "outcome": None, "flag": None, "offset": 0, "limit": 50, **kw})
    r = call(outcome="attack_missed", limit=5)
    assert r["total"] > 0 and all(x["outcome"] == "attack_missed" and not x["flag"] for x in r["rows"])
    for bad in ({"outcome": "nope"}, {"label": "nope"}):
        try:
            call(**bad)
        except HTTPException as e:
            assert e.status_code == 400
        else:
            raise AssertionError("expected 400")


def test_sector_status_never_claims_an_unapproved_model():
    st = api.ml_sectors()["sectors"]
    dec = {s["sector"]: s["decision"] for s in st}
    assert dec["Water"] == "approved" and dec["Electricity"] == "approved"
    assert all(dec[k] != "approved" for k in ("IoT", "Healthcare", "Telecom", "Transportation"))



def test_model_evaluation_is_untampered_and_consistent():
    ev = api.ml_evaluation()
    for m in ev["models"]:
        fails = [g for g in m["gates"] if g["pass"] is False]
        assert (m["decision"] != "approved") or not fails, m["sector"]           # approved models fail no criterion
        assert (m["decision"] != "no_go") or fails, m["sector"]                  # rejected models show why
    if "iot_demo" in ev:
        d = ev["iot_demo"]
        assert d["declaration_matches"] and d["lock_matches"], "IoT demo declaration or results changed after the run"
        assert d["results"]["gates"]["G3"] is False and "Number" not in d["results"]["features_used"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
