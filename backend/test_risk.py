"""Sanity tests for the risk score. Run from project root:  python backend/test_risk.py
These check rules that must ALWAYS be true, whatever the data is."""
import copy

from load_graph import load_and_validate
from risk import compute_risks


def risk_of(tables, asset_id):
    df = compute_risks(tables)
    return float(df.loc[df["asset_id"] == asset_id, "risk"].iloc[0])


def test_more_exposure_never_lowers_risk():
    tables, _ = load_and_validate()
    for aid in tables["assets.csv"]["asset_id"]:
        low, high = copy.deepcopy(tables), copy.deepcopy(tables)
        low["assets.csv"].loc[low["assets.csv"]["asset_id"] == aid, "exposure"] = 0.1
        high["assets.csv"].loc[high["assets.csv"]["asset_id"] == aid, "exposure"] = 0.9
        assert risk_of(high, aid) >= risk_of(low, aid), f"exposure rule broken for {aid}"


def test_higher_criticality_never_lowers_risk():
    tables, _ = load_and_validate()
    for aid in tables["assets.csv"]["asset_id"]:
        low, high = copy.deepcopy(tables), copy.deepcopy(tables)
        low["assets.csv"].loc[low["assets.csv"]["asset_id"] == aid, "criticality"] = 1
        high["assets.csv"].loc[high["assets.csv"]["asset_id"] == aid, "criticality"] = 5
        assert risk_of(high, aid) >= risk_of(low, aid), f"criticality rule broken for {aid}"


def test_removing_all_cves_never_raises_risk():
    tables, _ = load_and_validate()
    for aid in tables["assets.csv"]["asset_id"]:
        patched = copy.deepcopy(tables)
        patched["assets.csv"].loc[patched["assets.csv"]["asset_id"] == aid, "cve_ids"] = ""
        assert risk_of(patched, aid) <= risk_of(tables, aid), f"patch made risk worse for {aid}"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
