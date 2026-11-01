"""Rules for the water monitoring layer. Run from project root:  python backend/test_water.py"""
import water


def test_package_present_and_labelled_historical():
    assert water.available()
    h = water.hourly_compact()
    assert "HISTORICAL REPLAY" in h["banner"] and "Not live telemetry" in h["banner"]


def test_ml_events_never_claim_compromise_or_exploit_prob():
    for e in water.events():
        must_not = e["risk_engine_evidence"]["must_not_be_used_as"]
        assert {"device_compromise", "service_outage", "exploit_prob"} <= set(must_not)


def test_mapped_assets_only_from_mapping_file():
    allowed = {a for row in water.mapping().to_dict("records") for a in row["mapped_city_asset_ids"].split(";") if a}
    assert allowed == {"WA01", "WA04"}
    for e in water.events():
        assert set(e["mapped_city_asset_ids"]) <= allowed


def test_rule_layer_uses_only_the_reference_period_for_limits():
    env = water.envelope()
    m = water.measurements().set_index("timestamp").loc[water.REF_START:water.REF_END]
    for sig, lim in env["limits"].items():          # every reference value sits inside its own limits
        assert m[sig].min() >= lim["low"] - 1e-6 and m[sig].max() <= lim["high"] + 1e-6


def test_alarm_needs_two_hours_and_levels_are_known():
    lv = water.fused()
    assert set(lv) <= {"normal", "watch", "advisory", "alarm"}
    rows = water.envelope()["rows"]
    for i, r in enumerate(rows):
        if r["alert"]:
            assert r["hits"] and rows[i - 1]["hits"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
