"""Recovery model, assumptions register, ATT&CK mapping and the live Modbus testbed.
Run: python backend/test_pass17.py  (or pytest)"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "live"))

import config
import insights
import live
import recovery
from assumptions import register
from harm import evaluate
from load_graph import load_and_validate

T, _ = load_and_validate()


def _entries():
    return list(evaluate(T)["per_entry"].keys())


def test_recovery_schedule_is_feasible():
    for e in _entries():
        for crews in (1, 2, 4):
            for backups in (True, False):
                p = recovery.plan(T, e, crews, backups)
                for j in p["jobs"]:
                    assert j["start"] >= j["ready_at"] - 1e-6, "a system cannot be cleaned before the attacker is cut off from it"
                    assert j["ready_at"] >= j["compromised_at"] - 1e-6
                    assert abs((j["end"] - j["start"]) / 60 - recovery.restore_hours(j["type"], backups)) < .1
                by_crew = {}
                for j in p["jobs"]:
                    by_crew.setdefault(j["crew"], []).append((j["start"], j["end"]))
                for spans in by_crew.values():
                    spans.sort()
                    for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
                        assert b0 >= a1 - 1e-6, "one crew, one system at a time"
                    assert len(by_crew) <= crews
                for s in p["services"]:
                    if s["restored_at"] is not None:
                        assert s["restored_at"] >= s["failed_at"]


def test_recovery_more_crews_or_backups_never_slower():
    e = evaluate(T)["worst_entry"]
    g = {(x["crews"], x["backups"]): x for x in recovery.summary(T, e)["grid"]}
    for b in (True, False):
        assert g[(4, b)]["all_restored_at"] <= g[(2, b)]["all_restored_at"] <= g[(1, b)]["all_restored_at"]
    for c in (1, 2, 4):
        assert g[(c, True)]["all_restored_at"] <= g[(c, False)]["all_restored_at"]
        assert g[(c, True)]["people_hours"] <= g[(c, False)]["people_hours"]


def test_assumptions_register_lists_every_config_number():
    names = {r["name"] for r in register()["rows"]}
    for k in ("MIN_EXPLOIT_FACTOR", "FIREWALL_FACTOR", "SEGMENT_FACTOR", "TTD_MONITORED_MIN", "TTD_UNMONITORED_MIN",
              "RESPONSE_DELAY_MIN", "HORIZON_MIN", "ENTRY_MIN_V", "FIX_STAFF_HOURS", "OPERATOR_ACK_MIN", "RESTORE_HOURS"):
        assert k in names
    for r in register()["rows"]:
        assert r["basis"] and r["tested"]
    assert register()["rows"][0]["value"] == config.MIN_EXPLOIT_FACTOR


def test_attack_mapping_uses_current_ids():
    for fx, m in insights.COMPLIANCE.items():
        assert m["mitre_ics"] and all(x.startswith("M0") for x in m["mitre_ics"]), fx
        assert m["mitre_techniques"] and all(x.startswith("T") for x in m["mitre_techniques"]), fx
        assert not any("T0855" in x for x in m["mitre_techniques"])     # superseded by T1692.001
    for sev, tech, mit in live.RULES.values():
        assert tech.startswith("T") and mit.startswith("M")


def test_live_testbed_detects_isolates_and_recovers():
    import attack
    old = live.BASELINE_S, live.ACK_S
    live.BASELINE_S, live.ACK_S = 4.5, 3
    try:
        d = live.LiveDevice("127.0.0.1", 0, "X1", "test controller").start()
        assert d.error is None and d.port
        time.sleep(6)
        assert d.snapshot()["baseline"]["learned"] and "1" in d.snapshot()["baseline"]["range"]
        assert d.incident is None
        c = attack.Client("127.0.0.1", d.port)
        v, e = c.read_hr(0)
        assert v and not e
        assert c.write_hr(0, 5) == "illegal address"                    # the level is read-only
        assert d.incident is not None                                   # ...but trying is still an unknown write
        assert c.write_hr(1, 520) is None
        assert c.write_coil(1, False) is None
        rules = {a["rule"] for a in d.alerts}
        assert {"new_master", "unknown_write", "out_of_range", "alarm_off"} <= rules
        time.sleep(live.ACK_S + 1.5)                                     # nobody answers: the failsafe isolates
        s = d.snapshot()
        assert s["incident"]["state"] == "isolated" and s["incident"]["decided_by"] == "failsafe"
        try:
            c.write_hr(1, 530)
            refused = False
        except (ConnectionError, OSError):
            refused = True
        assert refused, "the attacker's connection must be closed once isolated"
        assert d.hr[1] == 520                                            # isolation stops the attacker, it does not undo him
        d.restore()
        assert d.hr[1] == live.GOOD["hr"][1] and d.co[1] == 1 and d.co[2] == 0
        assert d.snapshot()["status"] == "recovered"
    finally:
        live.BASELINE_S, live.ACK_S = old


def test_live_controls_are_guarded():
    from fastapi.testclient import TestClient
    import api
    c = TestClient(api.app)            # no startup: the guard must answer before the testbed is even looked at
    for path, body in (("/api/live/decide", {"decision": "isolate"}), ("/api/live/restore", None), ("/api/live/close", None), ("/api/live/sis", {"on": False})):
        r = c.post(path, json=body) if body is not None else c.post(path)
        assert r.status_code == 401, (path, r.status_code)          # not loopback, not signed in
        r = c.post(path, json=body or {}, headers={"Origin": "https://evil.example"})
        assert r.status_code == 403, (path, r.status_code)          # cross-site


def test_live_is_off_on_cloud_hosts_and_local_by_default():
    old = {k: os.environ.get(k) for k in ("RENDER", "CASCADE_LIVE", "CASCADE_LIVE_HOST", "CASCADE_LIVE_ALLOW_LAN")}
    try:
        for k in old:
            os.environ.pop(k, None)
        assert live.enabled_reason()[0] and live.bind_host() == "127.0.0.1"
        os.environ["RENDER"] = "true"
        assert not live.enabled_reason()[0]
        os.environ["CASCADE_LIVE"] = "1"
        assert live.enabled_reason()[0]
        os.environ["CASCADE_LIVE_HOST"] = "0.0.0.0"
        assert live.bind_host() == "127.0.0.1"                      # LAN needs the second, explicit switch
        os.environ["CASCADE_LIVE_ALLOW_LAN"] = "1"
        assert live.bind_host() == "0.0.0.0"
    finally:
        for k, v in old.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("ok", name)
