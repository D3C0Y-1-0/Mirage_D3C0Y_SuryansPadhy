"""Water anomaly monitoring: SENTINEL Model C output (historical BATADAL replay) plus an independent rule layer.

Two detection layers, kept separate on purpose:
  Layer 1  ML (Suryans Padhy, SENTINEL Model C, frozen C-1.0.0). A predictive residual model trained on NORMAL
           operation only (BATADAL dataset03). It predicts each tank level and pressure from the previous hours and the
           current pump/valve actuation; a large miss = unexpected behaviour. Because it learns "normal" rather than known
           attacks, it can flag attacks it has never seen. We only READ its frozen outputs; it is not re-run here.
  Layer 2  Safety envelope (this file, no ML). Rules a control engineer would write, learned from a reference period
           with no documented attacks (dataset04, 2016-07-04 to 2016-09-12):
             R1 range      a tank level, pressure or flow outside the range seen in the reference period (+10% margin)
             R2 consistency a pump reported ON with ~no flow, or OFF with flow
             R3 rate       an hourly change larger than any seen in the reference period (+20%)
             R4 frozen     a tank level that does not move for 6 hours while its pump/valve keeps switching
           An episode = any rule for 2 consecutive hours (same persistence as Model C).
Neither layer declares a cyberattack, a compromised device or a failed service. Results are advisory.
The documented BATADAL attack windows are used ONLY to score both layers afterwards, never as an input.
"""
import json
import os
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
WDIR = (ROOT / os.environ.get("CASCADE_WATER", "ml_water")).resolve()
REF_START, REF_END = "2016-07-04 00:00", "2016-09-12 23:00"
PERSIST_H = 2
BANNER = ("HISTORICAL REPLAY of BATADAL dataset04 (C-Town benchmark simulation, 2016). "
          "Not live telemetry and not a real city installation.")
DISCLAIMER = ("Advisory physical-process anomaly. Not a confirmed cyberattack, device compromise or service outage; "
              "requires investigation.")


def available():
    return (WDIR / "events" / "anomaly_events.json").exists()


@lru_cache(maxsize=1)
def model_card():
    return json.loads((WDIR / "MODEL_CARD.json").read_text())


@lru_cache(maxsize=1)
def events():
    return json.loads((WDIR / "events" / "anomaly_events.json").read_text())["events"]


@lru_cache(maxsize=1)
def hourly():
    return pd.read_csv(WDIR / "replay" / "replay_dataset04_hourly.csv", parse_dates=["timestamp"])


@lru_cache(maxsize=1)
def measurements():
    return pd.read_csv(WDIR / "replay" / "measurements_dataset04.csv", parse_dates=["timestamp"])


@lru_cache(maxsize=1)
def mapping():
    return pd.read_csv(WDIR / "signal_asset_mapping.csv", dtype=str).fillna("")


@lru_cache(maxsize=1)
def attack_windows():
    w = pd.read_csv(WDIR / "reference" / "attack_windows_dataset04.csv")
    return [{"id": int(r["attack_id"]), "start": str(r["start"]), "end": str(r["end"]), "description": r["description"]}
            for _, r in w.iterrows()]


@lru_cache(maxsize=1)
def demo():
    return json.loads((WDIR / "demo" / "attack6_historical_replay.json").read_text())


# ---------------- Layer 2: safety envelope ----------------
@lru_cache(maxsize=1)
def envelope():
    m = measurements().set_index("timestamp")
    obs = [c for c in m.columns if not c.startswith("pred_")]
    ref = m.loc[REF_START:REF_END, obs]
    cont = [c for c in obs if c[:2] in ("L_", "P_", "F_") and ref[c].std() > 1e-6]
    lo, hi = ref[cont].min(), ref[cont].max()
    pad = (hi - lo) * 0.10
    lo, hi = lo - pad, hi + pad
    step_max = ref[cont].diff().abs().max() * 1.2 + 1e-6
    pumps = [c[2:] for c in obs if c.startswith("S_") and ref[c].std() > 1e-6 and f"F_{c[2:]}" in m.columns]

    rows = []
    d = m[cont].diff().abs()
    for ts, row in m.iterrows():
        hits = []
        for c in cont:
            v = row[c]
            if v < lo[c] or v > hi[c]:
                hits.append({"rule": "R1 range", "signal": c, "value": round(float(v), 2),
                             "detail": f"{c} = {v:.2f}, normal range {lo[c]:.2f} to {hi[c]:.2f}"})
            dv = d.at[ts, c]
            if pd.notna(dv) and dv > step_max[c]:
                hits.append({"rule": "R3 rate", "signal": c, "value": round(float(dv), 2),
                             "detail": f"{c} changed {dv:.2f} in one hour; the largest normal change is {step_max[c] / 1.2:.2f}"})
        for p in pumps:
            s, f = row[f"S_{p}"], row[f"F_{p}"]
            if (s >= 0.5 and f < 1.0) or (s < 0.5 and f > 1.0):
                hits.append({"rule": "R2 consistency", "signal": f"S_{p}", "value": float(s),
                             "detail": f"{p} reported {'ON' if s >= .5 else 'OFF'} with flow {f:.1f} L/s"})
        rows.append({"timestamp": ts, "hits": hits})
    # R4: a tank level frozen for 6 h while the pumps it controls keep switching
    lv = [c for c in cont if c.startswith("L_")]
    ctrl = {"L_T1": ["S_PU1", "S_PU2"], "L_T3": ["S_PU4", "S_PU5"], "L_T4": ["S_PU6", "S_PU7"], "L_T7": ["S_PU10", "S_PU11"], "L_T2": ["S_V2"]}
    for c in lv:
        frozen = m[c].diff().abs().rolling(6).max() < 1e-9
        sw = [s for s in ctrl.get(c, []) if s in m.columns]
        switching = m[sw].diff().abs().rolling(6).sum().sum(axis=1) > 0 if sw else pd.Series(False, index=m.index)
        for i, ts in enumerate(m.index):
            if frozen.iloc[i] and switching.iloc[i]:
                rows[i]["hits"].append({"rule": "R4 frozen", "signal": c, "value": float(m[c].iloc[i]),
                                        "detail": f"{c} has not moved for 6 h while its pumps/valve keep switching"})
    flag = np.array([bool(r["hits"]) for r in rows])
    alert = flag & np.r_[False, flag[:-1]]           # 2 consecutive hours
    for i, r in enumerate(rows):
        r["alert"] = bool(alert[i])
    eps = _episodes([r["timestamp"] for r in rows], alert, [r["hits"] for r in rows])
    limits = {c: {"low": round(float(lo[c]), 3), "high": round(float(hi[c]), 3)} for c in cont}
    return {"rows": rows, "episodes": eps, "limits": limits, "signals": cont,
            "evaluation": _evaluate([e for e in eps if e["start"] > REF_END], after=REF_END)}


def _episodes(times, alert, hits, merge_gap_h=3):
    eps, cur, gap = [], None, 0
    for t, a, h in zip(times, alert, hits):
        if a:
            if cur is None:
                cur = {"start": str(t), "end": str(t), "hours": 0, "rules": set(), "signals": set()}
            cur["end"] = str(t); cur["hours"] += 1; gap = 0
            for x in h:
                cur["rules"].add(x["rule"]); cur["signals"].add(x["signal"])
        elif cur is not None:
            gap += 1
            if gap > merge_gap_h:
                eps.append(cur); cur = None
    if cur is not None:
        eps.append(cur)
    for e in eps:
        e["rules"], e["signals"] = sorted(e["rules"]), sorted(e["signals"])[:8]
        e["id"] = "ENV-" + e["start"].replace("-", "").replace(" ", "T")[:11]
    return eps


def _evaluate(episodes, after):
    """Score episodes against the documented windows that start after the reference period."""
    wins = [w for w in attack_windows() if w["start"] > after]
    det, lat = {}, {}
    for w in wins:
        hit = [e for e in episodes if e["start"] <= w["end"] and e["end"] >= w["start"]]
        det[w["id"]] = bool(hit)
        if hit:
            first = min(max(pd.Timestamp(e["start"]), pd.Timestamp(w["start"])) for e in hit)
            lat[w["id"]] = int((first - pd.Timestamp(w["start"])).total_seconds() // 3600)
    false = [e for e in episodes if not any(e["start"] <= w["end"] and e["end"] >= w["start"] for w in wins)]
    m = measurements()
    days = (m["timestamp"].max() - pd.Timestamp(after)).total_seconds() / 86400
    return {"attacks_detected": f"{sum(det.values())}/{len(det)}", "detected": det, "latency_h": lat,
            "false_alarm_episodes": len(false), "false_alarms_per_7d": round(7 * len(false) / max(days, 1), 2),
            "scored_period": f"after {after}", "note": "Scored once against the documented BATADAL windows; rules were not tuned to them."}


def ml_evaluation_same_period():
    """Model C episodes scored the same way, for a like-for-like comparison with the rule layer."""
    eps = [{"start": e["timestamp_start"].replace("T", " "), "end": e["timestamp_last_alert"].replace("T", " ")} for e in events()]
    return _evaluate([e for e in eps if e["start"] > REF_END], after=REF_END)


# ---------------- fusion: what the operator console sees each hour ----------------
@lru_cache(maxsize=1)
def fused():
    """Per hour: ML state, rule state, and the resulting operator level.
       watch     = one layer above its threshold, no 2-hour alert yet
       advisory  = one layer alerting (2 h)       -> notify the operator, investigate
       alarm     = both layers alerting, or ML 'high', or a tank level outside its safe range
                   -> page the operator, propose protective actions, failsafe if nobody responds"""
    h = hourly()
    env = envelope()
    out = []
    for i, r in h.iterrows():
        er = env["rows"][i] if i < len(env["rows"]) else {"hits": [], "alert": False}
        ml_alert, ml_hi = bool(r["alert"]), r["severity"] == "high" and bool(r["alert"])
        tank_breach = any(x["rule"] == "R1 range" and x["signal"].startswith("L_") for x in er["hits"])
        rule_alert = er["alert"]
        if (ml_alert and rule_alert) or ml_hi or (rule_alert and tank_breach):
            level = "alarm"
        elif ml_alert or rule_alert:
            level = "advisory"
        elif bool(r["exceeds_threshold"]) or er["hits"]:
            level = "watch"
        else:
            level = "normal"
        out.append(level)
    return out


def hourly_compact(start=None, end=None):
    h = hourly()
    env = envelope()
    lv = fused()
    idx = h.index
    if start:
        idx = h.index[h["timestamp"] >= pd.Timestamp(start)]
    if end:
        idx = [i for i in idx if h.at[i, "timestamp"] <= pd.Timestamp(end)]
    cols = {"t": [], "score": [], "raw": [], "alert": [], "episode": [], "severity": [], "top": [], "zone": [],
            "mapped": [], "rules": [], "rule_alert": [], "level": []}
    for i in idx:
        r = h.loc[i]
        cols["t"].append(str(r["timestamp"])[:16])
        cols["score"].append(float(r["display_score_0_100"]))
        cols["raw"].append(float(r["anomaly_score_raw"]))
        cols["alert"].append(bool(r["alert"]))
        cols["episode"].append("" if pd.isna(r["alert_episode_id"]) else r["alert_episode_id"])
        cols["severity"].append(r["severity"])
        cols["top"].append([{"signal": r[f"top{k}_signal_id"], "observed": float(r[f"top{k}_observed"]),
                             "predicted": float(r[f"top{k}_predicted"]), "z": float(r[f"top{k}_abs_z"]),
                             "zone": r[f"top{k}_hydraulic_zone"], "mapping": r[f"top{k}_mapping_status"],
                             "assets": [] if pd.isna(r[f"top{k}_city_assets"]) else str(r[f"top{k}_city_assets"]).split(";")}
                            for k in (1, 2, 3) if not pd.isna(r[f"top{k}_signal_id"])])
        cols["zone"].append(r["top1_hydraulic_zone"])
        cols["mapped"].append("" if pd.isna(r["top1_city_assets"]) else str(r["top1_city_assets"]))
        cols["rules"].append(env["rows"][i]["hits"][:4])
        cols["rule_alert"].append(env["rows"][i]["alert"])
        cols["level"].append(lv[i])
    return {"banner": BANNER, "disclaimer": DISCLAIMER, "threshold": model_card()["threshold"], **cols}


def signal_series(sig, start=None, end=None):
    m = measurements()
    if sig not in m.columns:
        raise KeyError(sig)
    if start:
        m = m[m["timestamp"] >= pd.Timestamp(start)]
    if end:
        m = m[m["timestamp"] <= pd.Timestamp(end)]
    lim = envelope()["limits"].get(sig)
    pred = f"pred_{sig}"
    return {"signal": sig, "t": [str(x)[:16] for x in m["timestamp"]], "observed": m[sig].round(3).tolist(),
            "predicted": m[pred].round(3).tolist() if pred in m.columns else None, "limits": lim}


def summary():
    ev = events()
    sev = {k: sum(1 for e in ev if e["severity"] == k) for k in ("low", "medium", "high")}
    mapped = sum(1 for e in ev if e["mapping_status"] != "unmapped")
    env = envelope()
    lv = fused()
    return {"available": True, "banner": BANNER, "disclaimer": DISCLAIMER, "model_card": model_card(),
            "events": len(ev), "by_severity": sev, "mapped_events": mapped, "unmapped_events": len(ev) - mapped,
            "hours": len(hourly()), "attack_windows": attack_windows(),
            "reference_period": [REF_START, REF_END],
            "rules": {"episodes": len(env["episodes"]), "evaluation": env["evaluation"]},
            "ml_same_period": ml_evaluation_same_period(),
            "levels": {k: lv.count(k) for k in ("normal", "watch", "advisory", "alarm")},
            "mapping": mapping().to_dict("records")}
