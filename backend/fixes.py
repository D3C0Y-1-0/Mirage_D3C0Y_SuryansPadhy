"""Step 4b: fix engine. Answers 'which fix first, how much risk does it remove, how many minutes does it buy?'

Every fix is just an EDIT to the data, then we re-run harm.evaluate():
    patch   -> remove the asset's CVEs
    harden  -> remove config weaknesses (default creds, no MFA, ...)
    monitor -> mark the asset monitored (fast detection, so containment starts earlier)
    segment -> mark a link segmented (much slower to cross)

Patching OT has its own cost: if the asset needs downtime, it is offline for the patch, and services that depend on
it can go down. That self-inflicted harm is measured in the SAME people-minutes and subtracted (the 'net' column).
Run from project root:  python backend/fixes.py
"""
import copy

import pandas as pd

from config import FIX_STAFF_HOURS, HORIZON_MIN, RESTRICT_EXPOSURE_ZONES
from harm import evaluate, fmt_first
from load_graph import load_and_validate, split_list
from risk import service_up
from simulate import flag, SPREAD_LINK_TYPES


def candidates(tables):
    out = []
    for _, a in tables["assets.csv"].iterrows():
        aid, name = a["asset_id"], a["name"]
        if split_list(a["cve_ids"]):
            out.append({"fix": "patch", "target": aid, "label": f"Patch {name}"})
        if split_list(a["config_flags"]):
            out.append({"fix": "harden", "target": aid, "label": f"Harden {name} ({a['config_flags']})"})
        if not flag(a, "monitored"):
            out.append({"fix": "monitor", "target": aid, "label": f"Monitor {name}"})
        if (flag(a, "internet_facing") or flag(a, "vendor_access")) and a["zone"] in RESTRICT_EXPOSURE_ZONES:
            out.append({"fix": "restrict_exposure", "target": aid, "label": f"Remove direct internet access to {name}"})
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    for i, l in tables["links.csv"].iterrows():
        if l["link_type"] in SPREAD_LINK_TYPES and not int(l["segmented"]):
            out.append({"fix": "segment", "target": i,
                        "label": f"Segment {names.get(l['src'], l['src'])} to {names.get(l['dst'], l['dst'])}"})
    return out


def apply(tables, fix):
    """Return a NEW copy of the data with one fix applied. The original is untouched.
    Keys starting with '_' (the compiled-model cache) are NOT copied, so the copy is recompiled fresh."""
    t = {k: copy.deepcopy(v) for k, v in tables.items() if not k.startswith("_")}
    assets = t["assets.csv"]
    if fix["fix"] == "segment":
        t["links.csv"].loc[fix["target"], "segmented"] = 1
        return t
    row = assets["asset_id"] == fix["target"]
    if fix["fix"] == "patch":
        assets.loc[row, "cve_ids"] = ""
    elif fix["fix"] == "harden":
        assets.loc[row, "config_flags"] = ""
    elif fix["fix"] == "monitor":
        assets["monitored"] = assets.get("monitored", 0)
        assets["monitored"] = assets["monitored"].fillna(0)
        assets.loc[row, "monitored"] = 1
    elif fix["fix"] == "restrict_exposure":       # behind a private network: no longer a way in from outside
        assets.loc[row, ["internet_facing", "vendor_access"]] = 0
    return t


def patch_outage_harm(tables, asset_id):
    """People-minutes lost because the patch itself takes the asset offline (OT reality)."""
    a = tables["assets.csv"].set_index("asset_id").loc[asset_id]
    if int(a["patchable_without_downtime"]) == 1:
        return 0.0
    outage = float(a["downtime_hours_to_patch"]) * 60
    ids = set(tables["assets.csv"]["asset_id"])
    harm = 0.0
    for _, s in tables["services.csv"].iterrows():
        if not service_up(s["required_logic"], {asset_id}, ids):
            harm += float(s["population_affected"]) * max(0.0, min(outage, HORIZON_MIN) - float(s["buffer_min"]))
    return harm


def rank_fixes(tables, speed=1.0):
    base = evaluate(tables, speed)
    rows = []
    for fx in candidates(tables):
        after = evaluate(apply(tables, fx), speed)
        reduction = base["expected_harm"] - after["expected_harm"]
        outage = patch_outage_harm(tables, fx["target"]) if fx["fix"] == "patch" else 0.0
        note = ""
        if fx["fix"] == "patch" and outage > 0:
            note = "Patch outage hurts services: use a maintenance window, or segment/monitor instead"
        elif fx["fix"] == "patch" and not flag(tables["assets.csv"].set_index("asset_id").loc[fx["target"]],
                                                "patchable_without_downtime"):
            note = "Needs downtime, but no service is lost while it is patched"
        if reduction < 0:
            note = ("Makes things worse in this model: it slows the attacker on the way to a monitored system, "
                    "so the alarm goes off later")
        rows.append({
            "fix": fx["label"], "type": fx["fix"],
            "risk_reduction_pct": round(100 * reduction / base["expected_harm"], 1) if base["expected_harm"] else 0.0,
            "worst_case_reduction_pct": round(100 * (base["worst_harm"] - after["worst_harm"]) / base["worst_harm"], 1)
                                         if base["worst_harm"] else 0.0,
            "minutes_bought": round(after["first_failure_min"] - base["first_failure_min"], 1),
            "patch_outage_harm": round(outage),
            "net_benefit": round(reduction - outage),
            "staff_hours": FIX_STAFF_HOURS[fx["fix"]],
            "note": note,
        })
    df = pd.DataFrame(rows).sort_values(["net_benefit", "minutes_bought"], ascending=False).reset_index(drop=True)
    return base, df


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    base, df = rank_fixes(tables)
    print(f"BEFORE any fix: expected harm {base['expected_harm']:,.0f} people-min, "
          f"worst case {base['worst_harm']:,.0f} (entry {base['worst_entry']}), "
          f"first failure {fmt_first(base['first_failure_min'])}\n")
    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 60)
    print(df.to_string(index=False))
