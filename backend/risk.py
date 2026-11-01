"""Step 2: per-asset risk score (first version, no attack simulation yet).

Risk = 100 * Likelihood * Impact
  Vulnerability V : combines all CVEs on the asset + config weaknesses
  Likelihood    L : V scaled by how exposed the asset is
  Impact        I : criticality + how much of the service population is lost if THIS asset alone goes down
Run from project root:  python backend/risk.py
"""
import re

import pandas as pd

from load_graph import load_and_validate, split_list

CONFIG_FLAG_BOOST = 0.05   # each config weakness adds this to V (assumption, tunable)
W_CRITICALITY = 0.4        # weight of criticality in impact (assumption, tunable)
W_CONSEQUENCE = 0.6        # weight of service consequence in impact (assumption, tunable)
DEFAULT_EXPLOIT_PROB = 0.05


def cve_exploit_prob(row):
    """Probability a CVE gets exploited. Uses the ML column `exploit_prob` when your teammate adds it,
    otherwise falls back to: KEV-listed -> 0.9, else EPSS, else a small default."""
    if "exploit_prob" in row.index and not pd.isna(row["exploit_prob"]):
        return float(row["exploit_prob"])
    if int(row["kev"]) == 1:
        return 0.9
    if not pd.isna(row["epss"]):
        return float(row["epss"])
    return DEFAULT_EXPLOIT_PROB


def vulnerability_score(cve_ids, flags, vulns_by_id):
    """V = 1 - product(1 - p * cvss/10) over the asset's CVEs, plus a small boost per config weakness."""
    survive = 1.0
    for cid in cve_ids:
        v = vulns_by_id[cid]
        survive *= 1 - cve_exploit_prob(v) * float(v["cvss"]) / 10
    return min(1.0, (1 - survive) + CONFIG_FLAG_BOOST * len(flags))


def service_up(logic, down, known_ids):
    """Evaluate a service rule like 'A05 AND (A06 OR A07)' when the assets in `down` are lost."""
    parts = []
    for tok in re.findall(r"[A-Za-z0-9_]+|\(|\)", logic):
        if tok.upper() in ("AND", "OR", "NOT"):
            parts.append(tok.lower())
        elif tok in ("(", ")"):
            parts.append(tok)
        elif tok in known_ids:
            parts.append("False" if tok in down else "True")
        else:
            raise ValueError(f"services.csv: rule '{logic}' mentions unknown asset '{tok}'")
    return bool(eval(" ".join(parts), {"__builtins__": {}}, {}))


def compute_risks(tables):
    assets, services, vulns = tables["assets.csv"], tables["services.csv"], tables["vulns.csv"]
    vulns_by_id = {r["cve_id"]: r for _, r in vulns.iterrows()}
    ids = set(assets["asset_id"])
    total_pop = float(services["population_affected"].sum()) or 1.0

    rows = []
    for _, a in assets.iterrows():
        v = vulnerability_score(split_list(a["cve_ids"]), split_list(a["config_flags"]), vulns_by_id)
        likelihood = min(1.0, v * (0.4 + 0.6 * float(a["exposure"])))

        lost_pop = 0.0
        broken = []
        for _, s in services.iterrows():
            if not service_up(s["required_logic"], {a["asset_id"]}, ids):
                lost_pop += float(s["population_affected"])
                broken.append(s["name"])
        consequence = lost_pop / total_pop
        impact = W_CRITICALITY * (float(a["criticality"]) / 5) + W_CONSEQUENCE * consequence

        rows.append({
            "asset_id": a["asset_id"], "name": a["name"],
            "V": round(v, 3), "L": round(likelihood, 3),
            "consequence": round(consequence, 3), "impact": round(impact, 3),
            "risk": round(100 * likelihood * impact, 1),
            "breaks_alone": "; ".join(broken),
        })
    return pd.DataFrame(rows).sort_values("risk", ascending=False).reset_index(drop=True)


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    pd.set_option("display.width", 160)
    print(compute_risks(tables).to_string(index=False))
