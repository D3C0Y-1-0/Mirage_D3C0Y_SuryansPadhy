"""Decision insights built on the existing engine (no new physics):
  exposure_score   one 0-100 number for the city, from worst-case and expected harm
  monte_carlo      P10/P50/P90 harm when every assumption is uncertain at the same time (+/-30%)
  attack_paths     crown jewels, the fastest attack paths to each, and the links most paths share
  roadmap          the optimiser's fixes laid out over weeks within staff hours and maintenance windows
  compliance       which control families each fix type relates to (guidance, not certification)
All functions take the tables from load_graph and return plain dicts for the API.
"""
import contextlib
import random
import re

import networkx as nx

import config
from fixes import apply, candidates, patch_outage_harm
from harm import evaluate
from sensitivity import assumption, fresh
from simulate import compile_model

UNCERTAIN = ["MIN_EXPLOIT_FACTOR", "FIREWALL_FACTOR", "SEGMENT_FACTOR", "TTD_MONITORED_MIN",
             "TTD_UNMONITORED_MIN", "RESPONSE_DELAY_MIN", "ENTRY_MIN_V"]     # the harm window itself stays fixed


def max_harm(tables):
    """Every service lost for the whole window: the ceiling the score is measured against."""
    return sum(float(s["population_affected"]) for _, s in tables["services.csv"].iterrows()) * config.HORIZON_MIN


def exposure_score(tables, ev=None):
    ev = ev or evaluate(tables)
    ceiling = max_harm(tables) or 1.0
    w = min(1.0, ev["worst_harm"] / ceiling)
    e = min(1.0, ev["expected_harm"] / ceiling)
    return {"score": round(100 * (0.6 * w + 0.4 * e), 1), "worst_share": round(100 * w, 1), "expected_share": round(100 * e, 1),
            "formula": "100 x (0.6 x worst-case harm + 0.4 x likely harm) / harm if every service were lost for 6 hours"}


# ---------- Monte Carlo ----------
def monte_carlo(tables, runs=200, spread=0.30, seed=7, bundles=None):
    """Sample every uncertain assumption (and attacker speed) uniformly within +/-spread, all at once.
    bundles: {name: [fix dicts]} evaluated with the SAME samples, so before/after comparisons are paired.
    Must not run while other requests simulate (it changes module constants): the API holds the writer lock."""
    rng = random.Random(seed)
    bundles = {"No fixes": [], **(bundles or {})}
    variants = {}
    for name, fx in bundles.items():
        t = tables
        for f in fx:
            t = apply(t, f)
        variants[name] = t
    out = {name: {"worst": [], "expected": []} for name in bundles}
    for _ in range(runs):
        vals = {k: getattr(config, k) * rng.uniform(1 - spread, 1 + spread) for k in UNCERTAIN}
        speed = rng.uniform(1 - spread, 1 + spread)
        with contextlib.ExitStack() as st:
            for k, v in vals.items():
                st.enter_context(assumption(k, v))
            for name, t in variants.items():
                ev = evaluate(fresh(t), speed)
                out[name]["worst"].append(ev["worst_harm"])
                out[name]["expected"].append(ev["expected_harm"])

    def q(xs, p):
        s = sorted(xs)
        return s[min(len(s) - 1, int(p * (len(s) - 1) + 0.5))]

    def hist(xs, bins=16):
        lo, hi = min(xs), max(xs)
        if hi <= lo:
            return [{"from": lo, "to": hi, "n": len(xs)}]
        w = (hi - lo) / bins
        h = [0] * bins
        for x in xs:
            h[min(bins - 1, int((x - lo) / w))] += 1
        return [{"from": lo + i * w, "to": lo + (i + 1) * w, "n": n} for i, n in enumerate(h)]

    res = {}
    for name, d in out.items():
        res[name] = {m: {"p10": q(v, .1), "p50": q(v, .5), "p90": q(v, .9), "min": min(v), "max": max(v), "hist": hist(v)}
                     for m, v in d.items()}
    # paired: in how many samples does each bundle beat doing nothing?
    base = out["No fixes"]["worst"]
    for name in bundles:
        if name != "No fixes":
            res[name]["beats_no_fix_share"] = round(sum(1 for a, b in zip(out[name]["worst"], base) if a < b - 1e-6) / runs, 3)
    return {"runs": runs, "spread": spread, "assumptions": UNCERTAIN + ["attacker speed"], "results": res,
            "note": "Each run draws every assumption at once, uniformly within +/-30%. The 6-hour window is fixed so runs compare."}


# ---------- attack paths ----------
def attack_paths(tables, k=5):
    m = compile_model(tables)
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    g = nx.DiGraph()
    for s, lst in m["adj"].items():
        for d, mins in lst:
            g.add_edge(s, d, weight=mins)
    jewels = {}
    for _, s in tables["services.csv"].iterrows():
        for tok in set(re.findall(r"[A-Za-z0-9_]+", s["required_logic"])):
            if tok in m["ids"]:
                jewels.setdefault(tok, []).append(s["name"])
    entries = m["entries"]
    out, edge_use, total = [], {}, 0
    for j, svcs in sorted(jewels.items()):
        paths = []
        if j not in g:
            out.append({"id": j, "name": names[j], "services": svcs, "paths": []})
            continue
        for e in entries:
            if e == j or e not in g:
                continue
            try:
                for p in _k_paths(g, e, j, 2):
                    paths.append(p)
            except nx.NetworkXNoPath:
                continue
        paths.sort(key=lambda p: p[1])
        paths = paths[:k]
        for nodes, minutes in paths:
            total += 1
            for a, b in zip(nodes, nodes[1:]):
                edge_use[(a, b)] = edge_use.get((a, b), 0) + 1
        out.append({"id": j, "name": names[j], "services": svcs,
                    "paths": [{"nodes": nodes, "names": [names[n] for n in nodes], "minutes": round(minutes, 1),
                               "hop_minutes": [round(g[a][b]["weight"], 1) for a, b in zip(nodes, nodes[1:])],
                               "entry": nodes[0]} for nodes, minutes in paths]})
    links = tables["links.csv"]
    chokes = []
    for (a, b), n in sorted(edge_use.items(), key=lambda kv: -kv[1])[:10]:
        row = links[((links["src"] == a) & (links["dst"] == b)) | ((links["src"] == b) & (links["dst"] == a) & (links["bidirectional"].astype(int) == 1))]
        seg = None if row.empty else int(row.index[0])
        already = (not row.empty) and int(row.iloc[0]["segmented"]) == 1
        chokes.append({"src": a, "dst": b, "src_name": names[a], "dst_name": names[b], "paths": n, "of": total,
                       "fix": None if seg is None or already else f"segment:{seg}", "segmented": already})
    out.sort(key=lambda j: (min([p["minutes"] for p in j["paths"]], default=1e9)))
    return {"crown_jewels": out, "choke_points": chokes, "paths_counted": total,
            "note": "Paths follow network and vendor links only, weighted by the same crossing times the simulation uses."}


def _k_paths(g, s, t, k):
    out = []
    for p in nx.shortest_simple_paths(g, s, t, weight="weight"):
        out.append((p, sum(g[a][b]["weight"] for a, b in zip(p, p[1:]))))
        if len(out) >= k:
            break
    return out


# ---------- roadmap ----------
def roadmap(tables, fixes, staff_per_week=8.0, window_every_weeks=2, weeks=13):
    """Greedy schedule of an ordered fix list: each week has staff_per_week hours; patches that need downtime wait for
    the next maintenance window (every window_every_weeks weeks). Re-evaluates harm after each week."""
    t0 = tables
    base = evaluate(t0)
    sched, t, week, hours_left, i = [], t0, 1, staff_per_week, 0
    plan = []
    pending = list(fixes)
    while pending and week <= weeks:
        fx = pending[0]
        cost = config.FIX_STAFF_HOURS[fx["fix"]]
        needs = fx["fix"] == "patch" and int(t0["assets.csv"].set_index("asset_id").loc[fx["target"], "patchable_without_downtime"]) == 0
        window_ok = (not needs) or (week % window_every_weeks == 0)
        if cost <= hours_left and window_ok:
            plan.append({"week": week, "fix": f"{fx['fix']}:{fx['target']}", "label": fx.get("label", ""), "hours": cost,
                         "needs_window": needs})
            hours_left -= cost
            pending.pop(0)
        else:
            week += 1
            hours_left = staff_per_week
    points = [{"week": 0, "worst": base["worst_harm"], "expected": base["expected_harm"], "score": exposure_score(t0, base)["score"]}]
    t = t0
    for w in range(1, weeks + 1):
        done = [p for p in plan if p["week"] == w]
        for p in done:
            kind, target = p["fix"].split(":", 1)
            t = apply(t, {"fix": kind, "target": int(target) if kind == "segment" else target})
        if done or w in (4, 8, 13):
            ev = evaluate(t)
            points.append({"week": w, "worst": ev["worst_harm"], "expected": ev["expected_harm"], "score": exposure_score(t, ev)["score"]})
    return {"plan": plan, "points": points, "unscheduled": [f"{f['fix']}:{f['target']}" for f in pending],
            "staff_per_week": staff_per_week, "window_every_weeks": window_every_weeks, "weeks": weeks}


# ---------- compliance mapping (for guidance) ----------
COMPLIANCE = {
    "patch": {"nist_800_53": ["SI-2 Flaw remediation", "CM-3 Configuration change control"],
              "iec_62443": ["IEC 62443-2-3 Patch management in the IACS environment"],
              "india": ["CEA Cyber Security Guidelines (power sector): vulnerability and patch management"],
        "mitre_ics": ["M0951 Update Software", "M0916 Vulnerability Scanning"],
        "mitre_techniques": ["T0866 Exploitation of Remote Services", "T0819 Exploit Public-Facing Application"]},
    "harden": {"nist_800_53": ["CM-6 Configuration settings", "CM-7 Least functionality", "IA-2 Identification and authentication (MFA)"],
               "iec_62443": ["IEC 62443-3-3 SR 1.1 Human user identification and authentication", "SR 7.7 Least functionality"],
               "india": ["CEA Cyber Security Guidelines (power sector): secure configuration and access control"],
        "mitre_ics": ["M0932 Multi-factor Authentication", "M0927 Password Policies", "M0942 Disable or Remove Feature or Program"],
        "mitre_techniques": ["T1694.001 Insecure Credentials: Default Credentials", "T0859 Valid Accounts"]},
    "monitor": {"nist_800_53": ["SI-4 System monitoring", "AU-6 Audit record review"],
                "iec_62443": ["IEC 62443-3-3 SR 6.2 Continuous monitoring"],
                "india": ["CERT-In Directions (2022): report cyber incidents within 6 hours of noticing them"],
        "mitre_ics": ["M0947 Audit", "M0931 Network Intrusion Prevention (ATT&CK treats monitoring mainly as detection, not a mitigation)"],
        "mitre_techniques": ["T0886 Remote Services (lateral movement it would see)", "T0867 Lateral Tool Transfer"]},
    "segment": {"nist_800_53": ["SC-7 Boundary protection", "AC-4 Information flow enforcement"],
                "iec_62443": ["IEC 62443-3-2 Zones and conduits", "IEC 62443-3-3 SR 5.1 Network segmentation"],
                "india": ["CEA Cyber Security Guidelines (power sector): network segregation of OT and IT"],
        "mitre_ics": ["M0930 Network Segmentation", "M0937 Filter Network Traffic", "M0807 Network Allowlists"],
        "mitre_techniques": ["T0886 Remote Services", "T0866 Exploitation of Remote Services"]},
    "restrict_exposure": {"nist_800_53": ["SC-7 Boundary protection", "AC-17 Remote access"],
                          "iec_62443": ["IEC 62443-3-3 SR 5.2 Zone boundary protection", "SR 1.13 Access via untrusted networks"],
                          "india": ["CEA Cyber Security Guidelines (power sector): remote access controls"],
        "mitre_ics": ["M0935 Limit Access to Resource Over Network", "M0801 Access Management"],
        "mitre_techniques": ["T0883 Internet Accessible Device", "T0822 External Remote Services"]},
}
COMPLIANCE_NOTE = ("Mapping for guidance only, to show which control families a fix relates to. MITRE ATT&CK for ICS IDs were checked against attack.mitre.org (2026). "
                   "It is not an assessment and does not mean any standard is met.")
