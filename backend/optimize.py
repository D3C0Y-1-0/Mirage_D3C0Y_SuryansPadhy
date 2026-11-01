"""Step 5: budget-constrained fix optimizer with an ADAPTIVE attacker.

Question it answers: "I have N fixes, M maintenance windows and S staff hours. Which combination of fixes
leaves me safest, even if the attacker changes its plan after seeing my fixes?"

How:
  1. Score every single fix, keep the best ~15 (pruning keeps the search fast).
  2. Try every bundle of up to N fixes from that pool that fits the staff budget.
  3. For each bundle, the attacker re-picks its WORST entry point (or worst pair of entry points, for
     simultaneous attacks) against the fixed infrastructure. That worst case is what we minimise.
  4. Patches that need downtime use a maintenance window if one is left (service stays on backup, no harm);
     otherwise their self-inflicted outage harm is added.

Ranking order: lowest worst-case harm, then latest first service failure, then lowest expected harm.
Run from project root:  python backend/optimize.py
"""
import itertools

import pandas as pd

from config import FIX_STAFF_HOURS, HORIZON_MIN
from fixes import candidates, apply, patch_outage_harm
from harm import evaluate, entry_candidates, scenario_harm, fmt_first
from load_graph import load_and_validate
from simulate import simulate_full, compile_model

PRUNE_TO = 15     # how many single fixes go into the bundle search
GREEDY_ABOVE = 4  # bundles larger than this use greedy search instead of trying every combination


def needs_window(tables, fx):
    if fx["fix"] != "patch":
        return False
    a = tables["assets.csv"].set_index("asset_id").loc[fx["target"]]
    return int(a["patchable_without_downtime"]) == 0


def apply_bundle(tables, bundle):
    t = tables
    for fx in bundle:
        t = apply(t, fx)
    return t


def worst_case(tables, simultaneous=1, speed=1.0):
    """The adaptive attacker: tries every entry point (or every combination of `simultaneous` entry points)
    and returns the one that does the most harm. Also returns the earliest failure seen in any attack."""
    entries = entry_candidates(tables)
    k = min(simultaneous, len(entries))
    worst, earliest = None, HORIZON_MIN
    for combo in itertools.combinations(entries, k):
        r = simulate_full(tables, {e: 0 for e in combo}, speed)
        harm = scenario_harm(tables, r["failures"])
        pop = {n: p for n, _r, _b, p in compile_model(tables)["services"]}
        first = min([t for n, t in r["failures"].items() if t < HORIZON_MIN and pop[n] > 0], default=HORIZON_MIN)
        earliest = min(earliest, first)
        if worst is None or (harm, -first) > (worst["harm"], -worst["first_failure_min"]):
            worst = {"entries": combo, "harm": harm, "first_failure_min": first, "failures": r["failures"]}
    if worst is None:
        worst = {"entries": (), "harm": 0.0, "first_failure_min": HORIZON_MIN, "failures": {}}
    worst["earliest_failure_min"] = earliest
    return worst


def score_bundle(tables, bundle, windows, simultaneous, speed=1.0):
    t = apply_bundle(tables, bundle)
    wc = worst_case(t, simultaneous, speed)
    ev = evaluate(t, speed)
    downtime = [fx for fx in bundle if needs_window(tables, fx)]
    unwindowed = downtime[windows:]
    outage = sum(patch_outage_harm(tables, fx["target"]) for fx in unwindowed)
    return {
        "bundle": bundle,
        "labels": [fx["label"] for fx in bundle],
        "worst_harm": wc["harm"] + outage,
        "earliest_failure_min": wc["earliest_failure_min"],
        "expected_harm": ev["expected_harm"] + outage,
        "attacker_entry": wc["entries"],
        "attacker_failures": wc["failures"],
        "windows_used": min(len(downtime), windows),
        "patch_outage_harm": outage,
        "staff_hours": sum(FIX_STAFF_HOURS[fx["fix"]] for fx in bundle),
        "per_entry_harm": {e: p["harm"] for e, p in ev["per_entry"].items()},
    }


def sort_key(s):
    """Lower is better: worst-case harm, then later first failure, then expected harm,
    then cheaper (staff hours), then fewer fixes. Equally safe bundles -> the cheapest wins."""
    return (round(s["worst_harm"]), -s["earliest_failure_min"], round(s["expected_harm"]),
            s["staff_hours"], len(s["bundle"]))


def optimize(tables, max_fixes=3, windows=2, staff_budget=None, simultaneous=1, speed=1.0):
    base = score_bundle(tables, [], windows, simultaneous, speed)

    singles = [score_bundle(tables, [fx], windows, simultaneous, speed) for fx in candidates(tables)]
    if staff_budget is not None:
        singles = [s for s in singles if s["staff_hours"] <= staff_budget]
    by_worst = sorted(singles, key=sort_key)
    by_expected = sorted(singles, key=lambda s: s["expected_harm"])
    # Shortlist. A fix can matter only in combination: closing the second-worst way in does nothing on its own
    # while the worst one is open. So first take the single best fix against EACH way in, then fill up by
    # worst-case and expected-harm rank.
    per_entry_best = []
    for e, base_h in base["per_entry_harm"].items():
        better = [s for s in singles if s["per_entry_harm"].get(e, 0.0) < base_h - 1e-6]
        if better:
            per_entry_best.append(min(better, key=lambda s: (s["per_entry_harm"].get(e, 0.0), s["staff_hours"])))
    pool, seen = [], set()
    for s in per_entry_best + by_worst[:PRUNE_TO - 5] + by_expected[:5] + by_worst[PRUNE_TO - 5:]:
        key = (s["bundle"][0]["fix"], s["bundle"][0]["target"])
        if key not in seen and len(pool) < PRUNE_TO:
            seen.add(key)
            pool.append(s["bundle"][0])

    results = [base] + singles
    if max_fixes <= GREEDY_ABOVE:
        for k in range(2, max_fixes + 1):
            for combo in itertools.combinations(pool, k):
                if staff_budget is not None and sum(FIX_STAFF_HOURS[f["fix"]] for f in combo) > staff_budget:
                    continue
                results.append(score_bundle(tables, list(combo), windows, simultaneous, speed))
    else:
        chosen = []
        for _ in range(max_fixes):
            options = [score_bundle(tables, chosen + [f], windows, simultaneous, speed)
                       for f in pool if f not in chosen]
            if staff_budget is not None:
                options = [o for o in options if o["staff_hours"] <= staff_budget]
            if not options:
                break
            best_step = min(options, key=sort_key)
            chosen = best_step["bundle"]
            results.append(best_step)

    results.sort(key=sort_key)
    return base, results


def pct(before, after):
    return 0.0 if before == 0 else round(100 * (before - after) / before, 1)


def print_report(tables, title, **kw):
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    base, results = optimize(tables, **kw)
    best = results[0]
    who = lambda entries: " + ".join(names[e] for e in entries) or "none"
    print(f"\n=== {title} ===  budget: {kw}")
    print(f"BEFORE: worst case {base['worst_harm']:,.0f} people-min via {who(base['attacker_entry'])}, "
          f"first failure {fmt_first(base['earliest_failure_min'])}, expected {base['expected_harm']:,.0f}")
    print(f"BEST BUNDLE: {best['labels'] or ['do nothing']}")
    print(f"AFTER:  worst case {best['worst_harm']:,.0f} via {who(best['attacker_entry'])}, "
          f"first failure {fmt_first(best['earliest_failure_min'])}, expected {best['expected_harm']:,.0f}")
    print(f"        worst-case harm -{pct(base['worst_harm'], best['worst_harm'])}%, "
          f"expected harm -{pct(base['expected_harm'], best['expected_harm'])}%, "
          f"time bought +{best['earliest_failure_min'] - base['earliest_failure_min']:.0f} min, "
          f"windows used {best['windows_used']}, staff {best['staff_hours']}h, "
          f"patch outage {best['patch_outage_harm']:,.0f}")
    print("Runners-up:")
    for r in results[1:5]:
        print(f"   worst {r['worst_harm']:>10,.0f}  first {fmt_first(r['earliest_failure_min']):>15}  "
              f"exp {r['expected_harm']:>10,.0f}  {r['labels'] or ['do nothing']}")


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    print_report(tables, "One attacker, adaptive entry", max_fixes=3, windows=2, simultaneous=1)
    print_report(tables, "Two simultaneous entry points", max_fixes=3, windows=2, simultaneous=2)
    print_report(tables, "Tight budget: 2 fixes, no maintenance window, 6 staff hours",
                 max_fixes=2, windows=0, staff_budget=6, simultaneous=1)
