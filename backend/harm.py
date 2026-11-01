"""Step 4a: ONE definition of risk = expected harm in PEOPLE-MINUTES.

For one attack scenario:
    harm = sum over failed services of  population x minutes of outage inside the 6-hour window
Over all possible entry points:
    expected harm = sum over entry points of  P(entry used) x harm(that entry)
    P(entry used) = exposure x vulnerability   (a likelihood weight, an assumption)
    worst-case harm = the single worst entry point (what an adaptive attacker would pick)

'Risk reduction %' for any fix = how much it lowers expected harm. Same unit for every fix.
Run from project root:  python backend/harm.py
"""
from config import HORIZON_MIN, ENTRY_MIN_V
from load_graph import load_and_validate
from simulate import simulate_full, compile_model


def entry_candidates(tables):
    """Assets an outside attacker can start from: internet-facing or reachable by a vendor."""
    return list(compile_model(tables)["entries"])


def entry_probs(tables):
    m = compile_model(tables)
    return {e: min(1.0, m["exposure"][e] * max(m["v"][e], ENTRY_MIN_V)) for e in m["entries"]}


def scenario_harm(tables, failures):
    pop = {name: p for name, _rule, _buf, p in compile_model(tables)["services"]}
    return sum(pop[name] * (HORIZON_MIN - t) for name, t in failures.items() if t < HORIZON_MIN)


def evaluate(tables, speed=1.0):
    """Run every entry point. Returns expected harm, worst case, and time to first service failure."""
    probs = entry_probs(tables)
    per_entry = {}
    for e in probs:
        r = simulate_full(tables, {e: 0}, speed)
        pop = {n: p for n, _r, _b, p in compile_model(tables)["services"]}
        first = min([t for n, t in r["failures"].items() if t < HORIZON_MIN and pop[n] > 0], default=HORIZON_MIN)
        per_entry[e] = {"prob": round(probs[e], 3), "harm": scenario_harm(tables, r["failures"]),
                        "first_failure_min": first, "failures": r["failures"]}
    if not per_entry:
        return {"expected_harm": 0.0, "worst_harm": 0.0, "worst_entry": None,
                "first_failure_min": HORIZON_MIN, "per_entry": {}}
    worst = max(per_entry, key=lambda e: per_entry[e]["harm"])
    return {"expected_harm": sum(p["prob"] * p["harm"] for p in per_entry.values()),
            "worst_harm": per_entry[worst]["harm"],
            "worst_entry": worst,
            "first_failure_min": min(p["first_failure_min"] for p in per_entry.values()),
            "per_entry": per_entry}


def fmt_first(m):
    return "none within 6h" if m >= HORIZON_MIN else f"T+{m:.0f} min"


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    ev = evaluate(tables)
    print(f"Expected harm:   {ev['expected_harm']:,.0f} people-minutes")
    print(f"Worst case:      {ev['worst_harm']:,.0f} people-minutes (entry {ev['worst_entry']})")
    print(f"First failure:   {fmt_first(ev['first_failure_min'])}")
    for e, p in ev["per_entry"].items():
        print(f"  entry {e}: P={p['prob']}, harm={p['harm']:,.0f}, failures={p['failures']}")
