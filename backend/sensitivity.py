"""Pass 3: sensitivity check. Answers a judge's question: "your numbers are guesses, so why trust the ranking?"

Each assumption in config.py (plus attacker speed) is moved 30% down and 30% up, one at a time. For each change
we re-rank every fix and compare with the normal ranking:
  - does the top fix stay first?
  - are the top 3 fixes the same set?
If the answers are mostly yes, the recommendation does not hinge on any single guess.
Run from project root:  python backend/sensitivity.py
"""
import contextlib
import sys

import config
from fixes import rank_fixes
from load_graph import load_and_validate

CHANGE = 0.30
ASSUMPTIONS = {   # name in config.py -> plain-language label
    "MIN_EXPLOIT_FACTOR": "How fast a hardened asset still falls",
    "FIREWALL_FACTOR": "How much a firewall slows the attacker",
    "SEGMENT_FACTOR": "How much segmentation slows the attacker",
    "TTD_MONITORED_MIN": "Time to detect, monitored assets",
    "TTD_UNMONITORED_MIN": "Time to detect, unmonitored assets",
    "RESPONSE_DELAY_MIN": "Time from detection to isolation",
    "HORIZON_MIN": "Length of the harm window",
    "ENTRY_MIN_V": "Minimum chance of a way in",
}
MODULES = ["config", "simulate", "harm", "fixes", "optimize"]


@contextlib.contextmanager
def assumption(name, value):
    """Temporarily change one assumption everywhere it was imported."""
    saved = []
    for mod_name in MODULES:
        mod = sys.modules.get(mod_name)
        if mod is not None and hasattr(mod, name):
            saved.append((mod, getattr(mod, name)))
            setattr(mod, name, value)
    try:
        yield
    finally:
        for mod, old in saved:
            setattr(mod, name, old)


def fresh(tables):
    """Same data without the compiled-model cache, so changed assumptions are picked up."""
    return {k: v for k, v in tables.items() if not k.startswith("_")}


def top(tables, speed=1.0, n=3):
    _, df = rank_fixes(fresh(tables), speed)
    return list(df["fix"].head(n))


def sensitivity(tables):
    base_top = top(tables)
    runs = []
    variants = [(name, label, factor) for name, label in ASSUMPTIONS.items() for factor in (1 - CHANGE, 1 + CHANGE)]
    variants += [("ATTACKER_SPEED", "Attacker speed", f) for f in (1 - CHANGE, 1 + CHANGE)]
    for name, label, factor in variants:
        if name == "ATTACKER_SPEED":
            t3 = top(tables, speed=factor)
            value = factor
        else:
            value = getattr(config, name) * factor
            with assumption(name, value):
                t3 = top(tables)
        runs.append({"assumption": name, "label": label, "change_pct": round((factor - 1) * 100),
                     "value": round(value, 3), "top3": t3,
                     "same_top1": bool(t3) and bool(base_top) and t3[0] == base_top[0],
                     "same_top3": set(t3) == set(base_top)})
    return {"base_top3": base_top, "runs": runs,
            "top1_stable": sum(r["same_top1"] for r in runs), "top3_stable": sum(r["same_top3"] for r in runs),
            "total": len(runs), "change_pct": round(CHANGE * 100)}


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    s = sensitivity(tables)
    print("Normal top 3:", s["base_top3"])
    print(f"Top fix stays first in {s['top1_stable']} of {s['total']} tests; "
          f"same top 3 in {s['top3_stable']} of {s['total']}.\n")
    for r in s["runs"]:
        mark = "same" if r["same_top1"] else "CHANGED"
        print(f"{r['label']:<42} {r['change_pct']:+4d}%  top fix {mark:<8} {r['top3'][0] if r['top3'] else '-'}")
