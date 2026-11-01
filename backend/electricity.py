"""Electricity attack-screening (SENTINEL module 11), integrated as a static SAMPLE EXPLORER.
The frozen model is not run here: the package in ml_electricity/ holds its outputs on the validation files
(data10-12) and its held-out metrics (data13-15, evaluated once by the model owner). Benchmark samples from the
MSU-ORNL power-system dataset; not city telemetry, no timestamps."""
import csv
import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EDIR = ROOT / "ml_electricity"
SDIR = ROOT / "ml_sectors"


def available():
    return (EDIR / "MODEL_CARD.json").exists() and (EDIR / "electricity_samples_validation.csv").exists()


@lru_cache(maxsize=1)
def model_card():
    return json.loads((EDIR / "MODEL_CARD.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def explorer():
    return json.loads((EDIR / "explorer_summary.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def demo():
    return json.loads((EDIR / "electricity_demo_samples.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def mapping():
    return json.loads((EDIR / "illustrative_asset_mapping.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def samples():
    out = []
    with open(EDIR / "electricity_samples_validation.csv", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append({"file": r["source_file"], "row": int(r["row_in_file"]), "block": int(r["label_block"]),
                        "label": r["benchmark_label"], "pred": r["predicted_class"],
                        "p": [float(r["p_normal_operation"]), float(r["p_natural_disturbance"]), float(r["p_cyberattack"])],
                        "flag": r["attack_screening_flag"] == "True", "outcome": r["outcome_vs_benchmark"],
                        "ev": [[r[f"evidence{k}_feature"], float(r[f"evidence{k}_influence"] or 0)] for k in (1, 2, 3) if r.get(f"evidence{k}_feature")]})
    return out


def query(file=None, block=None, label=None, outcome=None, flag=None, offset=0, limit=50):
    rows = [s for s in samples() if (not file or s["file"] == file) and (block is None or s["block"] == block)
            and (not label or s["label"] == label) and (not outcome or s["outcome"] == outcome)
            and (flag is None or s["flag"] == flag)]
    return {"total": len(rows), "offset": offset, "rows": rows[offset:offset + limit]}


@lru_cache(maxsize=1)
def sector_status():
    return json.loads((SDIR / "sector_status.json").read_text(encoding="utf-8"))


IDIR = ROOT / "ml_iot_demo"


@lru_cache(maxsize=1)
def evaluation():
    ev = json.loads((SDIR / "evaluation.json").read_text(encoding="utf-8"))
    if (IDIR / "results.json").exists():
        import hashlib
        res = json.loads((IDIR / "results.json").read_text(encoding="utf-8"))
        decl = (IDIR / "DECLARATION.json").read_bytes()
        lock = (IDIR / "FINAL_TEST_DONE.lock").read_text().strip() if (IDIR / "FINAL_TEST_DONE.lock").exists() else None
        ev["iot_demo"] = {"declaration": json.loads(decl), "results": res,
                          "declaration_matches": hashlib.sha256(decl).hexdigest() == res.get("declaration_sha256"),
                          "lock_matches": lock == hashlib.sha256((IDIR / "results.json").read_bytes()).hexdigest()}
    return ev
