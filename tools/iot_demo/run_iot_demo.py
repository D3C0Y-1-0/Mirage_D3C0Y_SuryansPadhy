"""IoT demonstration benchmark (CICIoT2023 derivative), exactly as declared in ml_iot_demo/DECLARATION.json.
Run once:  python tools/iot_demo/run_iot_demo.py <folder with the three parquet files>
Writes ml_iot_demo/results.json and ml_iot_demo/FINAL_TEST_DONE.lock; refuses to run again."""
import hashlib, json, sys, time
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

OUT = Path(__file__).resolve().parents[2] / "ml_iot_demo"
DECL = json.loads((OUT / "DECLARATION.json").read_text())
LOCK = OUT / "FINAL_TEST_DONE.lock"
SEED = 20261101


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def metrics(y, p, tau):
    pred = p >= tau
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn); spec = tn / max(1, tn + fp)
    f1a = 2 * prec * rec / max(1e-9, prec + rec)
    npv = tn / max(1, tn + fn); f1b = 2 * npv * spec / max(1e-9, npv + spec)
    return {"n": int(len(y)), "attack_recall": round(rec, 4), "attack_precision": round(prec, 4), "benign_fpr": round(fp / max(1, fp + tn), 4),
            "macro_f1": round((f1a + f1b) / 2, 4), "roc_auc": round(float(roc_auc_score(y, p)), 4) if len(set(y)) > 1 else None,
            "pr_auc": round(float(average_precision_score(y, p)), 4) if len(set(y)) > 1 else None,
            "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}}


def tau_for_fpr(y, p, cap=0.05):
    ben = np.sort(p[y == 0])
    k = int(np.floor(cap * len(ben)))           # allow at most k benign rows at or above tau
    return float(ben[len(ben) - k - 1] + 1e-9) if k < len(ben) else 0.0


def main(folder):
    if LOCK.exists():
        sys.exit("Refusing to run: the final test was already scored once (ml_iot_demo/FINAL_TEST_DONE.lock).")
    folder = Path(folder); t0 = time.time()
    for k in ("train", "validation", "test"):
        got = sha(folder / DECL["data"][k]["file"])
        assert got == DECL["data"][k]["sha256"], f"{k} file hash does not match the declaration"
    ex = DECL["excluded_features"]; drop = set(ex["capture_artefact"] + ex["window_dependent_aggregates"] + ex["labels"])
    tr = pd.read_parquet(folder / DECL["data"]["train"]["file"])
    va = pd.read_parquet(folder / DECL["data"]["validation"]["file"])
    feats = [c for c in tr.columns if c not in drop]
    # the audit's shortcut, reported to show why Number is excluded (rule, no training)
    shortcut = {k: metrics(d["label"].to_numpy(), (d["Number"] == 100).astype(float).to_numpy(), .5) for k, d in (("validation", va),)}
    n0 = len(tr); trd = tr.drop_duplicates(subset=feats)
    frac = min(1, 300000 / len(trd))                     # stratified: the same fraction of each class
    sub = pd.concat([trd[trd["label"] == v].sample(frac=frac, random_state=SEED) for v in (0, 1)])
    X, y = sub[feats].to_numpy(float), sub["label"].to_numpy()
    Xv, yv = va[feats].to_numpy(float), va["label"].to_numpy()
    seen = set(map(tuple, np.round(trd[feats].to_numpy(float), 6)))
    unseen_v = np.array([tuple(r) not in seen for r in np.round(Xv, 6)])
    mk = {"baseline": lambda: make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000)),
          "candidate": lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced", random_state=SEED)}
    res = {}
    for name, f in mk.items():
        oof = np.zeros(len(y)); folds = []
        for k, (a, b) in enumerate(StratifiedKFold(3, shuffle=True, random_state=SEED).split(X, y)):
            m = f().fit(X[a], y[a]); oof[b] = m.predict_proba(X[b])[:, 1]
        tau = tau_for_fpr(y, oof)
        for k, (a, b) in enumerate(StratifiedKFold(3, shuffle=True, random_state=SEED).split(X, y)):
            folds.append(metrics(y[b], oof[b], tau))
        m = f().fit(X, y); pv = m.predict_proba(Xv)[:, 1]
        res[name] = {"tau": round(tau, 6), "folds": folds, "validation": metrics(yv, pv, tau),
                     "validation_unseen_vectors": metrics(yv[unseen_v], pv[unseen_v], tau), "_model": m}
    b, c = res["baseline"], res["candidate"]
    gates = {"G1": c["validation"]["benign_fpr"] <= 0.05,
             "G2": c["validation"]["attack_recall"] > b["validation"]["attack_recall"] and all(fc["attack_recall"] > fb["attack_recall"] for fc, fb in zip(c["folds"], b["folds"])),
             "G3": False,
             "G4": abs(c["validation_unseen_vectors"]["attack_recall"] - c["validation"]["attack_recall"]) <= 0.10,
             "G5": all(f["macro_f1"] >= c["validation"]["macro_f1"] - 0.10 for f in c["folds"])}
    # final test: scored exactly once, with the threshold fixed above
    te = pd.read_parquet(folder / DECL["data"]["test"]["file"])
    Xt, yt = te[feats].to_numpy(float), te["label"].to_numpy()
    unseen_t = np.array([tuple(r) not in seen for r in np.round(Xt, 6)])
    pt = c["_model"].predict_proba(Xt)[:, 1]; ptb = b["_model"].predict_proba(Xt)[:, 1]
    per_class = {cls: round(float((pt[(te["attack_class"] == cls).to_numpy()] >= c["tau"]).mean()), 4) for cls in sorted(te["attack_class"].unique())}
    out = {"declaration_sha256": hashlib.sha256((OUT / "DECLARATION.json").read_bytes()).hexdigest(),
           "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "seconds": round(time.time() - t0, 1),
           "label": DECL["label"],
           "run_note": "A first attempt stopped with a pandas error while subsampling the training rows, before any model was trained or the test file was opened; the sampling line was fixed (same stratified fraction, same seed) and the script re-run. The declaration was not changed.", "features_used": feats, "n_features": len(feats),
           "train": {"rows": n0, "after_dedup": len(trd), "duplicates_removed": n0 - len(trd), "subsample": len(sub)},
           "shortcut_rule_number_eq_100_on_validation": shortcut["validation"],
           "baseline": {k: v for k, v in b.items() if k != "_model"}, "candidate": {k: v for k, v in c.items() if k != "_model"},
           "gates": gates, "gates_met": [k for k, v in gates.items() if v], "gates_unmet": [k for k, v in gates.items() if not v],
           "test_once": {"candidate": metrics(yt, pt, c["tau"]), "candidate_unseen_vectors": metrics(yt[unseen_t], pt[unseen_t], c["tau"]),
                         "baseline": metrics(yt, ptb, b["tau"]), "candidate_flag_rate_by_class": per_class,
                         "unseen_vector_share": round(float(unseen_t.mean()), 4)},
           "verdict": "Demonstration only. G3 (session confound) cannot be checked on this data, so the IoT gates remain UNMET whatever the scores. Scores are in-distribution: train, validation and test are random row splits of the same lab captures."}
    (OUT / "results.json").write_text(json.dumps(out, indent=1))
    LOCK.write_text(hashlib.sha256((OUT / "results.json").read_bytes()).hexdigest() + "\n")
    print(json.dumps({k: out[k] for k in ("train", "gates", "test_once")}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
