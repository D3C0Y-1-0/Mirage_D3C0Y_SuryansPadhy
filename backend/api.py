"""Step 6: the API. Connects the backend (steps 1-5) to the 3D twin.

Run from project root:   python -m uvicorn api:app --app-dir backend --port 8000
Then open:               http://localhost:8000

Every fix has a stable id like 'patch:A02', 'monitor:A01' or 'segment:3' (3 = row number in links.csv).
Endpoints take a list of fix ids, apply them to a copy of the data, and return results. The CSVs are never changed.
"""
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config
from containment import containment_plan
from fixes import candidates, apply, patch_outage_harm, rank_fixes
from sensitivity import sensitivity
from harm import evaluate, entry_probs, scenario_harm
from load_graph import load_and_validate, split_list
from optimize import optimize, worst_case, needs_window
from risk import compute_risks, cve_exploit_prob, service_up
from simulate import simulate_full, compile_model, flag

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
ZONE_ORDER = ["vendor", "cloud", "dmz", "enterprise", "control", "field"]
ZONE_NAMES = {"vendor": "Vendors", "cloud": "Cloud", "dmz": "Internet edge", "enterprise": "Hospital and office IT",
              "control": "Control room", "field": "Field devices"}

app = FastAPI(title="PS03 Cyber Twin API")


# ---------- data loading ----------
@lru_cache(maxsize=1)
def base_tables():
    tables, errors = load_and_validate()
    if errors:
        raise RuntimeError("Data problems: " + "; ".join(errors))
    return tables


def fix_id(fx):
    return f"{fx['fix']}:{fx['target']}"


def fix_lookup(tables):
    return {fix_id(fx): fx for fx in candidates(tables)}


def with_fixes(fix_ids):
    tables = base_tables()
    lookup = fix_lookup(tables)
    unknown = [f for f in fix_ids if f not in lookup]
    if unknown:
        raise HTTPException(400, f"Unknown fix ids: {unknown}. Get valid ids from GET /api/fixes.")
    t = tables
    for f in fix_ids:
        t = apply(t, lookup[f])
    return t, [lookup[f] for f in fix_ids]


def num(x, default=0.0):
    return default if pd.isna(x) else float(x)


def layout(assets):
    """Use layout_x/layout_y from the CSV if given, otherwise place assets in rows by zone."""
    pos = {}
    rows = {}
    for _, a in assets.iterrows():
        rows.setdefault(a["zone"], []).append(a["asset_id"])
    zones = [z for z in ZONE_ORDER if z in rows] + [z for z in rows if z not in ZONE_ORDER]
    # each zone is a band; a zone with more than PER_ROW assets wraps onto extra rows inside its band
    PER_ROW, DX, DZ, GAP = 5, 15.0, 13.0, 3.0
    z_cursor, placed = 0.0, {}
    for zi, z in enumerate(zones):
        ids = rows[z]
        n_rows = -(-len(ids) // PER_ROW)
        for k, aid in enumerate(ids):
            row, col = divmod(k, PER_ROW)
            in_row = min(PER_ROW, len(ids) - row * PER_ROW)
            stagger = (7.0 if zi % 2 else -7.0) if in_row < 3 else (DX / 2 if row % 2 else 0.0)  # zig-zag so towers don't hide each other
            placed[aid] = ((col - (in_row - 1) / 2) * DX + stagger, z_cursor + row * DZ)
        z_cursor += n_rows * DZ + GAP
    mid = (z_cursor - DZ - GAP) / 2
    for aid, (x, zz) in placed.items():
        pos[aid] = (x, zz - mid)
    # If EVERY asset has layout_x/layout_y (any canvas size), use that design instead, scaled so neighbouring
    # buildings sit about TARGET_GAP world units apart and centred on the origin.
    if {"layout_x", "layout_y"} <= set(assets.columns):
        xy = assets[["layout_x", "layout_y"]].apply(pd.to_numeric, errors="coerce")
        if xy.notna().all().all() and len(assets) > 1:
            pts = list(zip(assets["asset_id"], xy["layout_x"], xy["layout_y"]))
            nn = sorted(min(((x - x2) ** 2 + (y - y2) ** 2) ** .5 for b, x2, y2 in pts if b != a) for a, x, y in pts)
            gap = nn[len(nn) // 2] or 1.0
            TARGET_GAP = 15.0
            k = TARGET_GAP / gap
            cx, cy = xy["layout_x"].mean(), xy["layout_y"].mean()
            pos = {a: ((x - cx) * k, (y - cy) * k) for a, x, y in pts}
    return pos, zones


def asset_metadata():
    """Optional file next to the data: asset_metadata.csv with sector / ui_cluster columns (used to group the twin)."""
    from load_graph import DATA
    for f in (DATA / "asset_metadata.csv", DATA / "metadata" / "asset_metadata.csv"):
        if f.exists():
            md = pd.read_csv(f, dtype=str)
            cols = [c for c in ("sector", "ui_cluster") if c in md.columns]
            return md.set_index("asset_id")[cols].to_dict("index") if cols and "asset_id" in md.columns else {}
    return {}


# ---------- models ----------
class SimRequest(BaseModel):
    entry_points: List[str] = Field(..., min_length=1, max_length=40)
    speed: float = Field(1.0, gt=0, le=5)
    fixes: List[str] = Field(default_factory=list, max_length=40)


class OptRequest(BaseModel):
    max_fixes: int = Field(3, ge=1, le=6)
    windows: int = Field(2, ge=0, le=10)
    staff_budget: Optional[float] = None
    simultaneous: int = Field(1, ge=1, le=3)
    speed: float = 1.0


# ---------- endpoints ----------
@app.get("/api/graph")
def graph():
    t = base_tables()
    m = compile_model(t)
    risks = compute_risks(t).set_index("asset_id")
    probs = entry_probs(t)
    pos, zones = layout(t["assets.csv"])
    meta = asset_metadata()
    assets = []
    for _, a in t["assets.csv"].iterrows():
        aid = a["asset_id"]
        r = risks.loc[aid]
        assets.append({
            "id": aid, "name": a["name"], "type": a["type"], "zone": a["zone"],
            "criticality": int(a["criticality"]), "exposure": num(a["exposure"]),
            "is_entry": aid in m["entries"], "entry_prob": round(probs.get(aid, 0.0), 3),
            "monitored": bool(flag(a, "monitored")),
            "risk": float(r["risk"]), "V": float(r["V"]),
            "x": pos[aid][0], "z": pos[aid][1],
            "sector": meta.get(aid, {}).get("sector"), "cluster": meta.get(aid, {}).get("ui_cluster"),
        })
    links = []
    for i, l in t["links.csv"].iterrows():
        links.append({"id": int(i), "src": l["src"], "dst": l["dst"], "type": l["link_type"],
                      "protocol": l["protocol"], "attack_path": l["link_type"] in config.SPREAD_LINK_TYPES,
                      "segmented": bool(int(l["segmented"])), "bidirectional": bool(int(l["bidirectional"]))})
    services = [{"id": s["service_id"], "name": s["name"], "population": int(s["population_affected"]),
                 "rule": s["required_logic"], "buffer_min": num(s["buffer_min"])}
                for _, s in t["services.csv"].iterrows()]
    return {"assets": assets, "links": links, "services": services, "zones": zones,
            "horizon_min": config.HORIZON_MIN}


@app.get("/api/overview")
def overview():
    """Fast summary for the first screen: where the worst attack comes from and when the first service falls."""
    ev = evaluate(base_tables())
    return {"expected_harm": ev["expected_harm"], "worst_harm": ev["worst_harm"], "worst_entry": ev["worst_entry"],
            "first_failure_min": ev["first_failure_min"], "horizon_min": config.HORIZON_MIN}


@app.post("/api/simulate")
def simulate(req: SimRequest):
    t, _ = with_fixes(req.fixes)
    known = set(t["assets.csv"]["asset_id"])
    bad = [e for e in req.entry_points if e not in known]
    if bad:
        raise HTTPException(400, f"Unknown entry points: {bad}")
    r = simulate_full(t, {e: 0 for e in req.entry_points}, req.speed)
    names = dict(zip(t["assets.csv"]["asset_id"], t["assets.csv"]["name"]))
    events = [{"t": tm, "kind": "compromise", "asset": a, "from": r["parents"][a],
               "text": f"{names[a]} compromised" + (f" from {names[r['parents'][a]]}" if r["parents"][a] else " (entry point)")}
              for a, tm in r["compromised"].items()]
    events += [{"t": tm, "kind": "service_down", "service": s, "text": f"{s} lost"} for s, tm in r["failures"].items()]
    if r["detected_at"] is not None and r["detected_at"] <= config.HORIZON_MIN:
        events.append({"t": r["detected_at"], "kind": "detected", "text": "Attack detected"})
    for iso in r.get("isolations", []):
        if iso["at"] <= config.HORIZON_MIN:
            where = "Whole network isolated, spread stops" if iso["zone"] is None else f"{ZONE_NAMES.get(iso['zone'], iso['zone'])} zone isolated"
            events.append({"t": iso["at"], "kind": "contained", "text": where})
    events.sort(key=lambda e: (e["t"], e["kind"] != "compromise"))
    return {**r, "events": events, "harm": scenario_harm(t, r["failures"]), "horizon_min": config.HORIZON_MIN}


@app.get("/api/fixes")
def fixes(speed: float = 1.0):
    t = base_tables()
    base, df = _fixes_cached(speed)
    by_label = {fx["label"]: fx for fx in candidates(t)}
    rows = []
    for rec in df.to_dict("records"):
        fx = by_label[rec["fix"]]
        rows.append({**rec, "id": fix_id(fx), "target": str(fx["target"]),
                     "needs_window": needs_window(t, fx)})
    return {"base": {"expected_harm": base["expected_harm"], "worst_harm": base["worst_harm"],
                     "worst_entry": base["worst_entry"], "first_failure_min": base["first_failure_min"]},
            "fixes": rows}


@lru_cache(maxsize=32)
def _optimize_cached(max_fixes, windows, staff_budget, simultaneous, speed):
    return optimize(base_tables(), max_fixes=max_fixes, windows=windows, staff_budget=staff_budget,
                    simultaneous=simultaneous, speed=speed)


@lru_cache(maxsize=8)
def _fixes_cached(speed):
    return rank_fixes(base_tables(), speed)


@app.post("/api/optimize")
def run_optimize(req: OptRequest):
    base, results = _optimize_cached(req.max_fixes, req.windows, req.staff_budget, req.simultaneous, req.speed)
    t = base_tables()

    def pack(s):
        return {"fixes": [fix_id(fx) for fx in s["bundle"]], "labels": s["labels"],
                "worst_harm": s["worst_harm"], "expected_harm": s["expected_harm"],
                "earliest_failure_min": s["earliest_failure_min"], "attacker_entry": list(s["attacker_entry"]),
                "windows_used": s["windows_used"], "staff_hours": s["staff_hours"],
                "patch_outage_harm": s["patch_outage_harm"]}

    return {"before": pack(base), "best": pack(results[0]), "runners_up": [pack(r) for r in results[1:6]],
            "budget": req.model_dump()}


@app.get("/api/asset/{asset_id}")
def explain(asset_id: str):
    t = base_tables()
    assets = t["assets.csv"].set_index("asset_id")
    if asset_id not in assets.index:
        raise HTTPException(404, f"No asset {asset_id}")
    a = assets.loc[asset_id]
    r = compute_risks(t).set_index("asset_id").loc[asset_id]
    vulns = t["vulns.csv"].set_index("cve_id")
    cves = []
    for cid in split_list(a["cve_ids"]):
        v = vulns.loc[cid]
        cves.append({"id": cid, "cvss": num(v["cvss"]), "kev": bool(int(v["kev"])), "epss": num(v["epss"]),
                     "ics": bool(int(v["ics_flag"])), "exploit_prob": round(cve_exploit_prob(v.rename(cid)), 3),
                     "patch_available": bool(int(v["patch_available"]))})
    ids = set(t["assets.csv"]["asset_id"])
    breaks = [s["name"] for _, s in t["services.csv"].iterrows() if not service_up(s["required_logic"], {asset_id}, ids)]
    feeds = [s["name"] for _, s in t["services.csv"].iterrows() if asset_id in s["required_logic"]]
    links = t["links.csv"]
    neighbours = sorted(set(links.loc[links["src"] == asset_id, "dst"]) | set(links.loc[links["dst"] == asset_id, "src"]))

    reasons = []
    if flag(a, "internet_facing"):
        reasons.append("reachable from the internet")
    if flag(a, "vendor_access"):
        reasons.append("a third-party vendor can reach it")
    kev = [c["id"] for c in cves if c["kev"]]
    if kev:
        reasons.append(f"{', '.join(kev)} {'is' if len(kev) == 1 else 'are'} on the CISA known-exploited list")
    flags = split_list(a["config_flags"])
    if flags:
        reasons.append("weak configuration: " + ", ".join(f.replace("_", " ") for f in flags))
    if breaks:
        reasons.append("losing it alone takes down " + ", ".join(breaks))
    elif feeds:
        reasons.append("it is one of the assets behind " + ", ".join(feeds))
    if int(a["criticality"]) >= 4:
        reasons.append(f"criticality {int(a['criticality'])} of 5")
    if not reasons:
        reasons.append("no major exposure or known exploited weakness")

    asset_fixes = [{"id": fix_id(fx), "label": fx["label"], "type": fx["fix"]}
                   for fx in candidates(t) if fx["target"] == asset_id]
    return {"id": asset_id, "name": a["name"], "type": a["type"], "zone": a["zone"],
            "software": a["software"], "version": a["version"],
            "criticality": int(a["criticality"]), "exposure": num(a["exposure"]),
            "patchable_without_downtime": bool(int(a["patchable_without_downtime"])),
            "downtime_hours_to_patch": num(a["downtime_hours_to_patch"]),
            "patch_outage_harm": patch_outage_harm(t, asset_id),
            "monitored": bool(flag(a, "monitored")), "config_flags": flags,
            "score": {k: float(r[k]) for k in ("V", "L", "consequence", "impact", "risk")},
            "cves": cves, "breaks_alone": breaks, "part_of": feeds, "neighbours": neighbours,
            "summary": ("High risk: " if r["risk"] >= 15 else "Risk factors: ") + "; ".join(reasons) + ".",
            "fixes": asset_fixes}


@app.post("/api/containment")
def containment(req: SimRequest):
    t, _ = with_fixes(req.fixes)
    known = set(t["assets.csv"]["asset_id"])
    bad = [e for e in req.entry_points if e not in known]
    if bad:
        raise HTTPException(400, f"Unknown entry points: {bad}")
    return containment_plan(t, {e: 0 for e in req.entry_points}, req.speed)


class RWLock:
    """Many readers OR one writer. The sensitivity test temporarily changes module-level assumptions (config
    constants), so nothing else may simulate while it runs, or those results would use the wrong numbers."""
    def __init__(self):
        import threading
        self.c, self.readers, self.writer = threading.Condition(), 0, False

    def r_acquire(self):
        with self.c:
            while self.writer:
                self.c.wait()
            self.readers += 1

    def r_release(self):
        with self.c:
            self.readers -= 1
            self.c.notify_all()

    def w_acquire(self):
        with self.c:
            while self.writer or self.readers:
                self.c.wait()
            self.writer = True

    def w_release(self):
        with self.c:
            self.writer = False
            self.c.notify_all()


MODEL_LOCK = RWLock()


@lru_cache(maxsize=1)
def _sensitivity_raw():
    return sensitivity(base_tables())


def _sensitivity_cached():
    if _sensitivity_raw.cache_info().currsize:
        return _sensitivity_raw()
    MODEL_LOCK.w_acquire()
    try:
        return _sensitivity_raw()
    finally:
        MODEL_LOCK.w_release()


@app.get("/api/sensitivity")
def get_sensitivity():
    return _sensitivity_cached()


@app.on_event("startup")
def _warm_up():
    """Work out the slow answers in the background as soon as the server starts, so the demo never waits."""
    import threading

    def run():
        try:
            base_tables(); _sensitivity_cached()          # first, alone (it changes assumptions while it runs)
            if water.available():
                _water_summary()
            _landing_cached()
            _paths_cached()
        except Exception as exc:
            print("Warm-up skipped:", exc)
        try:
            MODEL_LOCK.r_acquire()
            try:
                _fixes_cached(1.0); _optimize_cached(3, 2, None, 1, 1.0); _optimize_cached(3, 2, None, 2, 1.0)
                _analytics_cached(); _presets_cached(1.0); _baseline_cached(5)
            finally:
                MODEL_LOCK.r_release()
            _mc_cached()                                  # last: holds the writer lock for a few seconds
        except Exception as exc:          # never crash the server because of warm-up
            print("Warm-up skipped:", exc)
    threading.Thread(target=run, daemon=True).start()


@app.get("/api/dataset")
def dataset():
    from load_graph import DATA
    t = base_tables()
    return {"folder": DATA.name, "assets": len(t["assets.csv"]), "links": len(t["links.csv"]), "services": len(t["services.csv"])}


@app.get("/api/config")
def get_config():
    return {k: getattr(config, k) for k in dir(config) if k.isupper() and not isinstance(getattr(config, k), set)}




# =====================================================================================================
# Platform additions: multi-attacker simulation, inventory, vulnerabilities, risk register, baseline,
# analytics, ML status, upload validation, 2FA login, and the page routes (landing, app, twin).
# =====================================================================================================
import json
import re
import tempfile

from fastapi import Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

import auth
from multi import simulate_multi, presets

COOKIE = "cascade_session"
PUBLIC_EXACT = {"/", "/login", "/favicon.ico"}
PUBLIC_PREFIXES = ("/api/auth/", "/api/public/", "/vendor/", "/static/")


@app.middleware("http")
async def access_gate(request: Request, call_next):
    path = request.url.path
    if auth.gate_enabled() and not (path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES)):
        sess = auth.read_session(request.cookies.get(COOKIE, ""))
        if not sess or sess.get("s") != "full":
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Sign in required"}, status_code=401)
            return RedirectResponse(f"/login?next={path}", status_code=303)
    if path.startswith("/api/") and not path.startswith(("/api/sensitivity", "/api/insights/montecarlo", "/api/auth/", "/api/water/", "/api/ops/", "/api/failsafe/policy")):
        from starlette.concurrency import run_in_threadpool
        await run_in_threadpool(MODEL_LOCK.r_acquire)       # wait while the sensitivity test is running
        try:
            return await call_next(request)
        finally:
            MODEL_LOCK.r_release()
    return await call_next(request)


def _names(t):
    return dict(zip(t["assets.csv"]["asset_id"], t["assets.csv"]["name"]))


def _meta_full():
    """Every column of asset_metadata.csv (role, MITRE asset class, how the version was sourced...), if present."""
    from load_graph import DATA
    for f in (DATA / "asset_metadata.csv", DATA / "metadata" / "asset_metadata.csv"):
        if f.exists():
            md = pd.read_csv(f, dtype=str).fillna("")
            return md.set_index("asset_id").to_dict("index") if "asset_id" in md.columns else {}
    return {}


def _fix_from_id(t, fid):
    kind, target = fid.split(":", 1)
    return {"fix": kind, "target": int(target) if kind == "segment" else target}


# ---------- multi-attacker ----------
class Entry(BaseModel):
    asset: str = Field(..., max_length=40)
    start: float = Field(0, ge=0, le=config.HORIZON_MIN)


class Attacker(BaseModel):
    id: str = Field("A", min_length=1, max_length=8)
    entry: Optional[str] = Field(None, max_length=40, description="single way in (kept for backward compatibility)")
    entries: List[Entry] = Field(default_factory=list, max_length=6, description="one attacker, several ways in")
    start: float = Field(0, ge=0, le=config.HORIZON_MIN)
    speed: float = Field(1.0, gt=0, le=5)
    contain_at: Optional[float] = Field(None, ge=0)
    adaptive: bool = False
    active: bool = True


class Maintenance(BaseModel):
    asset: str
    start: float = Field(0, ge=0)
    hours: float = Field(1, gt=0, le=48)
    patch: bool = True


class MultiRequest(BaseModel):
    island_at: Optional[float] = Field(None, ge=0, le=config.HORIZON_MIN, description="failsafe: minute internet and vendor access are cut")
    c2: bool = Field(True, description="assume outside attackers need a live internet command channel")
    attackers: List[Attacker] = Field(default_factory=list, max_length=6)
    fixes: List[str] = []
    maintenance: List[Maintenance] = Field(default_factory=list, max_length=4)
    detection: bool = True
    speed: float = Field(1.0, gt=0, le=5)


@app.post("/api/multi")
def run_multi(req: MultiRequest):
    t, _ = with_fixes(req.fixes)
    ids = set(t["assets.csv"]["asset_id"])
    if any(not a.entry and not a.entries for a in req.attackers):
        raise HTTPException(400, "Every attacker needs an entry point ('entry' or 'entries')")
    bad = ([a.entry for a in req.attackers if a.entry and not a.entries and a.entry not in ids]
           + [e.asset for a in req.attackers for e in a.entries if e.asset not in ids]
           + [w.asset for w in req.maintenance if w.asset not in ids])
    if bad:
        raise HTTPException(400, f"Unknown assets: {bad}")
    if len({a.id for a in req.attackers}) != len(req.attackers):
        raise HTTPException(400, "Each attacker needs a different ID")
    if not req.attackers and not req.maintenance:
        raise HTTPException(400, "Add at least one attacker or one maintenance window")
    r = simulate_multi(t, [a.model_dump() for a in req.attackers], speed=req.speed, detection=req.detection,
                       maintenance=[w.model_dump() for w in req.maintenance],
                       island=None if req.island_at is None else {"at": req.island_at, "c2": req.c2})
    return {**r, "request": req.model_dump()}


@lru_cache(maxsize=4)
def _presets_cached(speed):
    return presets(base_tables(), speed)


@app.get("/api/multi/presets")
def multi_presets(speed: float = 1.0):
    return {"presets": _presets_cached(speed)}


# ---------- inventory, vulnerabilities, risk register ----------
@app.get("/api/assets")
def assets_table():
    t = base_tables()
    m = compile_model(t)
    risks = compute_risks(t).set_index("asset_id")
    probs = entry_probs(t)
    meta = _meta_full()
    vulns = t["vulns.csv"].set_index("cve_id")
    links = t["links.csv"]
    rows = []
    for _, a in t["assets.csv"].iterrows():
        aid = a["asset_id"]
        cves = split_list(a["cve_ids"])
        vv = vulns.loc[cves] if cves else vulns.iloc[0:0]
        md = meta.get(aid, {})
        feeds = [s["name"] for _, s in t["services.csv"].iterrows() if aid in re.findall(r"[A-Za-z0-9_]+", s["required_logic"])]
        rows.append({
            "id": aid, "name": a["name"], "type": a["type"], "zone": a["zone"], "zone_name": ZONE_NAMES.get(a["zone"], a["zone"]),
            "sector": md.get("sector") or None, "role": md.get("role") or None,
            "mitre_asset_class": md.get("mitre_ics_asset_class") or None, "layer": md.get("nist_functional_layer") or None,
            "software": a["software"], "version": "" if pd.isna(a["version"]) else str(a["version"]),
            "version_source": md.get("version_source") or None,
            "criticality": int(a["criticality"]), "exposure": num(a["exposure"]),
            "internet_facing": bool(flag(a, "internet_facing")), "vendor_access": bool(flag(a, "vendor_access")),
            "is_entry": aid in m["entries"], "entry_prob": round(probs.get(aid, 0.0), 3),
            "monitored": bool(flag(a, "monitored")), "config_flags": split_list(a["config_flags"]),
            "cves": cves, "cve_count": len(cves), "kev_count": int(vv["kev"].astype(int).sum()) if len(vv) else 0,
            "max_cvss": float(vv["cvss"].max()) if len(vv) else 0.0,
            "max_epss": float(vv["epss"].max()) if len(vv) and vv["epss"].notna().any() else 0.0,
            "patch_available": bool(len(vv) and vv["patch_available"].astype(int).max() == 1),
            "patchable_without_downtime": bool(int(a["patchable_without_downtime"])),
            "downtime_hours_to_patch": num(a["downtime_hours_to_patch"]),
            "risk": float(risks.loc[aid, "risk"]), "V": float(risks.loc[aid, "V"]),
            "breaks_alone": [x for x in str(risks.loc[aid, "breaks_alone"]).split("; ") if x],
            "feeds": feeds,
            "links_out": int((links["src"] == aid).sum()), "links_in": int((links["dst"] == aid).sum()),
        })
    return {"assets": rows, "zones": ZONE_NAMES}


@app.get("/api/vulns")
def vulns_table():
    t = base_tables()
    risks = compute_risks(t).set_index("asset_id")
    on = {}
    for _, a in t["assets.csv"].iterrows():
        for c in split_list(a["cve_ids"]):
            on.setdefault(c, []).append({"id": a["asset_id"], "name": a["name"], "criticality": int(a["criticality"]),
                                         "exposure": num(a["exposure"]), "risk": float(risks.loc[a["asset_id"], "risk"])})
    rows = []
    for _, v in t["vulns.csv"].iterrows():
        p = cve_exploit_prob(v)
        has_ml = "exploit_prob" in v.index and not pd.isna(v["exploit_prob"])
        source = "ML model" if has_ml else ("CISA KEV (0.9)" if int(v["kev"]) == 1 else ("EPSS" if not pd.isna(v["epss"]) else "default 0.05"))
        assets = on.get(v["cve_id"], [])
        rows.append({"cve_id": v["cve_id"], "cvss": num(v["cvss"]), "vector": "" if pd.isna(v.get("vector")) else v.get("vector"),
                     "cwe": "" if pd.isna(v.get("cwe")) else v.get("cwe"),
                     "vendor": "" if pd.isna(v.get("vendor")) else v.get("vendor"),
                     "product": "" if pd.isna(v.get("product")) else v.get("product"),
                     "kev": bool(int(v["kev"])), "epss": None if pd.isna(v["epss"]) else float(v["epss"]),
                     "ics": bool(int(v["ics_flag"])), "patch_available": bool(int(v["patch_available"])),
                     "patch_type": "" if pd.isna(v.get("patch_type")) else v.get("patch_type"),
                     "exploit_prob_used": round(p, 4), "prob_source": source,
                     "severity_x_likelihood": round(p * num(v["cvss"]) / 10, 4),
                     "assets": assets, "max_asset_criticality": max((a["criticality"] for a in assets), default=0),
                     "max_asset_risk": max((a["risk"] for a in assets), default=0.0)})
    rows.sort(key=lambda r: (-r["max_asset_risk"], -r["severity_x_likelihood"]))
    return {"vulns": rows}


@app.get("/api/risk_register")
def risk_register():
    t = base_tables()
    inv = {a["id"]: a for a in assets_table()["assets"]}
    ev = evaluate(t)
    best_fix = {}
    try:
        base, df = _fixes_cached(1.0)
        lookup = {fx["label"]: fx for fx in candidates(t)}
        links = t["links.csv"]
        for rec in df.to_dict("records"):
            fx = lookup[rec["fix"]]
            targets = [fx["target"]] if fx["fix"] != "segment" else [links.loc[fx["target"], "src"], links.loc[fx["target"], "dst"]]
            for tg in targets:
                if tg not in best_fix and rec["net_benefit"] > 0:
                    best_fix[tg] = {"id": fix_id(fx), "label": rec["fix"], "risk_reduction_pct": rec["risk_reduction_pct"],
                                    "minutes_bought": rec["minutes_bought"], "staff_hours": rec["staff_hours"]}
    except Exception:
        pass
    rows = []
    for aid, a in inv.items():
        factors = []
        if a["internet_facing"]: factors.append("Internet-facing")
        if a["vendor_access"]: factors.append("Vendor access")
        if a["kev_count"]: factors.append(f"{a['kev_count']} known-exploited CVE{'s' if a['kev_count'] > 1 else ''}")
        if a["config_flags"]: factors.append("Weak config: " + ", ".join(f.replace("_", " ") for f in a["config_flags"]))
        if a["breaks_alone"]: factors.append("Single point of failure for " + ", ".join(a["breaks_alone"]))
        if not a["monitored"]: factors.append("Not monitored")
        pe = ev["per_entry"].get(aid)
        rows.append({**{k: a[k] for k in ("id", "name", "type", "zone", "zone_name", "sector", "criticality", "exposure",
                                          "cve_count", "kev_count", "max_cvss", "max_epss", "risk", "monitored",
                                          "breaks_alone", "feeds", "is_entry")},
                     "harm_if_entry": None if not pe else pe["harm"],
                     "first_failure_if_entry": None if not pe else pe["first_failure_min"],
                     "factors": factors, "recommended": best_fix.get(aid)})
    # water anomaly evidence (advisory): raises investigation priority only; never changes risk, CVSS, EPSS or KEV
    wcount = {}
    if water.available():
        for e in water.events():
            for a in e["mapped_city_asset_ids"]:
                wcount.setdefault(a, {"mapped": 0, "path": 0})["mapped"] += 1
            for a in e["observed_via_city_assets"]:
                wcount.setdefault(a, {"mapped": 0, "path": 0})["path"] += 1
    for r in rows:
        w = wcount.get(r["id"])
        r["water_advisory"] = None if not w else {**w, "text": (f"{w['mapped']} anomaly episodes on this system" if w["mapped"]
                                                              else f"telemetry path for {w['path']} anomaly episodes")}
    rows.sort(key=lambda r: -r["risk"])
    for i, r in enumerate(sorted(rows, key=lambda r: (-r["max_cvss"], -r["kev_count"]))):
        r["cvss_rank"] = i + 1
    for i, r in enumerate(rows):
        r["risk_rank"] = i + 1
    return {"rows": rows, "fix_ranking_ready": bool(best_fix)}


# ---------- CVSS-only baseline vs Cascade ----------
@lru_cache(maxsize=2)
def _baseline_cached(k_max=5):
    t0 = base_tables()
    assets = t0["assets.csv"]
    vulns = t0["vulns.csv"].set_index("cve_id")
    patchable = [a for _, a in assets.iterrows() if split_list(a["cve_ids"])]

    def worst_cvss(a):
        return max(float(vulns.loc[c, "cvss"]) for c in split_list(a["cve_ids"]))

    def worst_epss(a):
        return max(num(vulns.loc[c, "epss"]) for c in split_list(a["cve_ids"]))

    orders = {
        "cvss": [a["asset_id"] for a in sorted(patchable, key=lambda a: (-worst_cvss(a), a["asset_id"]))],
        "epss": [a["asset_id"] for a in sorted(patchable, key=lambda a: (-worst_epss(a), a["asset_id"]))],
        "kev_cvss": [a["asset_id"] for a in sorted(patchable, key=lambda a: (-max(int(vulns.loc[c, "kev"]) for c in split_list(a["cve_ids"])),
                                                                             -worst_cvss(a), a["asset_id"]))],
    }
    base = evaluate(t0)

    def curve(fix_list):
        pts = [{"k": 0, "expected": base["expected_harm"], "worst": base["worst_harm"], "first": base["first_failure_min"], "fix": None}]
        t = t0
        for i, fx in enumerate(fix_list[:k_max], 1):
            t = apply(t, fx)
            ev = evaluate(t)
            outage = patch_outage_harm(t0, fx["target"]) if fx["fix"] == "patch" else 0.0
            pts.append({"k": i, "expected": ev["expected_harm"], "worst": ev["worst_harm"], "first": ev["first_failure_min"],
                        "fix": f"{fx['fix']}:{fx['target']}", "label": next((c["label"] for c in candidates(t0) if c["fix"] == fx["fix"] and c["target"] == fx["target"]), ""),
                        "outage_if_no_window": outage})
        return pts

    def greedy(kinds):
        chosen, t = [], t0
        for _ in range(k_max):
            opts = [fx for fx in candidates(t0) if fx["fix"] in kinds and fx not in chosen]
            if not opts:
                break
            scored = []
            for fx in opts:
                ev = evaluate(apply(t, fx))
                scored.append((round(ev["expected_harm"]), round(ev["worst_harm"]), -ev["first_failure_min"], FIX_STAFF(fx), fx))
            best = min(scored, key=lambda x: x[:4])[4]
            chosen.append(best)
            t = apply(t, best)
        return chosen

    def FIX_STAFF(fx):
        return config.FIX_STAFF_HOURS[fx["fix"]]

    strategies = [
        {"key": "cvss", "name": "CVSS only", "text": "Patch the assets with the highest CVSS score first (common practice).",
         "points": curve([{"fix": "patch", "target": a} for a in orders["cvss"]])},
        {"key": "epss", "name": "EPSS only", "text": "Patch the assets whose CVEs are most likely to be exploited first.",
         "points": curve([{"fix": "patch", "target": a} for a in orders["epss"]])},
        {"key": "kev_cvss", "name": "KEV, then CVSS", "text": "Known-exploited first, then by CVSS (CISA's advice).",
         "points": curve([{"fix": "patch", "target": a} for a in orders["kev_cvss"]])},
        {"key": "cascade_patch", "name": "Cascade, patches only", "text": "Same patch-only budget, chosen by simulated harm.",
         "points": curve(greedy({"patch"}))},
        {"key": "cascade", "name": "Cascade, any fix", "text": "Patch, harden, monitor, segment or remove exposure, chosen by simulated harm.",
         "points": curve(greedy({"patch", "harden", "monitor", "segment", "restrict_exposure"}))},
    ]
    return {"k_max": k_max, "strategies": strategies,
            "note": "Each step applies one more fix and re-runs every entry point. Harm in people-minutes over 6 hours. "
                    "Patch outage (if no maintenance window) is listed per patch, not added in."}


@app.get("/api/baseline")
def baseline():
    return _baseline_cached(5)


# ---------- analytics ----------
@lru_cache(maxsize=1)
def _analytics_cached():
    import networkx as nx
    t = base_tables()
    m = compile_model(t)
    names = _names(t)
    ev = evaluate(t)
    meta = asset_metadata()
    # choke points: which attack-path links does each entry's spread tree use to reach systems behind services?
    service_assets = set()
    for _, s in t["services.csv"].iterrows():
        service_assets |= {tok for tok in pd.Series([s["required_logic"]]).str.findall(r"[A-Za-z0-9_]+")[0] if tok in m["ids"]}
    uses = {}
    for e in m["entries"]:
        r = simulate_full(t, {e: 0}, detection=False)
        seen = set()
        for target in service_assets & set(r["compromised"]):
            n = target
            while r["parents"].get(n):
                seen.add((r["parents"][n], n)); n = r["parents"][n]
        for edge in seen:
            uses.setdefault(edge, []).append(e)
    g = nx.DiGraph()
    for s, lst in m["adj"].items():
        for d, mins in lst:
            g.add_edge(s, d, weight=mins)
    btw = nx.betweenness_centrality(g, weight="weight") if g.number_of_nodes() > 2 else {}
    chokes = sorted(({"src": s, "dst": d, "src_name": names[s], "dst_name": names[d], "entries": len(es),
                      "entry_names": [names[x] for x in es]} for (s, d), es in uses.items()),
                    key=lambda c: -c["entries"])[:12]
    central = sorted(({"id": a, "name": names[a], "betweenness": round(v, 3)} for a, v in btw.items()), key=lambda x: -x["betweenness"])[:10]
    per_entry = [{"id": e, "name": names[e], "prob": p["prob"], "harm": p["harm"], "first_failure_min": p["first_failure_min"]}
                 for e, p in sorted(ev["per_entry"].items(), key=lambda kv: -kv[1]["harm"])]
    # vulnerabilities by zone and by sector
    by_zone, by_sector = {}, {}
    vul = t["vulns.csv"].set_index("cve_id")
    risks = compute_risks(t).set_index("asset_id")
    for _, a in t["assets.csv"].iterrows():
        cves = split_list(a["cve_ids"])
        kev = sum(int(vul.loc[c, "kev"]) for c in cves)
        for key, bucket in ((ZONE_NAMES.get(a["zone"], a["zone"]), by_zone), (meta.get(a["asset_id"], {}).get("sector") or "Unassigned", by_sector)):
            b = bucket.setdefault(key, {"name": key, "assets": 0, "cves": 0, "kev": 0, "risk_sum": 0.0, "high": 0})
            b["assets"] += 1; b["cves"] += len(cves); b["kev"] += kev
            b["risk_sum"] += float(risks.loc[a["asset_id"], "risk"]); b["high"] += int(risks.loc[a["asset_id"], "risk"] >= 15)
    for b in list(by_zone.values()) + list(by_sector.values()):
        b["avg_risk"] = round(b.pop("risk_sum") / b["assets"], 1)
    return {"choke_points": chokes, "central_assets": central, "per_entry": per_entry,
            "by_zone": list(by_zone.values()), "by_sector": list(by_sector.values()),
            "expected_harm": ev["expected_harm"], "worst_harm": ev["worst_harm"], "first_failure_min": ev["first_failure_min"]}


@app.get("/api/analytics")
def analytics():
    return _analytics_cached()


# ---------- ML status (honest: shows only what exists) ----------
@app.get("/api/ml")
def ml_status():
    from load_graph import DATA
    t = base_tables()
    v = t["vulns.csv"]
    has_col = "exploit_prob" in v.columns
    filled = int(v["exploit_prob"].notna().sum()) if has_col else 0
    sources = {"ML model": 0, "CISA KEV (0.9)": 0, "EPSS": 0, "default 0.05": 0}
    rows = []
    for _, r in v.iterrows():
        ml = has_col and not pd.isna(r["exploit_prob"])
        src = "ML model" if ml else ("CISA KEV (0.9)" if int(r["kev"]) == 1 else ("EPSS" if not pd.isna(r["epss"]) else "default 0.05"))
        sources[src] += 1
        rows.append({"cve_id": r["cve_id"], "cvss": num(r["cvss"]), "kev": bool(int(r["kev"])),
                     "epss": None if pd.isna(r["epss"]) else float(r["epss"]),
                     "exploit_prob": float(r["exploit_prob"]) if ml else None,
                     "why": (str(r["why"]) if "why" in v.columns and not pd.isna(r.get("why")) else None),
                     "used": round(cve_exploit_prob(r), 4), "source": src})
    card, metrics = None, None
    for name in ("ml_model_card.json", "model_card.json"):
        if (DATA / name).exists():
            card = json.loads((DATA / name).read_text())
    for name in ("ml_metrics.json", "metrics.json"):
        if (DATA / name).exists():
            metrics = json.loads((DATA / name).read_text())
    status = "live" if filled else ("column present but empty" if has_col else "not delivered yet")
    return {"status": status, "has_column": has_col, "filled": filled, "total": len(v), "sources": sources,
            "rows": rows, "model_card": card, "metrics": metrics,
            "contract": "vulns.csv gains a column exploit_prob (0-1) per CVE, optional column why (short reason). "
                        "Optional files next to the data: ml_model_card.json (model, features, training data, version) "
                        "and ml_metrics.json (evaluation results measured by the model owner)."}


# ---------- upload validation (checks a dataset without replacing the live one) ----------
class ValidateRequest(BaseModel):
    files: dict = Field(..., description="file name -> CSV text")


@app.post("/api/validate")
def validate_upload(req: ValidateRequest):
    allowed = {"assets.csv", "links.csv", "services.csv", "vulns.csv"}
    unknown = [k for k in req.files if k not in allowed]
    if unknown:
        raise HTTPException(400, f"Only {sorted(allowed)} can be checked. Got {unknown}.")
    if sum(len(x) for x in req.files.values()) > 5_000_000:
        raise HTTPException(413, "Files too large (5 MB total).")
    from load_graph import DATA, load_and_validate as lav
    from simulate import compile_rule
    with tempfile.TemporaryDirectory() as d:
        for f in allowed:          # anything not uploaded is taken from the live dataset, so one file can be checked
            src = req.files.get(f)
            (Path(d) / f).write_text(src if src is not None else (DATA / f).read_text())
        try:
            tables, errors = lav(d)
        except Exception as exc:
            return {"ok": False, "errors": [f"Could not read the CSV: {exc}"], "checked": sorted(req.files)}
        warnings = []
        if not errors:
            ids = set(tables["assets.csv"]["asset_id"])
            for _, s in tables["services.csv"].iterrows():
                try:
                    compile_rule(s["required_logic"], ids)
                except ValueError as exc:
                    errors.append(str(exc))
            if "monitored" not in tables["assets.csv"].columns:
                warnings.append("assets.csv has no 'monitored' column: every asset counts as unmonitored.")
            if not any(int(x) for x in tables["assets.csv"]["internet_facing"]) and not any(int(x) for x in tables["assets.csv"]["vendor_access"]):
                warnings.append("No asset is internet-facing or vendor-accessible: there is no way in for an attacker.")
        summary = {k: len(v) for k, v in tables.items() if not k.startswith("_")}
    return {"ok": not errors, "errors": errors, "warnings": warnings, "rows": summary, "checked": sorted(req.files),
            "note": "Checked only. The live dataset is not replaced; to switch, put the files in a folder and set CASCADE_DATA."}


# ---------- public (landing page): counts and an abstract topology, no names ----------
@app.get("/api/public/hero")
def public_hero():
    t = base_tables()
    m = compile_model(t)
    pos, _ = layout(t["assets.csv"])
    meta = asset_metadata()
    idx = {a: i for i, a in enumerate(t["assets.csv"]["asset_id"])}
    nm = _names(t)
    nodes = [{"id": a, "name": nm[a], "x": round(pos[a][0], 1), "z": round(pos[a][1], 1), "sector": meta.get(a, {}).get("sector") or z,
              "entry": a in m["entries"], "crit": int(c)}
             for a, z, c in zip(t["assets.csv"]["asset_id"], t["assets.csv"]["zone"], t["assets.csv"]["criticality"])]
    links = [[idx[l["src"]], idx[l["dst"]], l["link_type"] in config.SPREAD_LINK_TYPES] for _, l in t["links.csv"].iterrows()]
    v = t["vulns.csv"]
    return {"nodes": nodes, "links": links,
            "counts": {"assets": len(nodes), "links": len(links), "services": len(t["services.csv"]),
                       "cves": len(v), "kev": int(v["kev"].astype(int).sum()),
                       "sectors": len({n["sector"] for n in nodes}),
                       "people": int(t["services.csv"]["population_affected"].sum())}}


@app.get("/api/public/headline")
def public_headline():
    """For the landing page: the CVSS-only vs Cascade comparison, only if it has already been computed."""
    from load_graph import DATA
    if not _baseline_cached.cache_info().currsize:
        return {"ready": False}
    b = _baseline_cached(5)
    by = {s["key"]: s["points"] for s in b["strategies"]}
    vul = base_tables()["vulns.csv"].set_index("cve_id")
    first_cvss = by["cvss"][1]
    asset = base_tables()["assets.csv"].set_index("asset_id").loc[first_cvss["fix"].split(":", 1)[1]]
    return {"ready": True, "k": b["k_max"], "dataset": DATA.name, "base_worst": by["cvss"][0]["worst"],
            "cvss": {"first_label": first_cvss["label"], "worst_after": by["cvss"][-1]["worst"],
                     "first_cvss": max(float(vul.loc[c, "cvss"]) for c in split_list(asset["cve_ids"]))},
            "cascade": {"first_label": by["cascade"][1]["label"], "worst_after_1": by["cascade"][1]["worst"],
                        "worst_after": by["cascade"][-1]["worst"]}}


# ---------- public data for the landing page (simulated city, no credentials needed) ----------
@lru_cache(maxsize=1)
def _landing_cached():
    t = base_tables()
    m = compile_model(t)
    names = _names(t)
    ev = evaluate(t)
    worst = ev["worst_entry"]
    run = simulate_full(t, {worst: 0}) if worst else {"failures": {}, "compromised": {}, "parents": {}}
    pop = {s["name"]: int(s["population_affected"]) for _, s in t["services.csv"].iterrows()}
    services = [{"name": n, "people": pop[n], "fail_at": run["failures"].get(n)} for n in pop]
    events = []
    for a, tm in sorted(run["compromised"].items(), key=lambda kv: kv[1]):
        if tm <= config.HORIZON_MIN:
            p = run["parents"][a]
            events.append({"t": tm, "text": f"{names[a]} compromised" + (f" from {names[p]}" if p else " (way in)")})
    for n, tm in run["failures"].items():
        if tm <= config.HORIZON_MIN:
            events.append({"t": tm, "text": f"{n} lost", "lost": True})
    events.sort(key=lambda e: e["t"])
    # spotlight: the worst way in, as an X-ray card
    spot = None
    if worst:
        a = t["assets.csv"].set_index("asset_id").loc[worst]
        vul = t["vulns.csv"].set_index("cve_id")
        links = t["links.csv"]
        spot = {"id": worst, "name": a["name"], "type": a["type"], "software": a["software"], "version": str(a["version"]),
                "cves": [{"id": c, "cvss": num(vul.loc[c, "cvss"]), "epss": num(vul.loc[c, "epss"]), "kev": bool(int(vul.loc[c, "kev"]))}
                         for c in split_list(a["cve_ids"])],
                "connects_to": sorted({names[x] for x in links.loc[links["src"] == worst, "dst"]} | {names[x] for x in links.loc[links["dst"] == worst, "src"]}),
                "flags": split_list(a["config_flags"]), "harm": ev["per_entry"][worst]["harm"]}
    water_pub = None
    if water.available():
        mc = water.model_card()
        h = water.hourly()
        d = h[(h["timestamp"] >= "2016-12-05 19:00") & (h["timestamp"] <= "2016-12-10 16:00")]
        tst = mc["held_out_test_attacks_4_7_evaluated_once"]
        water_pub = {"scores": d["display_score_0_100"].round(1).tolist(), "alerts": d["alert"].astype(bool).tolist(),
                     "t": [str(x)[:16] for x in d["timestamp"]], "events": len(water.events()),
                     "test": {"detected": tst["attacks_detected"], "fa_per_7d": tst["false_alarms_per_7d_strict"],
                              "precision": tst["precision"], "recall": tst["recall"]},
                     "banner": water.BANNER}
    return {"worst_harm": ev["worst_harm"], "expected_harm": ev["expected_harm"], "first_failure_min": ev["first_failure_min"],
            "worst_entry": worst, "worst_entry_name": names.get(worst), "services": services, "events": events[:24],
            "spotlight": spot, "water": water_pub, "horizon_min": config.HORIZON_MIN,
            "entries": [{"id": e, "name": names[e]} for e in m["entries"]]}


@app.get("/api/public/landing")
def public_landing():
    d = dict(_landing_cached())
    d["optimizer"] = None
    if _optimize_cached.cache_info().currsize:
        base, res = _optimize_cached(3, 2, None, 1, 1.0)
        d["optimizer"] = {"labels": res[0]["labels"], "worst_before": base["worst_harm"], "worst_after": res[0]["worst_harm"],
                          "expected_before": base["expected_harm"], "expected_after": res[0]["expected_harm"]}
    return d


class PublicAttack(BaseModel):
    entry: str = Field(..., max_length=20)
    protect: bool = False


@app.post("/api/public/attack")
def public_attack(req: PublicAttack):
    """Landing-page demo: one attacker from any system, optionally with the optimiser's recommended bundle applied."""
    t = base_tables()
    if req.entry not in set(t["assets.csv"]["asset_id"]):
        raise HTTPException(400, "Unknown system")
    fixes, scope = [], None
    if req.protect:
        # the best (up to) 3 fixes against THIS attack. The optimiser's city-wide bundle targets the worst and the
        # expected case and often changes nothing for an attack from somewhere else, which made before = after.
        fixes, scope = list(_protect_for(req.entry)), "this attack"
    tt, _ = with_fixes(fixes)
    r = simulate_multi(tt, [{"id": "A", "entry": req.entry, "start": 0}])
    a = r["attackers"][0]
    return {"times": {k: v["t"] for k, v in r["combined"]["first_by"].items()},
            "parents": a["parents"],                        # who infected each system (None = the way in)
            "services": r["combined"]["services"], "events": r["events"], "isolations": r["isolations"],
            "harm": r["combined"]["harm"], "first_failure_min": r["combined"]["first_failure_min"],
            "detected_at": r["detected_at"], "horizon_min": r["horizon_min"], "fixes": fixes, "scope": scope,
            "fix_labels": [fix_lookup(t)[f]["label"] for f in fixes],
            "note": (None if not req.protect or fixes else
                     "No fix in the model reduces this attack: it starts on the system that matters, or nothing it "
                     "reaches can be patched, segmented or monitored in time. The defence here is stopping the foothold.")}


@lru_cache(maxsize=128)
def _protect_for(entry, k=3):
    """Greedy: add the fix that removes the most harm from an attack starting at `entry`, up to k fixes; stop when
    no fix helps. Same engine and same harm as everywhere else."""
    t = base_tables()
    def score(tab):
        r = simulate_full(tab, {entry: 0})
        return (scenario_harm(tab, r["failures"]), -min(r["failures"].values(), default=config.HORIZON_MIN))
    cur, chosen = score(t), []
    for _ in range(k):
        best = None
        for fx in candidates(t):
            if fix_id(fx) in chosen:
                continue
            sc = score(apply(t, fx))
            if sc < cur and (best is None or sc < best[0]):
                best = (sc, fx)
        if best is None:
            break
        cur, t = best[0], apply(t, best[1])
        chosen.append(fix_id(best[1]))
        if cur[0] == 0:
            break
    return tuple(chosen)


@app.get("/api/public/attack/ready")
def public_attack_ready():
    """Whether the Protect button will answer instantly (optimiser already cached) or needs a first computation."""
    return {"optimizer_cached": True}     # protect now uses a per-attack search that takes well under a second


# ---------- decision insights: exposure score, roadmap, uncertainty, attack paths, compliance ----------
import insights


def _plan_fixes():
    """The ordered 5-fix plan from the baseline comparison (Cascade, any fix type)."""
    b = _baseline_cached(5)
    pts = next(s for s in b["strategies"] if s["key"] == "cascade")["points"][1:]
    lookup = fix_lookup(base_tables())
    return [lookup[p["fix"]] for p in pts if p.get("fix") in lookup]


@app.get("/api/insights/exposure")
def insights_exposure():
    t = base_tables()
    ev = evaluate(t)
    sc = insights.exposure_score(t, ev)
    worst = simulate_full(t, {ev["worst_entry"]: 0}) if ev["worst_entry"] else {"failures": {}}
    pop = {s["name"]: float(s["population_affected"]) for _, s in t["services.csv"].iterrows()}
    by_service = [{"service": n, "harm": pop[n] * max(0.0, config.HORIZON_MIN - f)} for n, f in worst["failures"].items() if f < config.HORIZON_MIN]
    return {**sc, "ceiling": insights.max_harm(t), "worst_harm": ev["worst_harm"], "expected_harm": ev["expected_harm"],
            "by_service": sorted(by_service, key=lambda x: -x["harm"])}


@lru_cache(maxsize=16)
def _roadmap_cached(staff, every):
    return insights.roadmap(base_tables(), _plan_fixes(), staff_per_week=staff, window_every_weeks=every)


@app.get("/api/insights/roadmap")
def insights_roadmap(staff: float = Query(8.0, ge=1, le=80, description="staff hours per week"),
                     window_weeks: int = Query(2, ge=1, le=8, description="weeks between maintenance windows")):
    r = dict(_roadmap_cached(staff, window_weeks))
    r["staff_hours_by_fix"] = config.FIX_STAFF_HOURS
    return r


@lru_cache(maxsize=1)
def _mc_raw():
    t = base_tables()
    plan = _plan_fixes()
    best = _optimize_cached(3, 2, None, 1, 1.0)[1][0]["bundle"]
    return insights.monte_carlo(t, runs=200, bundles={"Optimiser bundle (3 fixes)": best, "Five-fix plan": plan})


def _mc_cached():
    if _mc_raw.cache_info().currsize:
        return _mc_raw()
    _plan_fixes(); _optimize_cached(3, 2, None, 1, 1.0)      # compute dependencies first (normal reads)
    MODEL_LOCK.w_acquire()
    try:
        return _mc_raw()
    finally:
        MODEL_LOCK.w_release()


@app.get("/api/insights/montecarlo")
def insights_mc():
    return _mc_cached()


@lru_cache(maxsize=1)
def _paths_cached():
    return insights.attack_paths(base_tables())


@app.get("/api/insights/paths")
def insights_paths():
    return _paths_cached()


@app.get("/api/insights/compliance")
def insights_compliance():
    plan = _plan_fixes()
    best = _optimize_cached(3, 2, None, 1, 1.0)[1][0]["bundle"]
    rows = lambda fx: [{"fix": f"{f['fix']}:{f['target']}", "label": f["label"], "type": f["fix"], **insights.COMPLIANCE[f["fix"]]} for f in fx]
    return {"mapping": insights.COMPLIANCE, "note": insights.COMPLIANCE_NOTE, "optimiser_bundle": rows(best), "plan": rows(plan)}


# ---------- recovery: after containment, how long until each service is back ----------
import recovery as _recovery


@lru_cache(maxsize=64)
def _recovery_cached(entry, crews, backups):
    t = base_tables()
    if crews == 2 and backups:
        return _recovery.summary(t, entry)
    return _recovery.plan(t, entry, crews, backups)


@app.get("/api/recovery")
def get_recovery(entry: Optional[str] = Query(None, max_length=40), crews: int = Query(2, ge=1, le=8),
                 backups: bool = True):
    """Restoration schedule after the attacker is cut off. Default: the worst single way in, 2 crews, with backups."""
    t = base_tables()
    entry = entry or _overview_worst_entry()
    if entry not in set(t["assets.csv"]["asset_id"]):
        raise HTTPException(404, f"Unknown asset '{entry}'")
    return _recovery_cached(entry, int(crews), bool(backups))


@lru_cache(maxsize=1)
def _overview_worst_entry():
    return evaluate(base_tables())["worst_entry"]


import assumptions as _assumptions


@app.get("/api/assumptions")
def get_assumptions():
    """Every modelled number in one place, with its basis and how it was tested."""
    return _assumptions.register()


# ---------- water anomaly monitoring (SENTINEL Model C, historical replay) + rule layer ----------
import water


def _need_water():
    if not water.available():
        raise HTTPException(404, "Water anomaly package not found. Put the integration files in ml_water/ (see README).")


@lru_cache(maxsize=1)
def _water_summary():
    return water.summary()


@app.get("/api/water/summary")
def water_summary():
    if not water.available():
        return {"available": False}
    return _water_summary()


@app.get("/api/water/hourly")
def water_hourly(start: Optional[str] = None, end: Optional[str] = None):
    _need_water()
    import pandas as pd
    for name, v in (("start", start), ("end", end)):
        if v:
            try:
                pd.Timestamp(v)
            except (ValueError, TypeError):
                raise HTTPException(400, f"'{name}' must be a date like 2016-09-01 or 2016-09-01T12:00")
    return water.hourly_compact(start, end)


@app.get("/api/water/events")
def water_events():
    _need_water()
    return {"banner": water.BANNER, "events": water.events(), "rule_episodes": water.envelope()["episodes"]}


@app.get("/api/water/signal/{sig}")
def water_signal(sig: str, start: Optional[str] = None, end: Optional[str] = None):
    _need_water()
    try:
        return water.signal_series(sig, start, end)
    except KeyError:
        raise HTTPException(404, f"No signal {sig}")


@app.get("/api/water/demo")
def water_demo():
    _need_water()
    return water.demo()


# ---------- operator decisions: an audit trail of every human (or failsafe) action ----------
class Decision(BaseModel):
    context: str = Field(..., max_length=200)
    action: str = Field(..., max_length=200)
    decision: str = Field(..., pattern="^(acknowledged|approved|rejected|dismissed|escalated|auto_failsafe|note)$")
    reason: str = Field("", max_length=500)
    sim_time: Optional[str] = Field(None, max_length=40)


import threading as _threading
_AUDIT_LOCK = _threading.Lock()


def _audit_append(rec):
    """Append one record to the hash-chained audit log (shared by operator decisions and the live testbed)."""
    import hashlib
    auth.STORE_DIR.mkdir(exist_ok=True)
    p = auth.STORE_DIR / "audit.jsonl"
    with _AUDIT_LOCK:
        prev = "0" * 64
        if p.exists():
            lines = [x for x in p.read_text().splitlines() if x.strip()]
            if lines:
                prev = json.loads(lines[-1]).get("hash", prev)
        rec["prev"] = prev
        rec["hash"] = hashlib.sha256((prev + json.dumps({k: v for k, v in rec.items() if k not in ("hash",)}, sort_keys=True)).encode()).hexdigest()
        with open(p, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return rec


@app.post("/api/ops/log")
def ops_log(d: Decision, request: Request):
    import time as _t
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    rec = {**d.model_dump(), "by": s["u"] if s else "operator (sign-in off)", "at": _t.strftime("%Y-%m-%d %H:%M:%S")}
    return _audit_append(rec)


def verify_audit_chain(lines):
    """Each entry stores the SHA-256 of (previous hash + its own content). Editing or deleting any entry breaks the chain."""
    import hashlib
    prev = "0" * 64
    legacy = 0
    while legacy < len(lines) and "hash" not in json.loads(lines[legacy]):
        legacy += 1                                   # entries from before hash chaining existed (older version)
    for i, line in enumerate(lines[legacy:], legacy + 1):
        rec = json.loads(line)
        if "hash" not in rec:
            return {"ok": False, "entries": len(lines), "broken_at": i, "reason": "unchained entry inserted"}
        body = {k: v for k, v in rec.items() if k != "hash"}
        want = hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
        if rec.get("prev") != prev or rec["hash"] != want:
            return {"ok": False, "entries": len(lines), "broken_at": i, "reason": "entry changed, removed or reordered"}
        prev = rec["hash"]
    return {"ok": True, "entries": len(lines) - legacy, "legacy_unchained": legacy, "head": prev}


@app.get("/api/ops/verify")
def ops_verify():
    p = auth.STORE_DIR / "audit.jsonl"
    lines = [x for x in p.read_text().splitlines() if x.strip()] if p.exists() else []
    return verify_audit_chain(lines)


@app.get("/api/ops/log")
def ops_log_list():
    p = auth.STORE_DIR / "audit.jsonl"
    rows = [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []
    return {"rows": rows[-200:][::-1]}


@app.get("/api/failsafe/policy")
def failsafe_policy():
    return {"operator_ack_min": config.OPERATOR_ACK_MIN, "auto": config.FAILSAFE_AUTO, "c2": config.FAILSAFE_C2_ASSUMPTION,
            "response_delay_min": config.RESPONSE_DELAY_MIN, "lost_zones": sorted(__import__("multi").ISLAND_LOST_ZONES)}


# ---------- 2FA login ----------
class Creds(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class Code(BaseModel):
    code: str = Field(..., max_length=32)


class DisableReq(BaseModel):
    password: str = Field(..., max_length=256)
    code: str = Field(..., max_length=32)


def _set_cookie(resp, user, stage):
    resp.set_cookie(COOKIE, auth.make_session(user, stage), httponly=True, samesite="strict",
                    max_age=auth.SESSION_HOURS * 3600, path="/")


def _session(request, stage="full"):
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    if not s or (stage == "full" and s["s"] != "full"):
        raise HTTPException(401, "Sign in required")
    return s


@app.get("/api/auth/status")
def auth_status(request: Request):
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    st = auth.status(s["u"] if s and s["s"] == "full" else None)
    st["stage"] = s["s"] if s else None
    return st


@app.post("/api/auth/setup")
def auth_setup(c: Creds, response: Response):
    try:
        user = auth.create_account(c.username, c.password)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(400, str(exc))
    _set_cookie(response, user, "full")
    return {"ok": True, "user": user}


@app.post("/api/auth/login")
def auth_login(c: Creds, response: Response):
    try:
        user, stage = auth.login_password(c.username, c.password)
    except PermissionError as exc:
        raise HTTPException(401, str(exc))
    _set_cookie(response, user, stage)
    return {"ok": True, "next": "code" if stage == "pw" else "done"}


@app.post("/api/auth/code")
def auth_code(c: Code, request: Request, response: Response):
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    if not s or s["s"] != "pw":
        raise HTTPException(401, "Enter your password first")
    try:
        how = auth.login_code(s["u"], c.code)
    except PermissionError as exc:
        raise HTTPException(401, str(exc))
    _set_cookie(response, s["u"], "full")
    return {"ok": True, "used": how, "recovery_left": auth.status(s["u"])["recovery_left"]}


@app.post("/api/auth/logout")
def auth_logout(response: Response):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/2fa/start")
def twofa_start(request: Request):
    s = _session(request)
    secret, uri = auth.start_enrolment(s["u"])
    return {"secret": secret, "uri": uri}


@app.post("/api/auth/2fa/confirm")
def twofa_confirm(c: Code, request: Request):
    s = _session(request)
    try:
        codes = auth.confirm_enrolment(s["u"], c.code)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "recovery_codes": codes}


@app.post("/api/auth/2fa/disable")
def twofa_disable(d: DisableReq, request: Request):
    s = _session(request)
    try:
        auth.disable_2fa(s["u"], d.password, d.code)
    except PermissionError as exc:
        raise HTTPException(401, str(exc))
    return {"ok": True}


# ---------- pages ----------
app.mount("/vendor", StaticFiles(directory=FRONTEND / "vendor"), name="vendor")
app.mount("/static", StaticFiles(directory=FRONTEND / "static"), name="static")


# ---------- electricity attack screening (benchmark sample explorer) and the per-sector ML status ----------
import electricity


def _need_elec():
    if not electricity.available():
        raise HTTPException(404, "Electricity screening package not found. Put the integration files in ml_electricity/ (see README).")


@app.get("/api/electricity/summary")
def elec_summary():
    if not electricity.available():
        return {"available": False}
    d = electricity.demo()
    return {"available": True, "model_card": electricity.model_card(), "explorer": electricity.explorer(),
            "mapping": electricity.mapping(), "banner": d["banner"], "warning": d["warning"],
            "explanation_note": d["explanation_note"]}


@app.get("/api/electricity/samples")
def elec_samples(file: Optional[str] = Query(None, max_length=20), block: Optional[int] = Query(None, ge=1, le=99),
                 label: Optional[str] = Query(None, max_length=30), outcome: Optional[str] = Query(None, max_length=30),
                 flag: Optional[bool] = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)):
    _need_elec()
    ok_out = {"attack_flagged", "attack_missed", "false_attack_flag", "correct", "non_attack_confusion"}
    ok_lab = {"normal_operation", "natural_disturbance", "cyberattack"}
    if outcome and outcome not in ok_out:
        raise HTTPException(400, f"outcome must be one of {sorted(ok_out)}")
    if label and label not in ok_lab:
        raise HTTPException(400, f"label must be one of {sorted(ok_lab)}")
    return electricity.query(file, block, label, outcome, flag, offset, limit)


@app.get("/api/electricity/demo")
def elec_demo():
    _need_elec()
    return electricity.demo()


@app.get("/api/ml/sectors")
def ml_sectors():
    return electricity.sector_status()


@app.get("/api/ml/evaluation")
def ml_evaluation():
    """Per-model criteria (fixed before training) against results, plus the IoT demonstration benchmark."""
    return electricity.evaluation()


# ---------- unknown-attack response: anomaly -> alarm -> "what if it is an attacker?" -> isolate -> human/failsafe ----------
@lru_cache(maxsize=1)
def _water_hours():
    return water.hourly_compact()


@lru_cache(maxsize=256)
def _novel_cached(hour, asset, respond_min, ack_min):
    H = _water_hours()
    if hour not in H["t"]:
        raise HTTPException(400, f"Unknown replay hour '{hour}'. Use one from GET /api/water/hourly (field t).")
    i = H["t"].index(hour)
    t = base_tables()
    ids = set(t["assets.csv"]["asset_id"])
    names = dict(zip(t["assets.csv"]["asset_id"], t["assets.csv"]["name"]))
    mp = {m["signal_id"]: m for m in water.mapping().to_dict("records")} if hasattr(water.mapping(), "to_dict") else {m["signal_id"]: m for m in water.mapping()}
    hot = [s for s in (H["top"][i] or []) if s["z"] >= H["threshold"]]
    rules = H["rules"][i] or []
    sigs = [s["signal"] for s in hot] + [r["signal"] for r in rules]
    split = lambda v: [a for a in str(v or "").split(";") if a and a != "nan" and a in ids]
    cands = []
    for sg in sigs:                     # the system the signal belongs to, if the city models one
        for a in split(mp.get(sg, {}).get("mapped_city_asset_ids")):
            if a not in [c["asset"] for c in cands]:
                cands.append({"asset": a, "name": names[a], "why": f"{sg} is measured or driven by this system"})
    for sg in sigs:                     # otherwise the systems that carry the signal to operators
        for a in split(mp.get(sg, {}).get("observed_via_city_assets")):
            if a not in [c["asset"] for c in cands]:
                cands.append({"asset": a, "name": names[a], "why": f"{sg} reaches operators through this system"})
    if asset and asset not in ids:
        raise HTTPException(400, f"Unknown asset '{asset}'")
    pick = asset or (cands[0]["asset"] if cands else None)
    alarm = {"hour": hour, "index": i, "level": H["level"][i], "score": H["score"][i], "threshold_display": 50,
             "ml_alert": bool(H["alert"][i]), "rule_alert": bool(H["rule_alert"][i]),
             "signals": [{"signal": s["signal"], "observed": s["observed"], "expected": s["predicted"], "z": s["z"], "zone": s["zone"]} for s in hot[:4]],
             "rules": [{"rule": r["rule"], "detail": r["detail"]} for r in rules[:4]]}
    if not pick:
        return {"alarm": alarm, "candidates": [], "asset": None, "options": [],
                "note": "Nothing is outside normal at this hour, so there is no foothold to test."}
    A = lambda **kw: [{"id": "A", "entry": pick, "start": 0, **kw}]
    runs = [("no_action", "Nobody acts on the alarm", "The network's own detection still isolates zones later.", A(), None),
            ("operator", f"Operator isolates the system after {respond_min:g} min", "A human confirms and cuts the suspected foothold off the network.", A(contain_at=respond_min), None),
            ("failsafe", f"Nobody answers: failsafe island mode after {ack_min:g} min", "Internet and vendor access cut automatically; insiders keep going.", A(), ack_min),
            ("both", f"Failsafe at {ack_min:g} min, then operator isolates at {ack_min + respond_min:g} min", "The timer acts first; the human finishes the job.", A(contain_at=ack_min + respond_min), ack_min)]
    options = []
    for key, title, text, atk, isl in runs:
        r = simulate_multi(t, atk, island=None if isl is None else {"at": isl, "c2": True})
        options.append({"key": key, "title": title, "text": text, "harm": r["combined"]["harm"],
                        "first_failure_min": r["combined"]["first_failure_min"], "assets_lost": r["combined"]["assets_lost"],
                        "services": [s for s in r["combined"]["services"] if s["population"] > 0],
                        "compromised": {k: v["t"] for k, v in r["combined"]["first_by"].items()},
                        "parents": r["attackers"][0]["parents"] if r["attackers"] else {}})
    return {"alarm": alarm, "candidates": cands, "asset": pick, "asset_name": names[pick], "options": options,
            "note": ("Assumption, not a finding: the anomaly is treated as an attacker already sitting on this system at the "
                     "alarm hour (T+0). An unknown attack has no CVE, so we do not model how it got in; onward spread uses "
                     "the same link model as every other simulation.")}


@app.get("/api/novel/whatif")
def novel_whatif(hour: str = Query(..., max_length=20), asset: Optional[str] = Query(None, max_length=40),
                 respond_min: float = Query(15, ge=1, le=240), ack_min: float = Query(None, ge=1, le=240)):
    """Unknown-attack response for one water alarm hour: who could be the foothold, and what each response saves."""
    _need_water()
    return _novel_cached(hour, asset or "", float(respond_min), float(ack_min or config.OPERATOR_ACK_MIN))


@app.get("/")
def landing():
    return FileResponse(FRONTEND / "landing.html")


@app.get("/app")
def platform():
    return FileResponse(FRONTEND / "app.html")


@app.get("/twin")
def twin():
    """The original 3D digital twin, unchanged. The app embeds it; it also works on its own."""
    return FileResponse(FRONTEND / "index.html")


@app.get("/login")
def login_page():
    return FileResponse(FRONTEND / "login.html")


# ---------- live attack testbed: emulated controller over real Modbus/TCP ----------
import asyncio as _asyncio
import live as _live
from fastapi.responses import StreamingResponse

_LIVE = {"dev": None}


def _live_asset():
    a = base_tables()["assets.csv"]
    for typ in ("water_controller", "plc"):
        m = a[a["type"] == typ]
        if len(m):
            return str(m.iloc[0]["asset_id"]), str(m.iloc[0]["name"])
    return str(a.iloc[0]["asset_id"]), str(a.iloc[0]["name"])


def _live_audit(**k):
    import time as _t
    try:
        _audit_append({**k, "by": "live testbed", "at": _t.strftime("%Y-%m-%d %H:%M:%S"), "sim_time": None})
    except Exception:
        pass


@app.on_event("startup")
def _start_live():
    aid, name = _live_asset()
    _LIVE["dev"] = _live.from_env(aid, name, _live_audit, config.FAILSAFE_AUTO)


def _dev():
    d = _LIVE["dev"]
    if d is None:
        raise HTTPException(503, "The live testbed is " + _live.enabled_reason()[1])
    return d


def _live_guard(request: Request):
    """Every state-changing live endpoint: same-origin only, and either a direct loopback request (the presenter's own
    laptop) or a signed-in session. Behind a proxy (X-Forwarded-For) a request is never treated as local."""
    origin = request.headers.get("origin")
    if origin:
        from urllib.parse import urlparse
        if urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(403, "Cross-site request refused.")
    client = request.client.host if request.client else ""
    forwarded = any(request.headers.get(h) for h in ("x-forwarded-for", "x-real-ip", "forwarded"))
    if client in _live.LOOPBACK and not forwarded:
        return None
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    if not s:
        raise HTTPException(401, "Sign in to control the live testbed from another machine.")
    return s


@lru_cache(maxsize=8)
def _live_spread(asset):
    t = base_tables()
    r = simulate_full(t, {asset: 0})
    names = _names(t)
    return {"asset": asset, "compromised": r["compromised"], "parents": r["parents"], "failures": r["failures"],
            "detected_at": r["detected_at"], "names": {k: names[k] for k in r["compromised"]},
            "note": "SIMULATED: what happens if the attacker on this controller keeps going. The controller attack itself is live; "
                    "everything beyond it is the model."}


@app.get("/api/live/state")
def live_state(all_packets: bool = False):
    d = _LIVE["dev"]
    if d is None:
        return {"running": False, "error": _live.enabled_reason()[1] or "not started"}
    return d.snapshot(packets=120, hide_hmi_reads=not all_packets)


@app.get("/api/live/status")
def live_status():
    """Small, for the site-wide pill and the twin: is there a live alarm right now?"""
    d = _LIVE["dev"]
    if d is None:
        return {"running": False}
    with d.lock:
        inc = d.incident
        return {"running": d.server is not None, "status": d.status, "asset": d.asset, "asset_name": d.asset_name,
                "level_cm": round(d.level, 1), "isolated": d.isolated,
                "incident": None if not inc else {"id": inc["id"], "state": inc["state"], "opened_at": inc["opened_at"],
                                                   "first": next((a["technique"] for a in d.alerts if a["id"] == inc["first_alert"]), None)}}


@app.get("/api/live/stream")
async def live_stream(request: Request):
    """Server-sent events: one state snapshot every half second while the page is open."""
    d = _dev()

    async def gen():
        last = None
        n = 0
        while not await request.is_disconnected():
            s = json.dumps(d.snapshot(packets=40))
            if s != last or n % 10 == 0:
                yield f"data: {s}\n\n"
                last = s
            n += 1
            await _asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class LiveDecision(BaseModel):
    decision: str = Field(..., pattern="^(isolate|dismiss)$")


@app.post("/api/live/decide")
def live_decide(body: LiveDecision, request: Request):
    _live_guard(request)
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    if not _dev().decide(body.decision, by=s["u"] if s else "operator"):
        raise HTTPException(409, "There is no alarm waiting for a decision.")
    return _dev().snapshot()


@app.post("/api/live/restore")
def live_restore(request: Request):
    _live_guard(request)
    s = auth.read_session(request.cookies.get(COOKIE, ""))
    d = _dev()
    if not d.isolated:
        raise HTTPException(409, "Isolate the controller first: restoring settings while the attacker can still write would be undone.")
    d.restore(by=s["u"] if s else "operator")
    return d.snapshot()


@app.post("/api/live/close")
def live_close(request: Request):
    _live_guard(request)
    d = _dev()
    d.close_incident()
    return d.snapshot()


class LiveSis(BaseModel):
    on: bool


@app.post("/api/live/sis")
def live_sis(body: LiveSis, request: Request):
    _live_guard(request)
    d = _dev()
    with d.lock:
        d.sis_on = bool(body.on)
        if not d.sis_on:
            d.sis_tripped = False
    return d.snapshot()


@app.get("/api/live/spread")
def live_spread():
    d = _dev()
    return _live_spread(d.asset)
