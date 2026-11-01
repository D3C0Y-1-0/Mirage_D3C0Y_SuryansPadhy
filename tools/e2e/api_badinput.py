"""Every endpoint with bad input must answer a clear 4xx (never 5xx, never a hang).
Usage (server on :8000, auth off or no account yet):  python tools/e2e/api_badinput.py"""
import json, sys, urllib.request, urllib.error

BASE = "http://localhost:8000"
BIG = 1e12


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]


CASES = [
    ("POST", "/api/simulate", {"entry_points": ["NOPE"]}),
    ("POST", "/api/simulate", {"entry_points": []}),
    ("POST", "/api/simulate", {"entry_points": ["EL01"], "speed": BIG}),
    ("POST", "/api/simulate", {"entry_points": ["EL01"], "fixes": ["nope"]}),
    ("POST", "/api/simulate", "not json"),
    ("POST", "/api/optimize", {"max_fixes": 999}),
    ("POST", "/api/optimize", {"max_fixes": -1}),
    ("GET", "/api/asset/NOPE", None),
    ("POST", "/api/containment", {"entry_points": ["NOPE"]}),
    ("POST", "/api/containment", {"entry_points": []}),
    ("POST", "/api/multi", {"attackers": []}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "NOPE"}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A"}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01", "start": BIG}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01", "speed": 0}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01"}] * 7}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entries": [{"asset": "EL01", "start": -5}]}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01"}], "island_at": BIG}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01"}], "maintenance": [{"asset": "NOPE"}]}),
    ("POST", "/api/multi", {"attackers": [{"id": "A", "entry": "EL01"}], "maintenance": [{"asset": "EL01", "hours": BIG}]}),
    ("GET", "/api/multi/presets?speed=abc", None),
    ("POST", "/api/validate", {"nope": 1}),
    ("POST", "/api/public/attack", {"entry": "NOPE"}),
    ("POST", "/api/public/attack", {"entry": "X" * 500}),
    ("POST", "/api/public/attack", {}),
    ("GET", "/api/insights/roadmap?staff=-1", None),
    ("GET", "/api/insights/roadmap?staff=abc", None),
    ("GET", "/api/water/signal/NOPE", None),
    ("GET", "/api/water/hourly?start=abc", None),
    ("POST", "/api/ops/log", {}),
    ("POST", "/api/ops/log", {"action": "x" * 10000}),
    ("POST", "/api/auth/login", {"username": "", "password": ""}),
    ("POST", "/api/auth/code", {"code": "abc"}),
    ("POST", "/api/auth/2fa/confirm", {"code": "000000"}),
    ("GET", "/api/nope", None),
]

bad = 0
for m, path, body in CASES:
    if body == "not json":
        req = urllib.request.Request(BASE + path, data=b"{oops", method=m, headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=60); code, txt = 200, b""
        except urllib.error.HTTPError as e:
            code, txt = e.code, e.read()[:200]
    else:
        code, txt = call(m, path, body)
    ok = 400 <= code < 500
    if not ok:
        bad += 1
    print(f"{'ok ' if ok else 'BAD'} {code} {m} {path} {json.dumps(body)[:70] if body else ''} -> {txt[:110]!r}")
print("FAIL" if bad else "PASS", f"{len(CASES) - bad}/{len(CASES)} answered 4xx")
sys.exit(1 if bad else 0)
