"""Live attack testbed: an EMULATED pumping-station controller that speaks real Modbus/TCP, a legitimate HMI that
talks to it, and a detector that watches every request.

What is real: the network traffic (real Modbus/TCP frames over a real socket, from a separate attack script or from
another laptop), the detection (rules run on those frames as they arrive), and the response (isolation really refuses
the attacker's connection; recovery really rewrites the controller's registers).
What is not: the controller is a small Python program on this laptop with a toy tank model, not a utility device.
What happens beyond the controller (the rest of the city) is the usual simulation.

Register map (unit id ignored, all addresses 0-based):
  holding registers  0 level_cm (read-only)  1 high_setpoint_cm  2 low_setpoint_cm  3 pump_flow_pct (read-only)
  coils              0 pump_run  1 alarm_enable  2 manual_mode
  discrete inputs    0 high_level_alarm  1 overflowing  2 sis_tripped
"""
import asyncio
import collections
import os
import random
import struct
import threading
import time

TANK_CM, SIS_TRIP_CM, HIGH_ALARM_CM, PROCESS_LIMIT_CM = 500.0, 490.0, 450.0, 470.0
TICK_S, INFLOW_CM, OUTFLOW_CM = 0.5, 3.6, 1.2        # per tick: pump on = +3.6, demand = -1.2  (net +2.4 cm per tick)
BASELINE_S = 30                                       # learn normal behaviour from the HMI for this long
ACK_S = 20                                            # operator has this long to answer before the failsafe acts
GOOD = {"hr": {1: 420, 2: 180}, "co": {1: 1, 2: 0}}   # known-good configuration (restored on recovery)
FN = {1: "Read coils", 2: "Read discrete inputs", 3: "Read holding registers", 4: "Read input registers",
      5: "Write single coil", 6: "Write single register", 15: "Write multiple coils", 16: "Write multiple registers"}
WRITES = {5, 6, 15, 16}
READ_ONLY_HR = {0, 3}
RULES = {   # rule -> (severity, ATT&CK for ICS technique, mitigation that would stop it)  IDs checked on attack.mitre.org
    "new_master": ("notice", "T0848 Rogue Master", "M0807 Network Allowlists"),
    "scan": ("notice", "T0861 Point & Tag Identification", "M0807 Network Allowlists"),
    "unknown_write": ("alarm", "T1692.001 Unauthorized Message: Command Message", "M0800 Authorization Enforcement"),
    "unseen_point": ("alarm", "T0831 Manipulation of Control", "M0800 Authorization Enforcement"),
    "out_of_range": ("alarm", "T0836 Modify Parameter", "M0818 Validate Program Inputs"),
    "alarm_off": ("alarm", "T0878 Alarm Suppression", "M0800 Authorization Enforcement"),
    "process": ("alarm", "T0831 Manipulation of Control (seen in the process, not the network)", "M0812 Safety Instrumented Systems"),
}
RULE_TEXT = {
    "new_master": "A device that was not seen while learning normal behaviour is talking to the controller",
    "scan": "An unknown device is reading many different addresses: mapping the controller",
    "unknown_write": "A write command from a device that is not the HMI",
    "unseen_point": "A write to a point the HMI never writes",
    "out_of_range": "A setpoint outside the range learned from normal operation",
    "alarm_off": "The high-level alarm was switched off",
    "process": "Tank level is above every normal operating level",
}


class LiveDevice:
    def __init__(self, host="127.0.0.1", port=5020, asset=None, asset_name="", audit=None, failsafe_auto=True):
        self.host, self.port, self.asset, self.asset_name = host, port, asset, asset_name
        self.audit = audit or (lambda **k: None)
        self.failsafe_auto = failsafe_auto
        self.lock = threading.RLock()
        self.loop = None
        self.server = None
        self.error = None
        self.ready = threading.Event()
        self.reset(full=True)

    # ---------------- state ----------------
    def reset(self, full=False):
        with getattr(self, "lock", threading.RLock()):
            self.t0 = time.time()
            self.hr = {0: 300, 1: GOOD["hr"][1], 2: GOOD["hr"][2], 3: 0}
            self.co = {0: 0, 1: GOOD["co"][1], 2: GOOD["co"][2]}
            self.level = 300.0
            self.sis_on, self.sis_tripped, self.spilled_s = True, False, 0.0
            self.packets = collections.deque(maxlen=300)
            self.alerts = []
            self.incident = None
            self.isolated = False
            self.status = "learning" if full else "normal"
            self.seen_masters = set()
            self.reads_by = collections.defaultdict(collections.deque)
            self.hmi_ports = getattr(self, "hmi_ports", set())
            self.conns = getattr(self, "conns", {})
            if full:
                self.base = {"writes": set(), "range": {}, "learned": False, "requests": 0}
            self.version = getattr(self, "version", 0) + 1

    def now(self):
        return round(time.time() - self.t0, 2)

    def snapshot(self, packets=60, hide_hmi_reads=True):
        with self.lock:
            pk = [p for p in self.packets if not (hide_hmi_reads and p["master"] == "HMI" and p["fc"] not in WRITES)]
            inc = dict(self.incident) if self.incident else None
            if inc and inc["state"] == "awaiting_operator":
                inc["seconds_left"] = max(0, round(inc["deadline"] - time.time(), 1))
            return {
                "running": self.server is not None, "error": self.error, "host": self.host, "port": self.port,
                "asset": self.asset, "asset_name": self.asset_name, "t": self.now(), "status": self.status,
                "baseline": {"learned": self.base["learned"], "seconds": BASELINE_S, "progress": min(1, self.now() / BASELINE_S) if not self.base["learned"] else 1,
                             "writes": sorted(f"{'coil' if fc in (5, 15) else 'register'} {a}" for fc, a in self.base["writes"]),
                             "range": {str(k): v for k, v in self.base["range"].items()}, "requests": self.base["requests"]},
                "process": {"level_cm": round(self.level, 1), "tank_cm": TANK_CM, "high_alarm_cm": HIGH_ALARM_CM, "sis_trip_cm": SIS_TRIP_CM,
                            "high_sp": self.hr[1], "low_sp": self.hr[2], "pump": bool(self.co[0]), "alarm_enable": bool(self.co[1]),
                            "manual": bool(self.co[2]), "high_alarm": bool(self.co[1] and self.level >= HIGH_ALARM_CM),
                            "overflowing": self.level >= TANK_CM, "spilled_s": round(self.spilled_s, 1),
                            "sis_on": self.sis_on, "sis_tripped": self.sis_tripped},
                "isolated": self.isolated, "incident": inc, "alerts": self.alerts[-40:],
                "packets": pk[-packets:], "masters": sorted(self.seen_masters), "version": self.version,
                "ack_s": ACK_S, "failsafe_auto": self.failsafe_auto,
            }

    # ---------------- detection ----------------
    def _alert(self, rule, src, detail):
        sev, tech, mit = RULES[rule]
        a = {"id": len(self.alerts) + 1, "t": self.now(), "at": time.strftime("%H:%M:%S"), "rule": rule, "severity": sev,
             "technique": tech, "mitigation": mit, "text": RULE_TEXT[rule], "detail": detail, "src": src}
        self.alerts.append(a)
        if sev == "alarm" and self.incident is None:
            self.incident = {"id": int(time.time() * 1000), "opened_t": a["t"], "opened_at": a["at"], "first_alert": a["id"],
                             "state": "awaiting_operator", "deadline": time.time() + ACK_S, "src": src,
                             "asset": self.asset, "asset_name": self.asset_name, "decision": None, "decided_by": None}
            self.status = "alarm"
            self.audit(context=f"LIVE alarm on {self.asset_name}", action="Isolate the controller from unknown masters",
                       decision="escalated", reason=f"{tech}: {RULE_TEXT[rule]} ({detail}) from {src}")
        return a

    def _inspect(self, master, src, fc, addr, vals):
        """Run every rule on one request. vals: written values (writes) or quantity (reads)."""
        hits = []
        if master != "HMI":
            if src not in self.seen_masters:
                self.seen_masters.add(src)
                hits.append(self._alert("new_master", src, f"{FN.get(fc, fc)} at address {addr}"))
            if fc not in WRITES:
                q = self.reads_by[src]; now = time.time()
                for k in range(vals if isinstance(vals, int) else 1):
                    q.append((now, fc, addr + k))
                while q and now - q[0][0] > 10:
                    q.popleft()
                if len({(f, a) for _, f, a in q}) >= 15 and not any(x["rule"] == "scan" and x["src"] == src for x in self.alerts):
                    hits.append(self._alert("scan", src, f"{len({(f, a) for _, f, a in q})} addresses in 10 s"))
        if fc in WRITES:
            if not self.base["learned"] and master == "HMI":
                for k, v in enumerate(vals):
                    self.base["writes"].add((5 if fc in (5, 15) else 6, addr + k))
                    if fc in (6, 16):
                        lo, hi = self.base["range"].get(addr + k, (v, v)); self.base["range"][addr + k] = (min(lo, v), max(hi, v))
                return hits
            if master != "HMI":
                hits.append(self._alert("unknown_write", src, f"{FN[fc]} at {addr} = {vals}"))
            kind = 5 if fc in (5, 15) else 6
            for k, v in enumerate(vals):
                a = addr + k
                if (kind, a) not in self.base["writes"]:
                    hits.append(self._alert("unseen_point", src, f"{'coil' if kind == 5 else 'register'} {a} set to {v}"))
                if kind == 6 and a in self.base["range"]:
                    lo, hi = self.base["range"][a]
                    if v < lo - 30 or v > hi + 30:
                        hits.append(self._alert("out_of_range", src, f"register {a} = {v} (normal {lo}-{hi}, tolerance ±30)"))
                if kind == 5 and a == 1 and not v:
                    hits.append(self._alert("alarm_off", src, "coil 1 (alarm enable) = 0"))
        elif master == "HMI" and not self.base["learned"]:
            self.base["requests"] += 1
        return hits

    # ---------------- response ----------------
    def decide(self, decision, by="operator"):
        with self.lock:
            if not self.incident or self.incident["state"] != "awaiting_operator":
                return False
            self.incident["decision"], self.incident["decided_by"], self.incident["decided_t"] = decision, by, self.now()
            if decision == "isolate":
                self._isolate()
                self.incident["state"] = "isolated"
            else:
                self.incident["state"] = "dismissed"
                self.status = "normal"
            self.audit(context=f"LIVE alarm on {self.asset_name}", action="Isolate the controller from unknown masters",
                       decision={"isolate": "approved", "dismiss": "dismissed"}.get(decision, "note") if by != "failsafe" else "auto_failsafe",
                       reason=f"decided by {by} at T+{self.now():.0f} s")
            return True

    def _isolate(self):
        self.isolated = True
        self.status = "isolated"
        for port, w in list(self.conns.items()):
            if port not in self.hmi_ports and self.loop:
                self.loop.call_soon_threadsafe(w.close)     # the socket belongs to the server's event loop

    def restore(self, by="operator"):
        with self.lock:
            self.hr[1], self.hr[2] = GOOD["hr"][1], GOOD["hr"][2]
            self.co[1], self.co[2] = GOOD["co"][1], GOOD["co"][2]
            self.sis_tripped = False
            if self.incident:
                self.incident["state"] = "recovered"; self.incident["recovered_t"] = self.now()
            self.status = "recovered"
            self.audit(context=f"LIVE incident on {self.asset_name}", action="Restore known-good configuration",
                       decision="approved", reason=f"setpoints {GOOD['hr'][1]}/{GOOD['hr'][2]} cm, alarm on, auto mode; by {by}")
            return True

    def close_incident(self):
        with self.lock:
            keep = self.base
            self.reset(full=False)
            self.base = keep
            self.status = "normal" if keep["learned"] else "learning"

    # ---------------- process model ----------------
    def _tick(self):
        with self.lock:
            if not self.base["learned"] and self.now() >= BASELINE_S:
                self.base["learned"] = True
                if self.status == "learning":
                    self.status = "normal"
            if not self.co[2]:                                   # auto mode: the controller's own logic
                if self.level < self.hr[2]:
                    self.co[0] = 1
                elif self.level > self.hr[1]:
                    self.co[0] = 0
            if self.sis_on and self.level >= SIS_TRIP_CM:      # independent safety trip: not reachable over Modbus
                self.sis_tripped = True
            pump = self.co[0] and not self.sis_tripped
            self.level = max(0.0, min(TANK_CM + 5, self.level + (INFLOW_CM if pump else 0) - OUTFLOW_CM))
            if self.level >= TANK_CM:
                self.spilled_s += TICK_S
            self.hr[0], self.hr[3] = int(round(self.level)), 100 if pump else 0
            if self.level >= PROCESS_LIMIT_CM and not any(a["rule"] == "process" and self.now() - a["t"] < 15 for a in self.alerts):
                hi = self.base["range"].get(1, (0, GOOD["hr"][1]))[1]
                self._alert("process", "tank level sensor", f"level {self.level:.0f} cm; highest normal setpoint {hi} cm")
            inc = self.incident
            if inc and inc["state"] == "awaiting_operator" and time.time() >= inc["deadline"] and self.failsafe_auto:
                self.decide("isolate", by="failsafe")

    # ---------------- Modbus/TCP server ----------------
    def _reply(self, fc, addr, data):
        """Returns (pdu bytes, ok)."""
        if fc in (1, 2):
            qty = data
            src = self.co if fc == 1 else {0: int(self.co[1] and self.level >= HIGH_ALARM_CM), 1: int(self.level >= TANK_CM), 2: int(self.sis_tripped)}
            if qty < 1 or qty > 2000 or any(addr + k not in src for k in range(qty)):
                return bytes([fc | 0x80, 2]), False
            bits = [src[addr + k] for k in range(qty)]
            by = bytearray((qty + 7) // 8)
            for k, b in enumerate(bits):
                if b:
                    by[k // 8] |= 1 << (k % 8)
            return bytes([fc, len(by)]) + bytes(by), True
        if fc in (3, 4):
            qty = data
            if qty < 1 or qty > 125 or any(addr + k not in self.hr for k in range(qty)):
                return bytes([fc | 0x80, 2]), False
            return bytes([fc, 2 * qty]) + b"".join(struct.pack(">H", self.hr[addr + k]) for k in range(qty)), True
        if fc in (5, 15):
            vals = data
            if any(addr + k not in self.co for k in range(len(vals))):
                return bytes([fc | 0x80, 2]), False
            for k, v in enumerate(vals):
                self.co[addr + k] = 1 if v else 0
            return (bytes([5]) + struct.pack(">HH", addr, 0xFF00 if vals[0] else 0)) if fc == 5 else bytes([15]) + struct.pack(">HH", addr, len(vals)), True
        if fc in (6, 16):
            vals = data
            if any(addr + k not in self.hr or addr + k in READ_ONLY_HR for k in range(len(vals))):
                return bytes([fc | 0x80, 2]), False
            for k, v in enumerate(vals):
                self.hr[addr + k] = int(v)
            return (bytes([6]) + struct.pack(">HH", addr, vals[0])) if fc == 6 else bytes([16]) + struct.pack(">HH", addr, len(vals)), True
        return bytes([fc | 0x80, 1]), False

    @staticmethod
    def _parse(fc, pdu):
        if fc in (1, 2, 3, 4):
            addr, qty = struct.unpack(">HH", pdu[:4]); return addr, qty
        if fc == 5:
            addr, v = struct.unpack(">HH", pdu[:4]); return addr, [1 if v == 0xFF00 else 0]
        if fc == 6:
            addr, v = struct.unpack(">HH", pdu[:4]); return addr, [v]
        if fc == 15:
            addr, qty, n = struct.unpack(">HHB", pdu[:5]); raw = pdu[5:5 + n]
            return addr, [(raw[k // 8] >> (k % 8)) & 1 for k in range(qty)]
        if fc == 16:
            addr, qty, n = struct.unpack(">HHB", pdu[:5]); return addr, list(struct.unpack(">" + "H" * qty, pdu[5:5 + 2 * qty]))
        return 0, None

    async def _handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        src = f"{peer[0]}:{peer[1]}"
        port = peer[1]
        with self.lock:
            master = "HMI" if port in self.hmi_ports else "unknown"
            if self.isolated and master != "HMI":
                self.packets.append({"t": self.now(), "at": time.strftime("%H:%M:%S"), "src": src, "master": master, "fc": 0,
                                     "fname": "Connection", "addr": None, "value": None, "result": "refused (isolated)", "alerts": []})
                writer.close()
                return
            self.conns[port] = writer
        try:
            while True:
                head = await reader.readexactly(7)
                tid, pid, length, unit = struct.unpack(">HHHB", head)
                body = await reader.readexactly(length - 1)
                fc, pdu = body[0], body[1:]
                with self.lock:
                    master = "HMI" if port in self.hmi_ports else "unknown"
                    if self.isolated and master != "HMI":
                        self.packets.append({"t": self.now(), "at": time.strftime("%H:%M:%S"), "src": src, "master": master, "fc": fc,
                                             "fname": FN.get(fc, f"Function {fc}"), "addr": None, "value": None, "result": "refused (isolated)", "alerts": []})
                        break
                    try:
                        addr, data = self._parse(fc, pdu)
                    except struct.error:
                        addr, data = 0, None
                    if data is None:
                        resp, ok = bytes([fc | 0x80, 1 if fc not in FN else 3]), False
                        hits = []
                    else:
                        hits = self._inspect(master, src, fc, addr, data)
                        resp, ok = self._reply(fc, addr, data)
                    self.packets.append({"t": self.now(), "at": time.strftime("%H:%M:%S"), "src": src, "master": master, "fc": fc,
                                         "fname": FN.get(fc, f"Function {fc}"), "addr": addr,
                                         "value": data if fc in WRITES else (f"x{data}" if data is not None else None),
                                         "result": "ok" if ok else f"exception {resp[1]}", "alerts": [h["id"] for h in hits]})
                writer.write(struct.pack(">HHHB", tid, pid, len(resp) + 1, unit) + resp)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            with self.lock:
                self.conns.pop(port, None)
            try:
                writer.close()
            except Exception:
                pass

    # ---------------- the legitimate HMI ----------------
    async def _hmi(self):
        """A real Modbus client on the same socket path: polls every second, nudges the high setpoint now and then."""
        rng = random.Random(7)
        while True:
            try:
                reader, writer = await asyncio.open_connection(self.host if self.host != "0.0.0.0" else "127.0.0.1", self.port)
                with self.lock:
                    self.hmi_ports.add(writer.get_extra_info("sockname")[1])
                tid, k = 0, 0
                while True:
                    tid = (tid + 1) % 65536
                    if k % 8 == 3 and not self.base["learned"]:
                        # the operator tunes the high setpoint while normal behaviour is being learned; afterwards the
                        # HMI only reads, as a real HMI does until someone changes something
                        req = struct.pack(">BHH", 6, 1, rng.randint(410, 430))
                    elif k % 2:
                        req = struct.pack(">BHH", 1, 0, 3)
                    else:
                        req = struct.pack(">BHH", 3, 0, 4)
                    writer.write(struct.pack(">HHHB", tid, 0, len(req) + 1, 1) + req)
                    await writer.drain()
                    h = await reader.readexactly(7)
                    await reader.readexactly(struct.unpack(">HHHB", h)[2] - 1)
                    k += 1
                    await asyncio.sleep(1.0)
            except (OSError, asyncio.IncompleteReadError):
                await asyncio.sleep(1.0)

    async def _ticker(self):
        while True:
            self._tick()
            await asyncio.sleep(TICK_S)

    async def _main(self):
        try:
            self.server = await asyncio.start_server(self._handle, self.host, self.port)
            self.port = self.server.sockets[0].getsockname()[1]
        except OSError as e:
            self.error = f"Could not open Modbus port {self.host}:{self.port}: {e}"
            self.server = None
            self.ready.set()
            return
        self.ready.set()
        await asyncio.gather(self._ticker(), self._hmi(), self.server.serve_forever())

    def start(self):
        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self._main())
            except Exception as e:      # never take the web app down
                self.error = str(e)
        threading.Thread(target=run, daemon=True, name="cascade-live").start()
        self.ready.wait(5)
        return self


LOOPBACK = {"127.0.0.1", "::1", "localhost"}
CLOUD_MARKERS = ("RENDER", "RENDER_SERVICE_ID", "DYNO", "FLY_APP_NAME", "K_SERVICE", "RAILWAY_ENVIRONMENT", "VERCEL")


def enabled_reason():
    """(enabled, why). Off on cloud hosts unless explicitly switched on; off whenever CASCADE_LIVE=0."""
    v = os.environ.get("CASCADE_LIVE", "").strip()
    if v == "0":
        return False, "switched off (CASCADE_LIVE=0)"
    if v != "1" and any(os.environ.get(k) for k in CLOUD_MARKERS):
        return False, "disabled on public deployments; it runs only on a local install (set CASCADE_LIVE=1 to override)"
    return True, ""


def bind_host():
    """Loopback unless the LAN demo is asked for explicitly with BOTH variables (run_master_lan.bat sets them)."""
    h = os.environ.get("CASCADE_LIVE_HOST", "127.0.0.1").strip() or "127.0.0.1"
    if h not in LOOPBACK and os.environ.get("CASCADE_LIVE_ALLOW_LAN") != "1":
        return "127.0.0.1"
    return h


def from_env(asset, asset_name, audit=None, failsafe_auto=True):
    ok, _ = enabled_reason()
    if not ok:
        return None
    return LiveDevice(bind_host(), int(os.environ.get("CASCADE_LIVE_PORT", "5020")), asset, asset_name, audit, failsafe_auto).start()
