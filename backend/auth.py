"""Login with a password plus a 6-digit code from an authenticator app (TOTP, RFC 6238). Standard library only.

What is stored, in .cascade/auth.json at the project root (git-ignored, never committed):
  - password: PBKDF2-HMAC-SHA256, 310,000 rounds, random 16-byte salt. Never the password itself.
  - TOTP secret: ENCRYPTED with a key that lives elsewhere (env CASCADE_SECRET, or .cascade/secret.key).
    Cipher: HMAC-SHA256 in counter mode as the keystream + HMAC-SHA256 tag over nonce and ciphertext
    (encrypt-then-MAC). Standard library only, so it runs on locked-down Windows machines with no extra packages.
  - recovery codes: SHA-256 hashes; each works once.
Sessions: a signed cookie (HMAC-SHA256), HttpOnly, SameSite=Strict, 8 hours. Two stages: after the password the
cookie only allows the code check ("pw"); after the code it is a full session ("full").
Brute force: 5 failed attempts lock that account for 5 minutes. A code that was used once cannot be replayed.

Access rule: until the first account exists the app is open (setup mode) so a fresh clone still demos.
Once an account exists, /app, /twin and the data API need a full session. CASCADE_AUTH=off disables the gate.
Reset (deletes accounts, not data):  python backend/auth.py --reset
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE_DIR = Path(os.environ["CASCADE_STATE_DIR"]) if os.environ.get("CASCADE_STATE_DIR") else ROOT / ".cascade"   # tests use a temp dir
STORE = STORE_DIR / "auth.json"
KEY_FILE = STORE_DIR / "secret.key"
ISSUER = "Cascade PS03"
SESSION_HOURS = 8
PBKDF2_ROUNDS = 310_000
LOCK_AFTER, LOCK_SECONDS = 5, 300
_lock = threading.Lock()
_fails = {}          # username -> (count, first_fail_time)


# ---------- keys and storage ----------
def _master_key():
    env = os.environ.get("CASCADE_SECRET")
    if env:
        return hashlib.sha256(env.encode()).digest()
    STORE_DIR.mkdir(exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
    return KEY_FILE.read_bytes()


def _subkey(purpose):
    return hmac.new(_master_key(), purpose.encode(), hashlib.sha256).digest()


def _load():
    if not STORE.exists():
        return {"users": {}}
    return json.loads(STORE.read_text())


def _save(db):
    STORE_DIR.mkdir(exist_ok=True)
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=1))
    tmp.replace(STORE)


def gate_enabled():
    return os.environ.get("CASCADE_AUTH", "on").lower() != "off" and bool(_load()["users"])


# ---------- primitives ----------
def hash_password(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ROUNDS)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def check_password(pw, stored):
    salt_b64, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(pw, base64.b64decode(salt_b64)), stored)


def _keystream(key, nonce, n):
    out = b""
    counter = 0
    while len(out) < n:
        out += hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        counter += 1
    return out[:n]


def encrypt(plain: bytes):
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plain, _keystream(_subkey("enc"), nonce, len(plain))))
    tag = hmac.new(_subkey("mac"), nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(nonce + ct + tag).decode()


def decrypt(token: str):
    raw = base64.b64decode(token)
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
    if not hmac.compare_digest(tag, hmac.new(_subkey("mac"), nonce + ct, hashlib.sha256).digest()):
        raise ValueError("secret store was tampered with or the key changed")
    return bytes(a ^ b for a, b in zip(ct, _keystream(_subkey("enc"), nonce, len(ct))))


def totp(secret_b32, step=None, digits=6):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    step = int(time.time() // 30) if step is None else step
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def verify_totp(secret_b32, code, last_step=-1):
    """Accept the current 30-second step and one either side (clock drift). Returns the matched step or None.
    A step at or before last_step is refused, so a code cannot be used twice."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    now = int(time.time() // 30)
    for s in (now - 1, now, now + 1):
        if s > last_step and hmac.compare_digest(totp(secret_b32, s), code):
            return s
    return None


# ---------- sessions ----------
def make_session(user, stage):
    body = base64.urlsafe_b64encode(json.dumps({"u": user, "s": stage,
                                                "exp": int(time.time()) + SESSION_HOURS * 3600}).encode()).decode()
    sig = hmac.new(_subkey("session"), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig


def read_session(cookie):
    try:
        body, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_subkey("session"), body.encode(), hashlib.sha256).hexdigest()):
            return None
        data = json.loads(base64.urlsafe_b64decode(body))
        return data if data["exp"] > time.time() else None
    except Exception:
        return None


# ---------- account operations ----------
def _locked(user):
    c, t0 = _fails.get(user, (0, 0))
    if c >= LOCK_AFTER and time.time() - t0 < LOCK_SECONDS:
        return int(LOCK_SECONDS - (time.time() - t0))
    if c >= LOCK_AFTER:
        _fails.pop(user, None)
    return 0


def _fail(user):
    c, t0 = _fails.get(user, (0, time.time()))
    _fails[user] = (c + 1, t0 if c else time.time())


def create_account(user, pw):
    user = user.strip().lower()
    if not (3 <= len(user) <= 32) or not user.replace("_", "").replace(".", "").isalnum():
        raise ValueError("Username: 3-32 letters, digits, dots or underscores.")
    if len(pw) < 10:
        raise ValueError("Password: at least 10 characters.")
    with _lock:
        db = _load()
        if db["users"]:
            raise PermissionError("An account already exists. Sign in with it to manage security.")
        db["users"][user] = {"pw": hash_password(pw), "totp": None, "pending": None, "recovery": [],
                             "last_step": -1, "created": int(time.time())}
        _save(db)
    return user


def login_password(user, pw):
    user = user.strip().lower()
    wait = _locked(user)
    if wait:
        raise PermissionError(f"Too many attempts. Try again in {wait} s.")
    u = _load()["users"].get(user)
    if not u or not check_password(pw, u["pw"]):
        _fail(user)
        raise PermissionError("Wrong username or password.")
    _fails.pop(user, None)
    return user, ("pw" if u["totp"] else "full")


def login_code(user, code):
    wait = _locked(user)
    if wait:
        raise PermissionError(f"Too many attempts. Try again in {wait} s.")
    with _lock:
        db = _load()
        u = db["users"][user]
        secret = decrypt(u["totp"]).decode()
        step = verify_totp(secret, code, u["last_step"])
        if step is not None:
            u["last_step"] = step
            _save(db)
            _fails.pop(user, None)
            return "totp"
        digest = hashlib.sha256(str(code).strip().upper().replace("-", "").encode()).hexdigest()
        if digest in u["recovery"]:
            u["recovery"].remove(digest)
            _save(db)
            return "recovery"
        reused = verify_totp(secret, code) is not None      # right code, but its 30-second step was already used
    _fail(user)
    if reused:
        raise PermissionError("That code was already used. Wait for the next code in your app (up to 30 seconds).")
    raise PermissionError("That code is not valid. Codes change every 30 seconds.")


def start_enrolment(user):
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    with _lock:
        db = _load()
        db["users"][user]["pending"] = encrypt(secret.encode())
        _save(db)
    uri = f"otpauth://totp/{ISSUER.replace(' ', '%20')}:{user}?secret={secret}&issuer={ISSUER.replace(' ', '%20')}&digits=6&period=30"
    return secret, uri


def confirm_enrolment(user, code):
    with _lock:
        db = _load()
        u = db["users"][user]
        if not u["pending"]:
            raise ValueError("Start set-up first.")
        secret = decrypt(u["pending"]).decode()
        step = verify_totp(secret, code)
        if step is None:
            raise PermissionError("That code does not match. Check the phone's clock and try the next code.")
        codes = ["-".join(secrets.token_hex(2).upper() for _ in range(2)) for _ in range(8)]
        u.update(totp=u["pending"], pending=None, last_step=step,
                 recovery=[hashlib.sha256(c.replace("-", "").encode()).hexdigest() for c in codes])
        _save(db)
    return codes


def disable_2fa(user, pw, code):
    _, _ = login_password(user, pw)
    login_code(user, code)
    with _lock:
        db = _load()
        db["users"][user].update(totp=None, pending=None, recovery=[], last_step=-1)
        _save(db)


def status(user):
    db = _load()
    u = db["users"].get(user) if user else None
    return {"accounts_exist": bool(db["users"]), "gate": gate_enabled(), "user": user,
            "totp_enabled": bool(u and u["totp"]), "recovery_left": len(u["recovery"]) if u else 0}


if __name__ == "__main__":
    import sys
    if "--reset" in sys.argv:
        if STORE.exists():
            STORE.unlink()
        print("Accounts removed. The app is open again until a new account is created.")
    else:
        print(__doc__)
