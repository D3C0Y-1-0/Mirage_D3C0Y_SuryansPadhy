"""2FA rules. Uses a throwaway store, never your real accounts. Run from project root:  python backend/test_auth.py"""
import os
import tempfile
import time
from pathlib import Path

import auth

_tmp = Path(tempfile.mkdtemp())
auth.STORE_DIR, auth.STORE, auth.KEY_FILE = _tmp, _tmp / "auth.json", _tmp / "secret.key"
os.environ.pop("CASCADE_SECRET", None)


def test_totp_matches_rfc6238_vector():
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert auth.totp(secret, step=59 // 30, digits=8) == "94287082"          # RFC 6238 Appendix B, T=59
    assert auth.totp(secret, step=1111111109 // 30, digits=8) == "07081804"


def test_password_is_hashed_and_secret_is_encrypted():
    auth.create_account("dhruv", "correct horse battery")
    secret, uri = auth.start_enrolment("dhruv")
    raw = auth.STORE.read_text()
    assert "correct horse" not in raw and secret not in raw
    assert uri.startswith("otpauth://totp/")
    codes = auth.confirm_enrolment("dhruv", auth.totp(secret))
    assert len(codes) == 8 and not any(c.replace("-", "") in auth.STORE.read_text() for c in codes)
    test_password_is_hashed_and_secret_is_encrypted.secret, test_password_is_hashed_and_secret_is_encrypted.codes = secret, codes


def test_login_needs_password_then_code_and_code_cannot_be_replayed():
    secret = test_password_is_hashed_and_secret_is_encrypted.secret
    user, stage = auth.login_password("dhruv", "correct horse battery")
    assert stage == "pw"                                    # password alone is not a full session
    step = int(time.time() // 30) + 1                      # use the next step: the current one was spent enrolling
    code = auth.totp(secret, step)
    try:
        assert auth.login_code(user, code) == "totp"
    except PermissionError:
        raise AssertionError("valid next-step code refused")
    try:
        auth.login_code(user, code)
        raise AssertionError("replayed code accepted")
    except PermissionError:
        pass


def test_recovery_code_works_once():
    code = test_password_is_hashed_and_secret_is_encrypted.codes[0]
    auth._fails.clear()
    assert auth.login_code("dhruv", code) == "recovery"
    try:
        auth.login_code("dhruv", code)
        raise AssertionError("recovery code reused")
    except PermissionError:
        pass


def test_wrong_password_locks_after_five_tries():
    auth._fails.clear()
    for _ in range(auth.LOCK_AFTER):
        try:
            auth.login_password("dhruv", "wrong password!")
        except PermissionError:
            pass
    try:
        auth.login_password("dhruv", "correct horse battery")
        raise AssertionError("not locked")
    except PermissionError as exc:
        assert "Too many" in str(exc)
    auth._fails.clear()


def test_tampered_session_is_rejected():
    tok = auth.make_session("dhruv", "full")
    assert auth.read_session(tok)["u"] == "dhruv"
    body, sig = tok.rsplit(".", 1)
    assert auth.read_session(body + "." + ("0" * len(sig))) is None


def test_only_one_account_can_be_created():
    try:
        auth.create_account("intruder", "another long password")
        raise AssertionError("second account created without signing in")
    except PermissionError:
        pass


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
