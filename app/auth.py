import hashlib
import hmac
import json
from pathlib import Path
import secrets
import threading
import time

from .common import UserError, read_json, write_private


class Accounts:
    def __init__(self, root):
        self.root = Path(root)
        self.account = read_json(self.root / "account.json")
        self.sessions, self.failures = {}, {}
        self.lock = threading.RLock()
        code_file = self.root / "setup-code"
        if not self.account:
            if not code_file.exists():
                write_private(code_file, secrets.token_urlsafe(18))
            self.setup_code = code_file.read_text().strip()
        else:
            self.setup_code = None

    def _hash(self, password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()

    def authenticate(self, data, peer, setup=False):
        with self.lock:
            now = time.monotonic()
            self.failures = {key: value for key, value in self.failures.items() if now - value[1] < 300}
            count, _ = self.failures.get(peer, (0, now))
            if count >= 10:
                raise UserError("Too many attempts. Please wait five minutes and try again.", 429)
            password = data.get("password", "")
            if not isinstance(password, str) or len(password) > 512:
                raise UserError("Enter a password of at most 512 characters.")
            if setup:
                if self.account:
                    raise UserError("This app already has an account.", 409)
                if not isinstance(data.get("code"), str) or not hmac.compare_digest(data["code"], self.setup_code):
                    self.failures[peer] = (count + 1, now)
                    raise UserError("The setup code is incorrect. Copy it from the web container's DSM log.", 401)
                if len(password) < 12:
                    raise UserError("Choose a password with at least 12 characters.")
                salt = secrets.token_hex(24)
                self.account = {"salt": salt, "hash": self._hash(password, salt)}
                write_private(self.root / "account.json", json.dumps(self.account))
                (self.root / "setup-code").unlink(missing_ok=True)
                self.setup_code = None
            elif not self.account or not hmac.compare_digest(self._hash(password, self.account["salt"]), self.account["hash"]):
                self.failures[peer] = (count + 1, now)
                raise UserError("The password is incorrect.", 401)
            self.failures.pop(peer, None)
            self.sessions = {key: value for key, value in self.sessions.items() if value["expires"] > now}
            if len(self.sessions) >= 64:
                self.sessions.pop(next(iter(self.sessions)))
            identifier = secrets.token_urlsafe(36)
            session = {"csrf": secrets.token_urlsafe(32), "expires": now + 12 * 3600}
            self.sessions[identifier] = session
            return identifier, session

    def session(self, identifier):
        with self.lock:
            value = self.sessions.get(identifier)
            if not value or value["expires"] < time.monotonic():
                raise UserError("Please sign in to continue.", 401)
            return value

    def logout(self, identifier):
        with self.lock:
            self.sessions.pop(identifier, None)
