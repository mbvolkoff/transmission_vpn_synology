import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from urllib import error, request


class UserError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def write_private(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content if isinstance(content, bytes) else content.encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def service_token(directory, create=False):
    path = Path(directory) / "service-token"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if create:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "w") as output:
                output.write(secrets.token_urlsafe(48))
    for _ in range(120):
        if path.exists() and path.stat().st_size:
            return path.read_text().strip()
        time.sleep(0.5)
    raise RuntimeError("The gateway did not initialize its service credentials")


def storage_ids():
    uid, gid = int(os.environ.get("PUID", "1000")), int(os.environ.get("PGID", "1000"))
    if uid <= 0 or gid <= 0:
        raise RuntimeError("PUID and PGID must be non-root numeric IDs")
    return uid, gid


class GatewayClient:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token

    def call(self, path, data=None):
        payload = None if data is None else json.dumps(data).encode()
        req = request.Request(self.url + path, data=payload, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"
        })
        try:
            with request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except error.HTTPError as exc:
            try:
                message = json.load(exc).get("error", "The VPN service rejected this request.")
            except (ValueError, OSError):
                message = "The VPN service rejected this request."
            raise UserError(message, exc.code) from None
        except (OSError, ValueError):
            raise UserError("The VPN service is starting. Please try again shortly.", 503) from None
