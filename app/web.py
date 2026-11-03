import base64
import binascii
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .auth import Accounts
from .common import GatewayClient, UserError, read_json, service_token, write_private
from .storage import Storage
from .transmission import RPC
from .permit import rpc_token, vpn_ready


FIELDS = ["id", "name", "status", "percentDone", "rateDownload", "rateUpload", "totalSize", "eta", "downloadDir", "errorString"]
STATIC = Path(__file__).parent / "static"


class Application:
    def __init__(self, root, storage, gateway, rpc):
        self.root = Path(root)
        self.accounts = Accounts(root)
        self.storage, self.gateway, self.rpc = storage, gateway, rpc
        self.settings = read_json(self.root / "settings.json", {})
        self.cached_torrents = read_json(self.root / "torrent-cache.json", [])
        self.cache_saved = 0
        self.lock = threading.RLock()

    def status(self):
        try:
            vpn = self.gateway.call("/status")
        except UserError:
            vpn = {"state": "unavailable", "protected": False}
        return {"vpn": vpn, "download_dir": self.settings.get("download_dir"),
                "configured": bool(self.settings.get("download_dir") is not None and vpn.get("protocol"))}

    def configure(self, data):
        folder = self.storage.check_writable(data.get("download_dir", ""))
        with self.lock:
            vpn = self.gateway.call("/configure", data)
            self.settings["download_dir"] = folder
            write_private(self.root / "settings.json", json.dumps(self.settings))
        return {"vpn": vpn, "download_dir": folder, "configured": True}

    def folder(self, data):
        folder = self.storage.check_writable(data.get("path", ""))
        with self.lock:
            self.settings["download_dir"] = folder
            write_private(self.root / "settings.json", json.dumps(self.settings))
        return {"download_dir": folder}

    def add_torrent(self, data):
        if not vpn_ready(self.gateway.call("/status")):
            raise UserError("Connect the VPN before adding a download.", 409)
        folder = self.settings.get("download_dir")
        if folder is None:
            raise UserError("Choose a download folder first.", 409)
        self.storage.check_writable(folder)
        arguments = {"download-dir": "/downloads" + ("/" + folder if folder != "." else ""), "paused": False}
        if data.get("magnet"):
            magnet = data["magnet"]
            if not isinstance(magnet, str) or not magnet.startswith("magnet:?") or len(magnet) > 8192:
                raise UserError("Paste a valid magnet link.")
            arguments["filename"] = magnet
        else:
            try:
                metainfo = base64.b64decode(data.get("torrent", ""), validate=True)
            except (ValueError, TypeError, binascii.Error):
                raise UserError("The torrent file could not be read.") from None
            if not metainfo or len(metainfo) > 2 * 1024 * 1024:
                raise UserError("Choose a .torrent file smaller than 2 MB.")
            arguments["metainfo"] = base64.b64encode(metainfo).decode()
        result = self.rpc.call("torrent-add", arguments)
        return {"duplicate": "torrent-duplicate" in result}

    def _waiting_torrents(self):
        with self.lock:
            return {"torrents": [dict(torrent, status=0, rateDownload=0, rateUpload=0, vpnBlocked=True)
                                 for torrent in self.cached_torrents], "blocked": True}

    def torrents(self):
        try:
            if not vpn_ready(self.gateway.call("/status")):
                return self._waiting_torrents()
            result = self.rpc.call("torrent-get", {"fields": FIELDS})
            with self.lock:
                self.cached_torrents = result.get("torrents", [])
                if time.monotonic() - self.cache_saved >= 30:
                    write_private(self.root / "torrent-cache.json", json.dumps(self.cached_torrents))
                    self.cache_saved = time.monotonic()
            # If disconnect raced the RPC request, never display its stale rates
            # as active traffic after the VPN has been disabled.
            if not vpn_ready(self.gateway.call("/status")):
                return self._waiting_torrents()
            return result
        except UserError:
            # The daemon intentionally does not exist without a verified VPN.
            # Keep its last known list visible, explicitly stopped and at 0 B/s.
            return self._waiting_torrents()

    def torrent_action(self, data):
        action = data.get("action")
        identifier = data.get("id")
        if type(identifier) is not int or identifier < 0 or action not in ("start", "stop", "remove"):
            raise UserError("Choose a valid download action.")
        if not vpn_ready(self.gateway.call("/status")):
            raise UserError("Connect the VPN before managing downloads. Transmission is stopped.", 409)
        arguments = {"ids": [identifier]}
        if action == "remove":
            arguments["delete-local-data"] = False
        self.rpc.call("torrent-" + action, arguments)
        return {"ok": True}


def serve(app, address=("0.0.0.0", 8080)):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def log_message(self, *_):
            # Request bodies, credentials and query strings never go to logs.
            pass

        def reply(self, status, payload, content_type="application/json", headers=None):
            if not isinstance(payload, bytes):
                payload = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def body(self):
            if self.headers.get_content_type() != "application/json":
                raise UserError("Send this request as JSON.", 415)
            if self.headers.get("Transfer-Encoding"):
                raise UserError("Streaming uploads are not supported.", 400)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise UserError("Invalid upload size.") from None
            if length < 0 or length > 8 * 1024 * 1024:
                raise UserError("The upload is too large. Use files smaller than 2 MB each.", 413)
            try:
                value = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError):
                raise UserError("The request could not be read.") from None
            if not isinstance(value, dict):
                raise UserError("Invalid request.")
            return value

        def identifier(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                return ""
            return cookie["tvpn_session"].value if "tvpn_session" in cookie else ""

        def check_origin(self):
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                raise UserError("Open the app directly and try again.", 403)

        def handle_request(self):
            try:
                path = urlsplit(self.path).path
                if self.command == "GET" and path in ("/", "/app.js", "/style.css", "/icon.svg"):
                    filename = "index.html" if path == "/" else path[1:]
                    return self.reply(200, (STATIC / filename).read_bytes(), mimetypes.guess_type(filename)[0] or "text/plain")
                if self.command == "GET" and path == "/api/session":
                    try:
                        session = app.accounts.session(self.identifier())
                    except UserError:
                        session = None
                    return self.reply(200, {"setup_required": not bool(app.accounts.account),
                                            "authenticated": bool(session), "csrf": session["csrf"] if session else None})
                if self.command == "POST":
                    self.check_origin()
                if self.command == "POST" and path in ("/api/login", "/api/setup"):
                    identifier, session = app.accounts.authenticate(self.body(), self.client_address[0], setup=path == "/api/setup")
                    secure = "; Secure" if os.environ.get("SECURE_COOKIES") == "true" else ""
                    return self.reply(200, {"csrf": session["csrf"]}, headers={
                        "Set-Cookie": "tvpn_session=" + identifier + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + secure
                    })
                session = app.accounts.session(self.identifier())
                if self.command == "POST" and not secrets_compare(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
                    raise UserError("Refresh the page and try again.", 403)
                if self.command == "GET":
                    if path == "/api/status":
                        return self.reply(200, app.status())
                    if path == "/api/folders":
                        relative = parse_qs(urlsplit(self.path).query).get("path", [""])[0]
                        return self.reply(200, app.storage.list(relative))
                    if path == "/api/torrents":
                        return self.reply(200, app.torrents())
                if self.command == "POST":
                    data = self.body()
                    if path == "/api/logout":
                        app.accounts.logout(self.identifier())
                        return self.reply(200, {"ok": True}, headers={"Set-Cookie": "tvpn_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
                    actions = {
                        "/api/configure": lambda: app.configure(data),
                        "/api/folder": lambda: app.folder(data),
                        "/api/folders": lambda: app.storage.create(data.get("path", ""), data.get("name", "")),
                        "/api/vpn/connect": lambda: app.gateway.call("/connect", {}),
                        "/api/vpn/disconnect": lambda: app.gateway.call("/disconnect", {}),
                        "/api/torrents": lambda: app.add_torrent(data),
                        "/api/torrents/action": lambda: app.torrent_action(data),
                    }
                    if path in actions:
                        return self.reply(200, actions[path]())
                self.reply(404, {"error": "Not found"})
            except UserError as exc:
                self.reply(exc.status, {"error": str(exc)})
                # Some failures happen before reading a POST body. Close rather
                # than interpreting leftover bytes as another HTTP request.
                self.close_connection = True
            except (OSError, ValueError, TypeError, AttributeError, KeyError):
                self.reply(503, {"error": "That action could not be completed. Please try again."})

        do_GET = do_POST = handle_request

    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    return server


def secrets_compare(left, right):
    import hmac
    return hmac.compare_digest(left, right)


if __name__ == "__main__":
    os.umask(0o077)
    token = service_token(os.environ.get("CONTROL_DIR", "/control"))
    storage = Storage(os.environ.get("DOWNLOAD_ROOT", "/downloads"))
    # Initialize only a new, empty dedicated download root. Existing shared
    # folders and their contents retain the administrator's permissions.
    if os.geteuid() == 0 and storage.root.is_dir() and not any(storage.root.iterdir()):
        from .common import storage_ids
        os.chown(storage.root, *storage_ids())
        os.chmod(storage.root, 0o775)
    app = Application(os.environ.get("WEB_DIR", "/data"), storage,
                      GatewayClient("http://gateway:8081", token), RPC("http://gateway:9091/transmission/rpc", rpc_token(token)))
    if app.accounts.setup_code:
        print("First-time setup code: " + app.accounts.setup_code, flush=True)
    print("Web interface ready on port 8080", flush=True)
    serve(app).serve_forever()
