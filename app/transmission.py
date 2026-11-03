import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from urllib import error, request

from .common import UserError, read_json, service_token, storage_ids, write_private
from . import permit
from .network import prepare_engine


class RPC:
    def __init__(self, url, token):
        self.url = url
        self.authorization = "Basic " + base64.b64encode(("internal:" + token).encode()).decode()
        self.session = ""
        self.lock = threading.Lock()

    def call(self, method, arguments=None):
        with self.lock:
            for _ in range(2):
                req = request.Request(self.url, data=json.dumps({"method": method, "arguments": arguments or {}}).encode(), headers={
                    "Content-Type": "application/json", "Authorization": self.authorization,
                    "X-Transmission-Session-Id": self.session,
                })
                try:
                    with request.urlopen(req, timeout=15) as response:
                        result = json.load(response)
                except error.HTTPError as exc:
                    if exc.code == 409:
                        self.session = exc.headers.get("X-Transmission-Session-Id", "")
                        continue
                    raise UserError("The torrent service is not ready. Please try again shortly.", 503) from None
                except (OSError, ValueError):
                    raise UserError("The torrent service is starting. Please try again shortly.", 503) from None
                if result.get("result") != "success":
                    # Do not echo backend errors, which can contain file paths
                    # or uploaded content. The UI supplies actionable context.
                    raise UserError("Transmission could not complete that action. Check the torrent file and folder permissions.")
                return result.get("arguments", {})
            raise UserError("Could not connect to the torrent service.", 503)


def prepare_settings(root, token, uid, gid, tunnel_ip):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings = read_json(root / "settings.json", {})
    settings.update(read_json(Path(__file__).parents[1] / "transmission/settings.json"))
    settings.update({"rpc-authentication-required": True, "rpc-username": "internal", "rpc-password": token,
                     "rpc-whitelist-enabled": False, "rpc-host-whitelist-enabled": False,
                     "watch-dir-enabled": False, "incomplete-dir-enabled": False,
                     "download-dir": "/downloads", "umask": 2, "rpc-bind-address": "0.0.0.0",
                     "bind-address-ipv4": tunnel_ip})
    write_private(root / "settings.json", json.dumps(settings))
    # Only application state is owned here; never recursively chmod/chown a NAS
    # shared folder. Its administrator grants access through DSM.
    if os.geteuid() == 0:
        for directory, directories, files in os.walk(root):
            os.chown(directory, uid, gid)
            for filename in files:
                path = Path(directory) / filename
                if not path.is_symlink():
                    os.chown(path, uid, gid)


class Supervisor:
    """The daemon exists only while a fresh verified-VPN permission is valid."""

    def __init__(self, root, control, token, uid, gid, status_file, network=None, address=None):
        if uid <= 0 or gid <= 0:
            raise ValueError("Transmission must use a non-root identity")
        self.root, self.control, self.token = Path(root), Path(control), token
        self.uid, self.gid, self.status_file = uid, gid, Path(status_file)
        self.network, self.address = network, address
        self.process, self.binding = None, None
        self.stopping = threading.Event()
        self.retry_after = 0

    def permission(self):
        router = permit.read_router(self.control, self.token)
        if not router or not self.network or any(router[key] != self.network[key] for key in ("address", "subnet")):
            return None
        return permit.read(self.control, self.token, namespace=router["namespace"])

    def stop_daemon(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            else:
                self.process.wait()
            self.process, self.binding = None, None

    def record_status(self):
        running = self.process is not None and self.process.poll() is None
        write_private(self.status_file, json.dumps({
            "state": "running" if running else "waiting_for_vpn",
            "pid": self.process.pid if running else None,
            "binding": self.binding if running else None,
            "updated": time.monotonic(),
        }))

    def step(self):
        value = self.permission()
        binding = (value["generation"], value["tunnel_ip"], value["namespace"]) if value else None
        if self.process is not None and (self.process.poll() is not None or binding != self.binding):
            changed = binding != self.binding
            self.stop_daemon()
            if changed:
                self.retry_after = 0
        if value and self.process is None and time.monotonic() >= self.retry_after:
            prepare_settings(self.root, permit.rpc_token(self.token), self.uid, self.gid, self.address)
            # Config preparation/old-daemon shutdown can take time. Recheck the
            # permission immediately before spawning, including its generation.
            fresh = self.permission()
            if fresh and (fresh["generation"], fresh["tunnel_ip"], fresh["namespace"]) == binding:
                self.process = subprocess.Popen(
                    ["transmission-daemon", "--foreground", "--config-dir", str(self.root), "--log-level", "error"],
                    user=self.uid, group=self.gid, extra_groups=[], umask=0o002,
                )
                self.binding = binding
                self.retry_after = time.monotonic() + 5
        self.record_status()

    def run(self):
        self.record_status()
        try:
            while not self.stopping.is_set():
                try:
                    self.step()
                except (OSError, ValueError, subprocess.SubprocessError):
                    self.stop_daemon()
                    self.record_status()
                    self.retry_after = time.monotonic() + 5
                self.stopping.wait(0.25)
        finally:
            self.stop_daemon()
            self.record_status()


def supervisor_healthy(status_file, control, token):
    try:
        status = read_json(status_file)
        if not isinstance(status, dict) or not 0 <= time.monotonic() - status["updated"] < 4:
            return False
        router = permit.read_router(control, token)
        value = permit.read(control, token, namespace=router["namespace"]) if router else None
        if not value:
            return status["state"] == "waiting_for_vpn" and status["pid"] is None
        binding = [value["generation"], value["tunnel_ip"], value["namespace"]]
        if status["state"] != "running" or status.get("binding") != binding:
            return False
        RPC("http://127.0.0.1:9091/transmission/rpc", permit.rpc_token(token)).call("session-get")
        return True
    except (OSError, ValueError, TypeError, KeyError, UserError):
        return False


if __name__ == "__main__":
    os.umask(0o077)
    control = os.environ.get("CONTROL_DIR", "/control")
    token = service_token(control)
    uid, gid = storage_ids()
    network = permit.read_router(control, token)
    if not network:
        raise RuntimeError("Missing authenticated VPN router configuration")
    address = prepare_engine(network)
    supervisor = Supervisor(os.environ.get("TRANSMISSION_DIR", "/data"), control, token, uid, gid,
                            "/run/transmission-vpn/supervisor.json", network, address)
    signal.signal(signal.SIGTERM, lambda *_: supervisor.stopping.set())
    signal.signal(signal.SIGINT, lambda *_: supervisor.stopping.set())
    supervisor.run()
