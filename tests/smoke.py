"""Isolated tvpn-smoke project only: real daemon, synthetic VPN, closed gate."""
import http.cookiejar
import json
from pathlib import Path
import re
import subprocess
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-p", "tvpn-smoke", "-f", str(ROOT / "compose.yaml"), "-f", str(ROOT / "tests/compose.smoke.yaml")]


def docker(*arguments, check=True):
    return subprocess.run([*COMPOSE, *arguments], check=check, capture_output=True, text=True)


opener = request.build_opener(request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def api(path, data=None):
    req = request.Request("http://127.0.0.1:18080" + path,
                          data=None if data is None else json.dumps(data).encode(),
                          headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
    with opener.open(req, timeout=15) as response:
        return json.load(response)


session = api("/api/session")
if session["setup_required"]:
    logs = docker("logs", "--no-log-prefix", "web").stdout
    code = re.search(r"First-time setup code: (\S+)", logs).group(1)
    csrf = api("/api/setup", {"code": code, "password": "container-smoke-password"})["csrf"]
else:
    csrf = api("/api/login", {"password": "container-smoke-password"})["csrf"]
status = api("/api/status")
assert status["vpn"]["protected"]
assert status["vpn"]["state"] == "not_configured"
assert not status["vpn"]["torrents_allowed"]
assert api("/api/torrents")["torrents"] == []


def wait_daemon(running, timeout=20):
    # Inspect real processes and the RPC socket, not just the agent's status.
    code = f'''
import json
from pathlib import Path
import socket
import time
from app.common import storage_ids
deadline = time.monotonic() + {timeout}
while time.monotonic() < deadline:
    state = json.loads(Path("/run/transmission-vpn/supervisor.json").read_text())
    processes = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            name = path.read_bytes().split(b"\\0")[0].rsplit(b"/", 1)[-1]
            if name == b"transmission-daemon":
                details = (path.parent / "status").read_text().splitlines()
                identity = next(line for line in details if line.startswith("Uid:"))
                assert all(int(value) == storage_ids()[0] for value in identity.split()[1:]), "Daemon has an unexpected identity"
                for field in ("CapEff:", "CapPrm:", "CapBnd:"):
                    cap = int(next(line.split()[1] for line in details if line.startswith(field)), 16)
                    assert not cap & ((1 << 12) | (1 << 13)), "Daemon retained a network capability"
                processes.append(path.parent.name)
        except OSError:
            pass
    with socket.socket() as connection:
        connection.settimeout(0.2)
        listening = connection.connect_ex(("127.0.0.1", 9091)) == 0
    if {running!r}:
        ready = state["state"] == "running" and bool(processes) and listening
    else:
        ready = state["state"] == "waiting_for_vpn" and not processes and not listening
    if ready:
        break
    time.sleep(0.2)
else:
    raise AssertionError("Daemon lifecycle did not reach expected state")
'''
    docker("exec", "-T", "transmission", "python3", "-c", code)


wait_daemon(False)
folders = api("/api/folders")["folders"]
if "Smoke test" not in folders:
    api("/api/folders", {"path": ".", "name": "Smoke test"})
api("/api/folder", {"path": "Smoke test"})
assert api("/api/status")["download_dir"] == "Smoke test"
for path, data in [("/api/torrents", {"magnet": "magnet:?xt=urn:btih:test"}),
                   *[("/api/torrents/action", {"id": 1, "action": action}) for action in ("start", "stop", "remove")]]:
    try:
        api(path, data)
    except error.HTTPError as exc:
        assert exc.code == 409
    else:
        raise AssertionError("Disconnected torrent operation was accepted")

# Reach a known local control service as root, then prove the protected torrent
# identity cannot take the same physical-interface route. No Internet needed.
container = docker("ps", "-q", "web").stdout.strip()
inspection = subprocess.run(["docker", "inspect", container], check=True, capture_output=True, text=True)
web_ip = next(iter(json.loads(inspection.stdout)[0]["NetworkSettings"]["Networks"].values()))["IPAddress"]
target = "http://" + web_ip + ":8080/api/session"
docker("exec", "-T", "gateway", "curl", "--fail", "--silent", "--max-time", "3", target)
blocked = docker("exec", "-T", "--user", "1000:1000", "transmission", "curl", "--fail", "--silent", "--max-time", "2", target, check=False)
assert blocked.returncode != 0

# Only in this disposable project: model a verified tunnel with a dummy device
# and a signed permission. The REAL packet gate stays CLOSED the entire time.
# This proves the real supervisor/daemon lifecycle; it cannot prove VPN routing.
def synthetic_connection(generation):
    docker("exec", "-T", "gateway", "ip", "link", "add", "tun0", "type", "dummy")
    docker("exec", "-T", "gateway", "ip", "addr", "add", "198.18.0.1/30", "dev", "tun0")
    docker("exec", "-T", "gateway", "ip", "link", "set", "tun0", "up")
    code = f'''
from app.common import service_token
from app.permit import publish
publish("/control", service_token("/control"), True, {generation!r}, "198.18.0.1")
'''
    docker("exec", "-T", "gateway", "python3", "-c", code)
    wait_daemon(True)


try:
    synthetic_connection("smoke-disconnect")
    # Validate real metainfo handling with a paused, trackerless fixture.
    metainfo_check = '''
import base64
from app.common import service_token
from app.permit import rpc_token
from app.transmission import RPC
rpc = RPC("http://gateway:9091/transmission/rpc", rpc_token(service_token("/control")))
metainfo = b"d4:infod6:lengthi1e4:name17:smoke-fixture.txt12:piece lengthi16384e6:pieces20:" + b"0" * 20 + b"ee"
result = rpc.call("torrent-add", {"metainfo": base64.b64encode(metainfo).decode(), "paused": True, "download-dir": "/downloads"})
identifier = result.get("torrent-added", result.get("torrent-duplicate"))["id"]
try:
    torrent = rpc.call("torrent-get", {"ids": [identifier], "fields": ["id", "status"]})["torrents"][0]
    assert torrent["status"] in (0, 1, 2)
finally:
    rpc.call("torrent-remove", {"ids": [identifier], "delete-local-data": False})
'''
    docker("exec", "-T", "web", "python3", "-c", metainfo_check)
    api("/api/vpn/disconnect", {})
    wait_daemon(False)
    synthetic_connection("smoke-expiry")
    # No renewal: the live daemon must stop when the 12-second lease expires,
    # even though the dummy interface is still present and up.
    wait_daemon(False)
    docker("exec", "-T", "gateway", "ip", "link", "show", "dev", "tun0")
    blocked = docker("exec", "-T", "--user", "1000:1000", "transmission", "curl", "--fail", "--silent", "--max-time", "2", target, check=False)
    assert blocked.returncode != 0
finally:
    api("/api/vpn/disconnect", {})
wait_daemon(False)
docker("exec", "-T", "transmission", "python3", "-m", "app.health", "transmission")
print("Container smoke checks passed: no daemon/RPC without VPN permission; non-root daemon start; explicit disconnect; expired permission with stale interface; authenticated metainfo handling; offline API refusal; folder setup; physical-interface egress blocking. VPN connection was synthetic, with its packet gate closed.")
