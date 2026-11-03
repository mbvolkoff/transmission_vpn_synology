"""Small privileged VPN agent. No Docker socket or host network is needed."""

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time

from .common import UserError, read_json, service_token, write_private
from .profiles import OPENVPN_PUSH_IGNORES, decode_upload, openvpn_profile, xray_profile
from . import permit


from .network import firewall_commands, gateway_network, install_firewall, run_firewall, set_forwarding
from . import relay


class Controller:
    def __init__(self, root, control_root, token, install_guard=True):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.control_root, self.token = Path(control_root), token
        self.generation = secrets.token_hex(16)
        self.traffic_allowed = False
        self.permission_active = None
        self.last_verified = 0
        self.tunnel_chain = None
        self.firewall_binary = "iptables"
        self.process = None
        self.active = read_json(self.root / "active.json", {})
        self.connected, self.external_ip = False, None
        self.last_attempt = 0
        self.started = 0
        self.stopping = False
        self.guard_ready = False
        self.interface = "eth0"
        self.network = None
        self.monitor_issue = None
        self._revoke()
        if install_guard:
            if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "0":
                raise RuntimeError("Gateway startup requires net.ipv4.ip_forward=0 in the updated Compose file")
            self.network = gateway_network()
            self.interface = self.network["outside"]
            set_forwarding(self.network["inside"], False)
            self.firewall_binary, self.tunnel_chain = install_firewall(
                self.network["inside"], self.root / "firewall.json", self.network["subnet"])
            set_forwarding(self.network["inside"], True)
            self.guard_ready = True
            permit.publish_router(self.control_root, token, self.network)
        threading.Thread(target=self._monitor, daemon=True).start()

    def _persist(self):
        write_private(self.root / "active.json", json.dumps(self.active))

    def _set_traffic(self, allowed, force=False):
        if not self.guard_ready:
            if allowed:
                raise RuntimeError("The torrent traffic guard is not installed")
            return
        if allowed == self.traffic_allowed and not force:
            return
        if allowed:
            inside = self.network["inside"]
            set_forwarding("tun0", True)
            # Neither existing flows nor new ones may fall back to the outside
            # interface. Reply traffic is permitted only from the VPN interface.
            run_firewall([self.firewall_binary, "-w", "-A", self.tunnel_chain,
                          "-i", inside, "-o", "tun0", "-j", "ACCEPT"], timeout=3)
            run_firewall([self.firewall_binary, "-w", "-A", self.tunnel_chain,
                          "-i", "tun0", "-o", inside, "-m", "conntrack",
                          "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], timeout=3)
        else:
            run_firewall([self.firewall_binary, "-w", "-F", self.tunnel_chain], timeout=3)
        self.traffic_allowed = allowed

    def _revoke(self, force=False):
        self.connected, self.external_ip, self.last_verified = False, None, 0
        try:
            self._set_traffic(False, force=force)
        finally:
            if force or self.permission_active is not False:
                permit.publish(self.control_root, self.token, False, self.generation)
                self.permission_active = False

    def _grant(self, address):
        self._set_traffic(True)
        lease = permit.publish(self.control_root, self.token, True, self.generation, address)
        self.permission_active = True
        self.last_verified = lease["issued"]
        self.connected = True

    def _stop(self):
        self.started = 0
        try:
            # Block packets and revoke daemon permission BEFORE VPN teardown.
            self._revoke(force=True)
        finally:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            self.process = None
            subprocess.run(["ip", "link", "delete", "tun0"], capture_output=True, timeout=5)

    def configure(self, data):
        protocol = data.get("protocol")
        if protocol not in ("openvpn", "xray"):
            raise UserError("Choose OpenVPN or Xray.")
        name, content = decode_upload(data.get("profile"))
        try:
            text = content.decode("utf-8-sig")
        except UnicodeError:
            raise UserError("The configuration must be a text file.") from None
        directory = self.root / "profiles" / secrets.token_hex(12)
        directory.mkdir(parents=True, mode=0o700)
        if protocol == "openvpn":
            assets = {}
            if not isinstance(data.get("assets", []), list) or len(data.get("assets", [])) > 12:
                raise UserError("Upload at most 12 supporting certificate/key files.")
            for upload in data.get("assets", []):
                asset_name, asset_data = decode_upload(upload)
                if asset_name in assets:
                    raise UserError("Supporting file names must be unique.")
                assets[asset_name] = asset_data
            effective = openvpn_profile(text, assets, directory, data.get("username", ""), data.get("password", ""))
            for asset_name, asset_data in assets.items():
                write_private(directory / "assets" / asset_name, asset_data)
            filename = directory / "client.ovpn"
            write_private(filename, effective)
        else:
            filename = directory / "client.json"
            write_private(filename, json.dumps(xray_profile(text, self.interface)))
            try:
                result = subprocess.run(["xray", "run", "-test", "-config", str(filename)], capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                raise UserError("Xray could not validate this profile. Check the installed Xray version.") from None
            if result.returncode:
                raise UserError("Xray could not load this server profile. Check its server, transport and certificate settings.")
        with self.lock:
            self._stop()
            self.active = {"protocol": protocol, "profile_name": name, "file": str(filename), "enabled": True}
            self._persist()
            self._start()
            return self.status()

    def _start(self):
        if not self.active.get("file"):
            raise UserError("Upload a VPN profile first.")
        self._revoke(force=True)
        self.generation = secrets.token_hex(16)
        protocol, filename = self.active["protocol"], self.active["file"]
        if protocol == "openvpn":
            command = ["openvpn", "--config", filename, "--script-security", "1",
                       "--connect-retry", "3", "15", "--resolv-retry", "15",
                       "--ping", "10", "--ping-restart", "60", "--auth-retry", "nointeract"]
            # Apply to already-saved profiles as well as new imports. These
            # private files survive image updates and may predate the filters.
            for option in OPENVPN_PUSH_IGNORES:
                command.extend(["--pull-filter", "ignore", option])
        else:
            # Existing private profiles survive the network layout migration.
            write_private(filename, json.dumps(xray_profile(Path(filename).read_text(), self.interface)))
            command = ["xray", "run", "-config", filename]
        log = self.root / "connection.log"
        if log.exists() and log.stat().st_size > 2 * 1024 * 1024:
            write_private(log, b"")
        with open(log, "ab") as output:
            self.process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        self.last_attempt = time.monotonic()
        if not self.started:
            self.started = self.last_attempt

    def connect(self):
        with self.lock:
            if not self.active.get("file"):
                raise UserError("Upload a VPN profile first.")
            self.active["enabled"] = True
            self._persist()
            if not self.process or self.process.poll() is not None:
                self._start()
            return self.status()

    def disconnect(self):
        with self.lock:
            self.active["enabled"] = False
            self._persist()
            self._stop()
            return self.status()

    def status(self):
        with self.lock:
            running = self.process is not None and self.process.poll() is None
            state = "not_configured"
            if self.active.get("file"):
                if not self.active.get("enabled"):
                    state = "disconnected"
                elif self.connected and running and self.traffic_allowed and time.monotonic() - self.last_verified < permit.LEASE_SECONDS:
                    state = "connected"
                elif running and time.monotonic() - self.started < 90:
                    state = "connecting"
                else:
                    state = "error"
            return {"state": state, "protocol": self.active.get("protocol"),
                    "profile_name": self.active.get("profile_name"),
                    "external_ip": self.external_ip if state == "connected" else None,
                    "protected": self.guard_ready,
                    "torrents_allowed": state == "connected"}

    def _report_issue(self, issue):
        if issue != self.monitor_issue:
            self.monitor_issue = issue
            if issue:
                # Fixed categories/codes only: no server addresses, certificate
                # identities, curl bodies, commands or exception messages.
                print("VPN verification: " + issue + "; downloads blocked", flush=True)

    def _monitor(self):
        while not self.stopping:
            stage = "VPN process startup"
            try:
                with self.lock:
                    if self.active.get("enabled") and self.active.get("file"):
                        if (not self.process or self.process.poll() is not None) and time.monotonic() - self.last_attempt > 15:
                            self._start()
                    process = self.process
                connected, address, tunnel_ip = False, None, None
                issue = None
                if process and process.poll() is None:
                    stage = "Tunnel Internet check"
                    check = subprocess.run(["curl", "-4", "--interface", "tun0", "--fail", "--silent",
                                            "--max-time", "5", "https://api.ipify.org"], capture_output=True, timeout=7)
                    if check.returncode == 0:
                        address = str(ipaddress.IPv4Address(check.stdout.decode().strip()))
                        stage = "Tunnel IPv4 address check"
                        addresses = json.loads(subprocess.check_output(
                            ["ip", "-j", "-4", "address", "show", "dev", "tun0"], timeout=2))
                        for interface in addresses:
                            for info in interface.get("addr_info", []):
                                if info.get("family") == "inet":
                                    tunnel_ip = str(ipaddress.IPv4Address(info["local"]))
                        connected = tunnel_ip is not None
                        if not connected:
                            issue = "Tunnel has no IPv4 address"
                    else:
                        issue = f"Tunnel Internet check failed (curl exit {check.returncode})"
                with self.lock:
                    if process is self.process:
                        stage = "Torrent permission update"
                        if self.connected and not connected:
                            self.started = time.monotonic()
                        if connected:
                            self._grant(tunnel_ip)
                            self.external_ip = address
                        else:
                            self._revoke()
                        self._report_issue(issue)
                stage = "Connection log maintenance"
                log = self.root / "connection.log"
                if log.exists() and log.stat().st_size > 2 * 1024 * 1024:
                    with open(log, "r+b") as output:
                        output.truncate(0)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                with self.lock:
                    self._report_issue(f"{stage} failed ({type(exc).__name__})")
                    try:
                        self._revoke()
                    except (OSError, subprocess.SubprocessError):
                        # The independent daemon supervisor also fails closed
                        # when the signed permission stops being renewed.
                        pass
            time.sleep(5)


def serve(controller, token, address=("0.0.0.0", 8081)):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            payload = json.dumps(value).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except ConnectionError:
                # A timed-out health/browser client can close before we reply.
                # This does not mean VPN startup failed; do not send a second
                # response to the closed connection or obscure the VPN log.
                self.close_connection = True

        def handle_request(self):
            try:
                if self.path == "/health" and self.command == "GET":
                    return self.reply(200 if controller.guard_ready else 503, {"ready": controller.guard_ready})
                if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                    return self.reply(401, {"error": "Authentication required"})
                if self.path == "/status" and self.command == "GET":
                    return self.reply(200, controller.status())
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 8 * 1024 * 1024:
                    raise UserError("The upload is too large.", 413)
                data = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(data, dict):
                    raise UserError("Invalid request.")
                actions = {"/configure": lambda: controller.configure(data),
                           "/connect": controller.connect, "/disconnect": controller.disconnect}
                if self.command != "POST" or self.path not in actions:
                    return self.reply(404, {"error": "Not found"})
                return self.reply(200, actions[self.path]())
            except UserError as exc:
                self.reply(exc.status, {"error": str(exc)})
            except (ValueError, TypeError, AttributeError):
                self.reply(400, {"error": "The profile or request could not be read."})
            except (OSError, subprocess.SubprocessError):
                self.reply(503, {"error": "The VPN could not start. Check this profile and the NAS TUN/firewall support."})

        do_GET = do_POST = handle_request

    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    os.umask(0o077)
    print("gateway: starting; preparing private service credentials", flush=True)
    token = service_token(os.environ.get("CONTROL_DIR", "/control"), create=True)
    print("gateway: preparing private VPN state and torrent protection", flush=True)
    controller = Controller(os.environ.get("VPN_DIR", "/vpn"), os.environ.get("CONTROL_DIR", "/control"), token)
    server = serve(controller, token)
    rpc_relay = relay.serve(controller.network["control_address"])
    threading.Thread(target=rpc_relay.serve_forever, daemon=True).start()

    def stop(*_):
        controller.stopping = True
        with controller.lock:
            controller._stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print("gateway: control API ready on port 8081; a VPN connection is not required for setup", flush=True)
    server.serve_forever()
