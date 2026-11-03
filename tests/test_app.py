import base64
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib import error, request

from app.auth import Accounts
from app import permit
from app.common import UserError, write_private
from app.gateway import Controller, firewall_commands
from app.profiles import decode_upload, openvpn_profile, xray_profile
from app.storage import Storage
from app.web import Application, serve


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)


class ProfileTests(TemporaryCase):
    def test_openvpn_supporting_files_and_credentials_stay_private(self):
        text = "client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\nauth-user-pass\n"
        config = openvpn_profile(text, {"ca.crt": b"certificate"}, self.root, "user", "secret-$-#")
        self.assertIn("ca " + str(self.root / "assets/ca.crt"), config)
        self.assertIn("redirect-gateway def1", config)
        self.assertNotIn("secret-$-#", config)
        self.assertEqual((self.root / "auth.txt").read_text(), "user\nsecret-$-#\n")
        self.assertEqual((self.root / "auth.txt").stat().st_mode & 0o777, 0o600)

    def test_uploaded_openvpn_cannot_execute_scripts_or_include_other_configs(self):
        for option in ("up /tmp/script", "plugin /tmp/library", "config /etc/passwd", "management 0.0.0.0 9999", "script-security 3", "route 0.0.0.0 0.0.0.0 net_gateway"):
            with self.subTest(option=option), self.assertRaises(UserError):
                openvpn_profile("remote vpn.example.com\n" + option, {}, self.root)

    def test_unsupported_openvpn_options_report_names_and_original_line_numbers(self):
        text = "# Exported profile\nclient\n\nremote private.example.com 1194\n<key>\nPRIVATE KEY CONTENT\n</key>\n--up /private/script password-value\n"
        with self.assertRaises(UserError) as result:
            openvpn_profile(text, {}, self.root)
        message = str(result.exception)
        self.assertIn("option 'up' on line 8", message)
        for private_value in ("private.example.com", "PRIVATE KEY CONTENT", "/private/script", "password-value"):
            self.assertNotIn(private_value, message)

    def test_invalid_option_names_and_broken_quotes_do_not_echo_private_content(self):
        for line in ('private-user@example.com secret-value', '"private/path" secret-value', 'remote "private-host'):
            with self.subTest(line=line), self.assertRaises(UserError) as result:
                openvpn_profile("client\n" + line, {}, self.root)
            message = str(result.exception)
            self.assertIn("line 2", message)
            self.assertNotIn("private", message)
            self.assertNotIn("secret-value", message)

    def test_certificate_only_and_inline_profiles_need_no_password(self):
        config = openvpn_profile("client\nremote vpn.example.com\n<ca>\ncertificate\n</ca>\n", {}, self.root)
        self.assertNotIn("auth-user-pass", config)
        self.assertIn("<ca>\ncertificate\n</ca>", config)

    def test_nyr_export_imports_without_forwarding_windows_dns_compatibility_options(self):
        # Public client-common.txt template from the user's Nyr installer;
        # inline credentials are synthetic and never loaded by OpenVPN here.
        template = """client
dev tun
proto {protocol}
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3
"""
        for protocol in ("udp", "tcp"):
            with self.subTest(protocol=protocol):
                profile = template.format(protocol=protocol)
                for section in ("ca", "cert", "key", "tls-crypt"):
                    profile += f"<{section}>\nSYNTHETIC {section}\n</{section}>\n"
                config = openvpn_profile(profile, {}, self.root)
                self.assertNotIn("ignore-unknown-option", config)
                self.assertIn('pull-filter ignore "block-outside-dns"', config)
                self.assertIn("proto " + ("udp4" if protocol == "udp" else "tcp4-client"), config)
                self.assertIn("redirect-gateway def1", config)
                self.assertIn("remote-cert-tls server", config)
                for section in ("ca", "cert", "key", "tls-crypt"):
                    self.assertIn(f"<{section}>\nSYNTHETIC {section}\n</{section}>", config)
                self.assertNotIn("auth-user-pass", config)
                self.assertFalse((self.root / "auth.txt").exists())

    def test_windows_dns_compatibility_does_not_bypass_the_allowlist(self):
        config = openvpn_profile("remote vpn.example.com\nblock-outside-dns\n", {}, self.root)
        self.assertNotIn("\nblock-outside-dns\n", config)
        for option in ("ignore-unknown-option", "ignore-unknown-option up",
                       "ignore-unknown-option block-outside-dns up", "block-outside-dns unexpected",
                       "ignore-unknown-option block-outside-dns\nup /tmp/script",
                       "ignore-unknown-option block-outside-dns\nroute 0.0.0.0 0.0.0.0 net_gateway"):
            with self.subTest(option=option), self.assertRaises(UserError):
                openvpn_profile("remote vpn.example.com\n" + option, {}, self.root)

    def test_pushed_ipv6_redirect_cannot_override_the_local_ipv4_tunnel_policy(self):
        config = openvpn_profile("client\nremote vpn.example.com\nredirect-gateway def1 ipv6\n", {}, self.root)
        self.assertEqual(config.splitlines().count("redirect-gateway def1"), 1)
        for option in ("redirect-gateway", "redirect-private", "route-ipv6", "ifconfig-ipv6", "tun-ipv6"):
            self.assertIn(f'pull-filter ignore "{option}"', config)
        # IPv4 tunnel addressing and its next hop must still be accepted.
        self.assertNotIn('pull-filter ignore "route"', config)
        self.assertNotIn('pull-filter ignore "route-gateway"', config)
        self.assertNotIn('pull-filter ignore "ifconfig"', config)

    def test_missing_certificates_and_authentication_get_actionable_errors(self):
        for text in ("remote vpn.example.com\nca missing.crt", "remote vpn.example.com\nauth-user-pass", "remote vpn.example.com\n<ca>\nnever closed"):
            with self.subTest(text=text), self.assertRaises(UserError):
                openvpn_profile(text, {}, self.root)

    def test_upload_names_cannot_escape_private_directory(self):
        for name in ("../secret", "/secret", "..", "a\\b", "line\nbreak"):
            with self.subTest(name=name), self.assertRaises(UserError):
                decode_upload({"name": name, "data": "eA=="})
        self.assertEqual(decode_upload({"name": "My VPN profile.ovpn", "data": "eA=="})[1], b"x")

    def test_xray_import_removes_direct_routes_and_desktop_listeners(self):
        source = {"inbounds": [{"protocol": "socks", "port": 1080}],
                  "outbounds": [{"protocol": "freedom", "tag": "direct"},
                                {"protocol": "vless", "settings": {"vnext": [{"address": "vpn.example.com"}]}},
                                {"protocol": "blackhole"}], "routing": {"rules": [{"outboundTag": "direct"}]}}
        config = xray_profile(json.dumps(source))
        self.assertEqual([out["protocol"] for out in config["outbounds"]], ["vless"])
        self.assertEqual(config["inbounds"][0]["protocol"], "tun")
        self.assertEqual(config["inbounds"][0]["settings"]["autoSystemRoutingTable"], ["0.0.0.0/0"])
        self.assertEqual(config["outbounds"][0]["streamSettings"]["sockopt"]["interface"], "eth0")
        self.assertNotIn("routing", config)

    def test_xray_rejects_ambiguous_and_chained_profiles(self):
        for source in ({}, {"outbounds": [{"protocol": "freedom"}]},
                       {"outbounds": [{"protocol": "vless", "settings": {}}, {"protocol": "trojan", "settings": {}}]},
                       {"outbounds": [{"protocol": "vless", "settings": {}, "proxySettings": {"tag": "direct"}}]}):
            with self.subTest(source=source), self.assertRaises(UserError):
                xray_profile(json.dumps(source))


class StorageTests(TemporaryCase):
    def test_folder_picker_cannot_follow_symlinks_outside_mount(self):
        storage = self.root / "storage"
        storage.mkdir()
        (storage / "Movies").mkdir()
        (storage / "escape").symlink_to(self.root, target_is_directory=True)
        app = Storage(storage)
        self.assertEqual(app.list()["folders"], ["Movies"])
        for path in ("..", "escape", "/etc"):
            with self.subTest(path=path), self.assertRaises(UserError):
                app.resolve(path)

    def test_create_cannot_use_path_traversal(self):
        app = Storage(self.root)
        for name in ("../other", "a/b", "..", "a\\b", ""):
            with self.subTest(name=name), self.assertRaises(UserError):
                app.create(".", name)


class AuthTests(TemporaryCase):
    def test_setup_requires_dsm_code_and_stores_only_password_hash(self):
        accounts = Accounts(self.root)
        with self.assertRaises(UserError):
            accounts.authenticate({"code": "wrong", "password": "long-test-password"}, "peer", True)
        identifier, session = accounts.authenticate({"code": accounts.setup_code, "password": "long-test-password"}, "peer", True)
        self.assertEqual(accounts.session(identifier)["csrf"], session["csrf"])
        self.assertNotIn("long-test-password", (self.root / "account.json").read_text())
        self.assertFalse((self.root / "setup-code").exists())
        with self.assertRaises(UserError):
            accounts.authenticate({"password": "incorrect"}, "peer")
        accounts.logout(identifier)
        with self.assertRaises(UserError):
            accounts.session(identifier)
        self.assertTrue(Accounts(self.root).authenticate({"password": "long-test-password"}, "peer"))

    def test_setup_cannot_be_repeated_and_login_attempts_are_limited(self):
        accounts = Accounts(self.root)
        for _ in range(10):
            with self.assertRaises(UserError):
                accounts.authenticate({"code": "wrong", "password": "password"}, "peer", True)
        with self.assertRaises(UserError) as result:
            accounts.authenticate({"code": accounts.setup_code, "password": "long-test-password"}, "peer", True)
        self.assertEqual(result.exception.status, 429)


class FakeGateway:
    def __init__(self):
        self.state = "not_configured"
        self.protocol = None
        self.calls = []

    def call(self, path, data=None):
        self.calls.append((path, data))
        if path == "/configure":
            self.protocol = data["protocol"]
            self.state = "connected"
        if path == "/disconnect":
            self.state = "disconnected"
        if path == "/connect":
            self.state = "connected"
        return {"state": self.state, "protocol": self.protocol, "protected": True,
                "torrents_allowed": self.state == "connected",
                "profile_name": "Private profile.ovpn" if self.protocol else None,
                "external_ip": "203.0.113.42" if self.state == "connected" else None}


class FakeRPC:
    def __init__(self):
        self.calls = []
        self.torrents = []

    def call(self, method, arguments=None):
        self.calls.append((method, arguments))
        if method == "torrent-get":
            return {"torrents": self.torrents}
        if method == "torrent-add":
            self.torrents.append({"id": len(self.torrents) + 1, "name": "Example download", "status": 4,
                                  "percentDone": 0.35, "rateDownload": 102400, "rateUpload": 2048,
                                  "totalSize": 10000000, "downloadDir": arguments["download-dir"], "errorString": ""})
        return {}


class APITests(TemporaryCase):
    def setUp(self):
        super().setUp()
        storage = self.root / "downloads"
        storage.mkdir()
        (storage / "Movies").mkdir()
        self.gateway, self.rpc = FakeGateway(), FakeRPC()
        self.app = Application(self.root / "web", Storage(storage), self.gateway, self.rpc)
        self.server = serve(self.app, ("127.0.0.1", 0))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.cookie, self.csrf = "", ""

    def call(self, path, data=None, headers=None):
        values = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        values.update(headers or {})
        if data is not None:
            values["Content-Type"] = "application/json"
        req = request.Request(self.url + path, data=None if data is None else json.dumps(data).encode(), headers=values)
        with request.urlopen(req, timeout=5) as response:
            if response.headers.get("Set-Cookie"):
                self.cookie = response.headers["Set-Cookie"].split(";")[0]
            return json.load(response)

    def login(self):
        result = self.call("/api/setup", {"code": self.app.accounts.setup_code, "password": "long-test-password"})
        self.csrf = result["csrf"]

    def test_authentication_and_csrf_protect_vpn_actions(self):
        with self.assertRaises(error.HTTPError) as result:
            self.call("/api/status")
        self.assertEqual(result.exception.code, 401)
        self.login()
        with self.assertRaises(error.HTTPError) as result:
            self.call("/api/vpn/disconnect", {}, {"X-CSRF-Token": "wrong"})
        self.assertEqual(result.exception.code, 403)
        with self.assertRaises(error.HTTPError) as result:
            self.call("/api/vpn/disconnect", {}, {"Origin": "https://evil.example"})
        self.assertEqual(result.exception.code, 403)
        self.assertEqual(self.call("/api/vpn/disconnect", {})["state"], "disconnected")

    def test_browser_setup_folder_and_torrent_flow(self):
        self.login()
        self.assertEqual(self.call("/api/folders")["folders"], ["Movies"])
        with patch.object(self.app.storage, "check_writable", return_value="Movies"):
            self.call("/api/configure", {"protocol": "openvpn", "download_dir": "Movies", "profile": {"name": "client.ovpn", "data": "eA=="}})
            self.call("/api/torrents", {"torrent": base64.b64encode(b"test metainfo").decode()})
        self.assertEqual(self.rpc.calls[-1][1]["download-dir"], "/downloads/Movies")
        self.assertEqual(len(self.call("/api/torrents")["torrents"]), 1)
        self.call("/api/torrents/action", {"id": 1, "action": "remove"})
        self.assertFalse(self.rpc.calls[-1][1]["delete-local-data"])

    def test_disconnected_vpn_refuses_new_and_resumed_torrents(self):
        self.login()
        for path, data in (("/api/torrents", {"magnet": "magnet:?xt=urn:btih:test"}),
                           ("/api/torrents/action", {"id": 1, "action": "start"})):
            with self.subTest(path=path), self.assertRaises(error.HTTPError) as result:
                self.call(path, data)
            self.assertEqual(result.exception.code, 409)
        self.assertFalse(self.rpc.calls)

    def test_public_session_does_not_expose_service_or_setup_credentials(self):
        value = self.call("/api/session")
        self.assertTrue(value["setup_required"])
        self.assertNotIn(self.app.accounts.setup_code, json.dumps(value))
        with request.urlopen(self.url) as response:
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            self.assertIn(b"Choose your connection", response.read())


class FirewallTests(unittest.TestCase):
    def test_existing_peer_sessions_cannot_bypass_guard_on_route_fallback(self):
        commands = firewall_commands("eth1", "TEST_GUARD")
        self.assertEqual(commands[-1][-2:], ["-j", "DROP"])
        self.assertFalse(any("--uid-owner" in command or "owner" in command for command in commands))
        self.assertFalse(any("ESTABLISHED" in command for command in commands))
        self.assertFalse(any("-F" in command or "REJECT" in command for command in commands))



class GatewayTests(TemporaryCase):
    def controller(self):
        # Profile validation/status tests do not need OS network operations or a
        # background monitor. The real guard is checked by the container smoke test.
        with patch("app.gateway.threading.Thread.start"):
            return Controller(self.root, self.root / "control", "test-token", install_guard=False)

    def test_rejected_upload_keeps_the_existing_connection(self):
        controller = self.controller()
        controller.active = {"protocol": "openvpn", "file": "existing.ovpn", "enabled": True}
        profile = base64.b64encode(b"remote vpn.example.com\nup /tmp/script").decode()
        with patch.object(controller, "_stop") as stop:
            with self.assertRaises(UserError):
                controller.configure({"protocol": "openvpn", "profile": {"name": "client.ovpn", "data": profile}})
            stop.assert_not_called()
        self.assertEqual(controller.active["file"], "existing.ovpn")

    def test_automatic_retries_do_not_hide_a_persistent_connection_failure(self):
        controller = self.controller()
        controller.active = {"protocol": "openvpn", "file": "test.ovpn", "enabled": True}
        controller.started = time.monotonic() - 100
        with patch("app.gateway.subprocess.Popen") as start:
            start.return_value.poll.return_value = None
            controller._start()
        self.assertEqual(controller.status()["state"], "error")

    def test_saved_profiles_receive_the_current_server_push_policy_at_start(self):
        controller = self.controller()
        filename = self.root / "existing.ovpn"
        old_config = 'client\nremote vpn.example.com\nredirect-gateway def1\npull-filter ignore "ifconfig-ipv6"\n'
        filename.write_text(old_config)
        controller.active = {"protocol": "openvpn", "file": str(filename), "enabled": True}
        with patch("app.gateway.subprocess.Popen") as start:
            controller._start()
        command = start.call_args.args[0]
        filters = [command[index + 1:index + 3] for index, arg in enumerate(command) if arg == "--pull-filter"]
        for option in ("redirect-gateway", "redirect-private", "route-ipv6", "ifconfig-ipv6", "tun-ipv6", "block-outside-dns"):
            self.assertIn(["ignore", option], filters)
        self.assertNotIn(["ignore", "route"], filters)
        self.assertEqual(filename.read_text(), old_config)

    def monitor_once(self, controller):
        with patch("app.gateway.time.sleep", side_effect=lambda _: setattr(controller, "stopping", True)):
            controller._monitor()

    def test_dns_probe_failure_stays_blocked_and_reports_only_the_curl_code(self):
        controller = self.controller()
        controller.process = Mock()
        controller.process.poll.return_value = None
        output = io.StringIO()
        probe = Mock(returncode=28, stdout=b"private response", stderr=b"private resolver address")
        with patch("app.gateway.subprocess.run", return_value=probe), patch.object(controller, "_grant") as grant, patch("sys.stdout", output):
            self.monitor_once(controller)
        grant.assert_not_called()
        self.assertIn("curl exit 28", output.getvalue())
        self.assertNotIn("private", output.getvalue())
        self.assertFalse(controller.connected)
        self.assertIsNone(permit.read(controller.control_root, controller.token))

    def test_permission_update_failure_revokes_and_identifies_the_failed_phase(self):
        controller = self.controller()
        controller.process = Mock()
        controller.process.poll.return_value = None
        output = io.StringIO()
        probe = Mock(returncode=0, stdout=b"198.18.0.1")
        addresses = json.dumps([{"addr_info": [{"family": "inet", "local": "10.8.0.2"}]}]).encode()
        with patch("app.gateway.subprocess.run", return_value=probe), patch(
                "app.gateway.subprocess.check_output", return_value=addresses), patch.object(
                controller, "_grant", side_effect=OSError("private command/address")), patch("sys.stdout", output):
            self.monitor_once(controller)
        self.assertIn("Torrent permission update failed (OSError)", output.getvalue())
        self.assertNotIn("private", output.getvalue())
        self.assertFalse(controller.connected)
        self.assertIsNone(permit.read(controller.control_root, controller.token))


if __name__ == "__main__":
    unittest.main()
