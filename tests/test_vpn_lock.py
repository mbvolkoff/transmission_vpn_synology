"""Fail-closed lifecycle and packet-gate regressions, without a real VPN."""
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from app import permit
from app.common import UserError, write_private
from app.gateway import Controller, firewall_commands
from app.storage import Storage
from app.transmission import Supervisor, supervisor_healthy
from app.web import Application


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.control = self.root / "control"
        self.token = "test-service-token"

    def grant(self, generation="first", address="198.18.0.1"):
        return permit.publish(self.control, self.token, True, generation, address)


class PermissionTests(TemporaryCase):
    def test_only_fresh_authenticated_same_namespace_permission_is_accepted(self):
        self.assertIsNone(permit.read(self.control, self.token))
        value = self.grant()
        self.assertEqual(permit.read(self.control, self.token), value)
        self.assertEqual((self.control / permit.PERMIT_FILE).stat().st_mode & 0o777, 0o600)
        self.assertIsNone(permit.read(self.control, "wrong-key"))
        self.assertIsNone(permit.read(self.control, self.token, namespace="net:[other]"))
        self.assertIsNone(permit.read(self.control, self.token, now=value["issued"] - 1))
        self.assertIsNone(permit.read(self.control, self.token, now=value["issued"] + permit.LEASE_SECONDS))
        permit.publish(self.control, self.token, False, "first")
        self.assertIsNone(permit.read(self.control, self.token))

    def test_corrupt_or_tampered_permissions_cannot_start_the_daemon(self):
        self.grant()
        path = self.control / permit.PERMIT_FILE
        value = json.loads(path.read_text())
        value["permit"]["tunnel_ip"] = "198.18.0.2"
        for content in (json.dumps(value), "{", "null", "[]", '{"permit":{},"signature":false}'):
            with self.subTest(content=content):
                path.write_text(content)
                self.assertIsNone(permit.read(self.control, self.token))

    def test_even_signed_invalid_fields_fail_closed(self):
        value = self.grant()
        for field, replacement in (("issued", float("nan")), ("issued", True),
                                   ("boot", "different-host-boot"),
                                   ("generation", ""), ("tunnel_ip", "127.0.0.1"),
                                   ("tunnel_ip", "0.0.0.0"), ("tunnel_ip", "::1")):
            with self.subTest(field=field, replacement=replacement):
                changed = dict(value, **{field: replacement})
                encoded = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
                signature = hmac.new(self.token.encode(), encoded, hashlib.sha256).hexdigest()
                write_private(self.control / permit.PERMIT_FILE, json.dumps({"permit": changed, "signature": signature}))
                self.assertIsNone(permit.read(self.control, self.token))


class SupervisorTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.network = {"address": "172.28.0.2", "subnet": "172.28.0.0/24"}
        permit.publish_router(self.control, self.token, self.network)
        self.supervisor = Supervisor(self.root / "data", self.control, self.token, 1000, 1000,
                                     self.root / "run/status.json", self.network, "172.28.0.3")
        self.child = Mock(pid=123)
        self.child.poll.return_value = None
        self.spawn = patch("app.transmission.subprocess.Popen", return_value=self.child).start()
        self.addCleanup(patch.stopall)

    def test_cold_start_has_no_daemon_or_rpc_state(self):
        self.supervisor.step()
        self.spawn.assert_not_called()
        self.assertFalse(self.supervisor.root.exists())
        state = json.loads(self.supervisor.status_file.read_text())
        self.assertEqual(state["state"], "waiting_for_vpn")
        self.assertIsNone(state["pid"])
        self.assertTrue(supervisor_healthy(self.supervisor.status_file, self.control, self.token))

    def test_valid_connection_starts_nonroot_bound_to_its_isolated_address(self):
        self.grant()
        self.supervisor.step()
        self.spawn.assert_called_once()
        self.assertEqual(self.spawn.call_args.kwargs["user"], 1000)
        self.assertEqual(self.spawn.call_args.kwargs["group"], 1000)
        self.assertEqual(self.spawn.call_args.kwargs["extra_groups"], [])
        settings = json.loads((self.supervisor.root / "settings.json").read_text())
        self.assertEqual(settings["bind-address-ipv4"], "172.28.0.3")
        self.assertNotEqual(settings["rpc-password"], self.token)
        self.assertFalse(settings["watch-dir-enabled"])

    def test_revocation_stops_and_does_not_restart_the_daemon(self):
        self.grant()
        self.supervisor.step()
        permit.publish(self.control, self.token, False, "first")
        self.supervisor.step()
        self.supervisor.step()
        self.child.terminate.assert_called_once()
        self.child.wait.assert_called_once_with(timeout=5)
        self.assertIsNone(self.supervisor.process)
        self.spawn.assert_called_once()

    def test_dead_agent_permission_expiry_stops_the_daemon(self):
        value = self.grant()
        self.supervisor.step()
        with patch("app.permit.time.monotonic", return_value=value["issued"] + permit.LEASE_SECONDS):
            self.supervisor.step()
        self.child.terminate.assert_called_once()
        self.assertIsNone(self.supervisor.process)

    def test_corruption_or_router_change_stops_the_daemon(self):
        for reason in ("corrupt", "changed_router"):
            with self.subTest(reason=reason):
                self.grant()
                permit.publish_router(self.control, self.token, self.network)
                self.child.reset_mock()
                self.child.poll.return_value = None
                self.supervisor.retry_after = 0
                self.supervisor.step()
                if reason == "corrupt":
                    (self.control / permit.PERMIT_FILE).write_text("invalid")
                else:
                    permit.publish_router(self.control, self.token, dict(self.network, address="172.28.0.4"))
                self.supervisor.step()
                self.child.terminate.assert_called_once()
                self.assertIsNone(self.supervisor.process)

    def test_reconnect_stops_old_generation_and_rebinds_immediately(self):
        self.grant()
        self.supervisor.step()
        self.grant("second", "198.18.0.2")
        self.supervisor.step()
        self.child.terminate.assert_called_once()
        self.assertEqual(self.spawn.call_count, 2)
        self.assertEqual(self.supervisor.binding[:2], ("second", "198.18.0.2"))
        settings = json.loads((self.supervisor.root / "settings.json").read_text())
        self.assertEqual(settings["bind-address-ipv4"], "172.28.0.3")

    def test_revocation_during_settings_preparation_prevents_spawn(self):
        self.grant()
        with patch("app.transmission.prepare_settings", side_effect=lambda *_: permit.publish(
                self.control, self.token, False, "first")):
            self.supervisor.step()
        self.spawn.assert_not_called()

    def test_unresponsive_daemon_is_killed(self):
        self.grant()
        self.supervisor.step()
        self.child.wait.side_effect = [subprocess.TimeoutExpired("transmission-daemon", 5), 0]
        permit.publish(self.control, self.token, False, "first")
        self.supervisor.step()
        self.child.kill.assert_called_once()
        self.assertIsNone(self.supervisor.process)

    def test_health_rejects_stale_or_inconsistent_supervisor_state(self):
        self.supervisor.step()
        self.grant()
        self.assertFalse(supervisor_healthy(self.supervisor.status_file, self.control, self.token))
        self.supervisor.step()
        with patch("app.transmission.RPC.call", return_value={}):
            self.assertTrue(supervisor_healthy(self.supervisor.status_file, self.control, self.token))
        with patch("app.transmission.time.monotonic", return_value=time.monotonic() + 20):
            self.assertFalse(supervisor_healthy(self.supervisor.status_file, self.control, self.token))

    def test_daemon_rpc_credential_cannot_sign_permissions(self):
        self.grant()
        self.supervisor.step()
        settings = json.loads((self.supervisor.root / "settings.json").read_text())
        self.assertIsNone(permit.read(self.control, settings["rpc-password"]))

    def test_isolated_supervisor_accepts_only_its_authenticated_router_namespace(self):
        with patch("app.permit.os.readlink", return_value="net:[gateway]"):
            permit.publish_router(self.control, self.token, self.network)
            self.grant()
        self.supervisor.step()
        self.spawn.assert_called_once()
        with patch("app.permit.os.readlink", return_value="net:[foreign]"):
            self.grant()
        self.supervisor.step()
        self.child.terminate.assert_called_once()



class GatewayLockTests(TemporaryCase):
    def controller(self):
        with patch("app.gateway.threading.Thread.start"):
            return Controller(self.root / "vpn", self.control, self.token, install_guard=False)

    def test_initial_packet_gate_is_closed_even_with_a_stale_tunnel(self):
        commands = firewall_commands("eth1", "GUARD")
        self.assertFalse(any("tun0" in command for command in commands))
        self.assertIn(["iptables", "-w", "-A", "GUARD", "-j", "GUARD_VPN"], commands)
        controller = self.controller()
        with self.assertRaises(RuntimeError):
            controller._grant("198.18.0.1")
        self.assertIsNone(permit.read(self.control, self.token))

    def test_disconnect_closes_gate_and_revokes_before_vpn_teardown(self):
        controller = self.controller()
        controller.network = {"inside": "eth1"}
        controller.guard_ready, controller.traffic_allowed = True, True
        controller.tunnel_chain = "TEST_VPN"
        controller.process = Mock()
        controller.process.poll.return_value = None
        order = []
        controller.process.terminate.side_effect = lambda: order.append("terminate")
        publish = permit.publish

        def record_publish(*args):
            order.append("revoke")
            return publish(*args)

        def command(args, **kwargs):
            order.append("close" if "iptables" in args else "delete")

        with patch("app.gateway.subprocess.run", side_effect=command), patch(
                "app.gateway.permit.publish", side_effect=record_publish):
            controller.disconnect()
        self.assertEqual(order, ["close", "revoke", "terminate", "delete"])
        self.assertIsNone(permit.read(self.control, self.token))

    def test_gate_error_still_revokes_and_tears_down_tunnel(self):
        controller = self.controller()
        controller.network = {"inside": "eth1"}
        controller.guard_ready, controller.traffic_allowed = True, True
        controller.tunnel_chain = "TEST_VPN"
        child = controller.process = Mock()
        child.poll.return_value = None
        self.grant()
        with patch("app.gateway.subprocess.run", side_effect=[OSError("iptables failed"), Mock()]):
            with self.assertRaises(OSError):
                controller.disconnect()
        self.assertIsNone(permit.read(self.control, self.token))
        child.terminate.assert_called_once()
        self.assertIsNone(controller.process)


class WebLockTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.gateway, self.rpc = Mock(), Mock()
        self.gateway.call.return_value = {"state": "connected", "protected": True, "torrents_allowed": True}
        self.rpc.call.return_value = {"torrents": [{"id": 1, "status": 4, "rateDownload": 100, "rateUpload": 20}]}
        self.app = Application(self.root / "web", Storage(self.root), self.gateway, self.rpc)

    def test_offline_list_is_cached_with_zero_activity_and_no_rpc(self):
        self.assertEqual(self.app.torrents()["torrents"][0]["rateDownload"], 100)
        self.rpc.reset_mock()
        self.gateway.call.return_value = {"state": "disconnected", "protected": True, "torrents_allowed": False}
        result = self.app.torrents()
        self.assertTrue(result["blocked"])
        self.assertEqual(result["torrents"][0]["status"], 0)
        self.assertEqual(result["torrents"][0]["rateDownload"], 0)
        self.assertEqual(result["torrents"][0]["rateUpload"], 0)
        self.rpc.call.assert_not_called()
        self.gateway.call.side_effect = UserError("Agent unavailable", 503)
        self.assertTrue(self.app.torrents()["blocked"])

    def test_disconnect_racing_rpc_does_not_report_live_rates(self):
        self.gateway.call.side_effect = [self.gateway.call.return_value, {"state": "disconnected"}]
        result = self.app.torrents()
        self.assertTrue(result["blocked"])
        self.assertEqual(result["torrents"][0]["rateDownload"], 0)

    def test_connected_label_alone_cannot_authorize_torrent_actions(self):
        for status in ({"state": "connected", "protected": False, "torrents_allowed": True},
                       {"state": "connected", "protected": True, "torrents_allowed": False},
                       {"state": "connected"}):
            self.gateway.call.return_value = status
            with self.subTest(status=status):
                self.assertTrue(self.app.torrents()["blocked"])
                with self.assertRaises(UserError):
                    self.app.add_torrent({"magnet": "magnet:?xt=urn:btih:test"})
                for action in ("start", "stop", "remove"):
                    with self.assertRaises(UserError):
                        self.app.torrent_action({"id": 1, "action": action})
        self.rpc.call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
