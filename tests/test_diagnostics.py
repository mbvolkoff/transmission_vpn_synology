import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from app.gateway import Controller, install_firewall, run_firewall, serve
from app.health import healthy


class DiagnosticsTests(unittest.TestCase):
    def test_disconnected_health_client_is_not_treated_as_a_vpn_startup_error(self):
        with patch("app.gateway.ThreadingHTTPServer") as server:
            serve(Mock(), "test-token")
        handler_type = server.call_args.args[1]
        for stage, failure in (("end_headers", ConnectionResetError()), ("write", BrokenPipeError())):
            with self.subTest(stage=stage):
                handler = object.__new__(handler_type)
                handler.send_response = Mock()
                handler.send_header = Mock()
                handler.end_headers = Mock()
                handler.wfile = Mock()
                target = handler.wfile.write if stage == "write" else handler.end_headers
                target.side_effect = failure
                handler.reply(200, {"ready": True})
                handler.send_response.assert_called_once_with(200)
                self.assertTrue(handler.close_connection)

    def test_firewall_error_reports_kernel_message_and_keeps_failure(self):
        command = ["iptables", "-w", "-N", "TEST_GUARD"]
        failure = subprocess.CalledProcessError(3, command, stderr=b"Kernel backend is unavailable")
        output = io.StringIO()
        with patch("app.gateway.subprocess.run", side_effect=failure), patch("sys.stderr", output):
            with self.assertRaises(subprocess.CalledProcessError):
                run_firewall(command)
        self.assertIn("Kernel backend is unavailable", output.getvalue())
        self.assertIn("iptables -w -N TEST_GUARD", output.getvalue())

    def test_firewall_timeout_stays_a_failure(self):
        command = ["iptables", "-w", "-N", "TEST_GUARD"]
        output = io.StringIO()
        with patch("app.gateway.subprocess.run", side_effect=subprocess.TimeoutExpired(command, 15)), patch("sys.stderr", output):
            with self.assertRaises(subprocess.TimeoutExpired):
                run_firewall(command)
        self.assertIn("timed out", output.getvalue())

    def test_health_output_identifies_failure_without_echoing_private_messages(self):
        failures = [URLError("private backend details"),
                    HTTPError("http://internal/health", 503, "private response", {}, None)]
        for failure in failures:
            output = io.StringIO()
            with self.subTest(failure=type(failure).__name__), patch(
                    "app.health.urlopen", side_effect=failure), patch("sys.stderr", output):
                self.assertFalse(healthy("http://internal/health"))
            self.assertIn("Health check failed:", output.getvalue())
            self.assertNotIn("private", output.getvalue())

    def test_healthy_http_and_waiting_supervisor_still_pass(self):
        response = Mock(status=200)
        with patch("app.health.urlopen") as get:
            get.return_value.__enter__.return_value = response
            self.assertTrue(healthy("http://internal/health"))
        with patch("app.health.service_token", return_value="private-token"), patch(
                "app.transmission.supervisor_healthy", return_value=True):
            self.assertTrue(healthy("transmission"))


class FirewallBackendTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.stdout = patch("sys.stdout", self.output)
        self.stderr = patch("sys.stderr", self.output)
        self.stdout.start()
        self.stderr.start()
        self.addCleanup(self.stdout.stop)
        self.addCleanup(self.stderr.stop)

    def test_supported_default_backend_attaches_complete_guard_last(self):
        with patch("app.gateway.subprocess.run") as run:
            binary, tunnel_chain = install_firewall("eth1")
        self.assertEqual(binary, "iptables")
        self.assertTrue(tunnel_chain.endswith("_VPN"))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(all(command[0] == binary for command in commands))
        self.assertFalse(any("owner" in command for command in commands))
        self.assertEqual(commands[-1][2:5], ["-I", "INPUT", "1"])
        self.assertFalse(any("tun0" in command and "ACCEPT" in command for command in commands))

    def test_kernel_rejection_falls_back_to_complete_legacy_guard(self):
        def kernel(command, **kwargs):
            if command[0] == "iptables":
                raise subprocess.CalledProcessError(4, command, stderr=b"Unsupported kernel API")
            return Mock(returncode=0)

        with patch("app.gateway.subprocess.run", side_effect=kernel) as run:
            binary, _ = install_firewall("eth1")
        self.assertEqual(binary, "iptables-legacy")
        attached = [call.args[0] for call in run.call_args_list if "-I" in call.args[0]]
        self.assertEqual(len(attached), 3)
        self.assertEqual(attached[0][0], "iptables-legacy")
        self.assertIn("Unsupported kernel API", self.output.getvalue())

    def test_partial_preparation_cleans_only_its_unattached_chains(self):
        def kernel(command, **kwargs):
            if command[0] == "iptables" and "--ctstate" in command:
                raise subprocess.CalledProcessError(4, command, stderr=b"Match unavailable")
            return Mock(returncode=0)

        with patch("app.gateway.subprocess.run", side_effect=kernel) as run:
            binary, _ = install_firewall("eth1")
        self.assertEqual(binary, "iptables-legacy")
        commands = [call.args[0] for call in run.call_args_list]
        cleanup = [command for command in commands if command[0] == "iptables" and ("-F" in command or "-X" in command)]
        self.assertEqual(len(cleanup), 6)
        self.assertTrue(all(command[-1].startswith("TVPN_") for command in cleanup))
        self.assertFalse(any(command[0] == "iptables" and "-I" in command for command in commands))

    def test_no_supported_backend_keeps_startup_blocked(self):
        with patch("app.gateway.subprocess.run", side_effect=FileNotFoundError("backend missing")) as run:
            with self.assertRaisesRegex(RuntimeError, "No firewall backend"):
                install_firewall("eth1")
        self.assertFalse(any("-I" in call.args[0] for call in run.call_args_list))

    def test_attach_failure_is_fatal_without_switching_backend(self):
        def kernel(command, **kwargs):
            if "-I" in command:
                raise subprocess.CalledProcessError(4, command, stderr=b"Attach rejected")
            return Mock(returncode=0)

        with patch("app.gateway.subprocess.run", side_effect=kernel) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                install_firewall("eth1")
        self.assertTrue(all(call.args[0][0] == "iptables" for call in run.call_args_list))

    def test_gate_updates_use_the_selected_backend(self):
        # A small controller instance suffices to exercise both transitions;
        # no startup, private-volume setup or OS networking is needed here.
        controller = Controller.__new__(Controller)
        controller.guard_ready = True
        controller.traffic_allowed = False
        controller.firewall_binary = "iptables-legacy"
        controller.tunnel_chain = "TEST_VPN"
        controller.network = {"inside": "eth1"}
        with patch("app.gateway.subprocess.run") as run, patch("app.gateway.set_forwarding"):
            controller._set_traffic(True)
            controller._set_traffic(False)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], ["iptables-legacy", "-w", "-A", "TEST_VPN", "-i", "eth1", "-o", "tun0", "-j", "ACCEPT"])
        self.assertIn("ESTABLISHED,RELATED", commands[1])
        self.assertIn("tun0", commands[1])
        self.assertEqual(commands[2], ["iptables-legacy", "-w", "-F", "TEST_VPN"])


    def test_same_namespace_restart_keeps_its_legacy_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "firewall.json"
            state_file.write_text(json.dumps({"namespace": os.readlink("/proc/self/ns/net"), "binary": "iptables-legacy"}))
            with patch("app.gateway.subprocess.run") as run:
                binary, _ = install_firewall("eth1", state_file)
            self.assertEqual(binary, "iptables-legacy")
            self.assertTrue(all(call.args[0][0] == binary for call in run.call_args_list))

    def test_new_namespace_selects_again_and_persists_before_attaching(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "firewall.json"
            state_file.write_text(json.dumps({"namespace": "net:[old]", "binary": "iptables-legacy"}))

            def kernel(command, **kwargs):
                if "-I" in command:
                    saved = json.loads(state_file.read_text())
                    self.assertEqual(saved["namespace"], os.readlink("/proc/self/ns/net"))
                    self.assertEqual(saved["binary"], command[0])
                    self.assertEqual(saved["interface"], "eth1")
                return Mock(returncode=0)

            with patch("app.gateway.subprocess.run", side_effect=kernel):
                binary, _ = install_firewall("eth1", state_file)
            self.assertEqual(binary, "iptables")


if __name__ == "__main__":
    unittest.main()
