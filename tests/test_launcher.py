import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("launcher", ROOT / "scripts/build_dsm_launcher.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class LauncherTests(unittest.TestCase):
    def test_dsm_launcher_has_required_metadata_privileges_icons_and_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = launcher.build(Path(directory) / "launcher.spk", "https://downloads.example.com/")
            with tarfile.open(output) as package:
                metadata = package.extractfile("INFO").read().decode()
                for field in ("package", "version", "os_min_ver", "arch", "description", "maintainer", "dsmappname"):
                    self.assertIn(field + "=", metadata)
                privilege = json.load(package.extractfile("conf/privilege"))
                self.assertEqual(privilege["defaults"]["run-as"], "package")
                for entry in package.getmembers():
                    self.assertFalse(entry.name.startswith("/") or ".." in Path(entry.name).parts)
                    if entry.name.startswith("scripts/"):
                        self.assertEqual(entry.mode, 0o755)
                        self.assertNotIn(b"docker", package.extractfile(entry).read())
                with tarfile.open(fileobj=io.BytesIO(package.extractfile("package.tgz").read())) as payload:
                    config = json.load(payload.extractfile("ui/config"))
                    self.assertTrue(config[".url"]["org.transmissionvpn.Launcher"]["allUsers"])
                    self.assertIn(b"https://downloads.example.com/", payload.extractfile("ui/launch.js").read())
                    self.assertTrue(payload.extractfile("ui/images/icon_64.png").read().startswith(b"\x89PNG"))

    def test_launcher_rejects_script_urls_and_embedded_credentials(self):
        for url in ("javascript:alert(1)", "https://user:password@example.com/", "https://example.com/?secret=value"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                launcher.build("unused.spk", url)


if __name__ == "__main__":
    unittest.main()
