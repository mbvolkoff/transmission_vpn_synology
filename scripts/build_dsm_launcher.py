"""Build a DSM 7 menu launcher; it never installs/manages Docker or user data."""

import argparse
import io
import json
from pathlib import Path
import tarfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "TransmissionVPNLauncher"


def add(archive, name, data, mode=0o644):
    if isinstance(data, str):
        data = data.encode()
    entry = tarfile.TarInfo(name)
    entry.size, entry.mode = len(data), mode
    entry.uid = entry.gid = entry.mtime = 0
    archive.addfile(entry, io.BytesIO(data))


def build(output, url="", port=8080):
    if url:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Use an HTTP(S) portal root URL without credentials or query parameters")
    if not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535")
    ui = io.BytesIO()
    with tarfile.open(fileobj=ui, mode="w:gz") as payload:
        config = {".url": {"org.transmissionvpn.Launcher": {
            "type": "url", "icon": "images/icon_{0}.png", "title": "Transmission VPN",
            "desc": "Private downloads", "url": f"3rdparty/{PACKAGE}/index.html", "allUsers": True,
        }}}
        add(payload, "ui/config", json.dumps(config))
        add(payload, "ui/index.html", '<!doctype html><html lang="en"><meta charset="utf-8"><title>Transmission VPN</title><script src="launch.js" defer></script><p>Opening your downloads app… <a id="open">Open Transmission</a></p></html>')
        script = "const configured = " + json.dumps(url) + ";\n"
        script += "const host = location.hostname.includes(':') ? '[' + location.hostname + ']' : location.hostname;\n"
        script += "const target = configured || 'http://' + host + ':" + str(port) + "/';\n"
        script += "document.getElementById('open').href = target; location.replace(target);\n"
        add(payload, "ui/launch.js", script)
        for size in (16, 24, 32, 48, 64, 72, 256):
            add(payload, f"ui/images/icon_{size}.png", (ROOT / f"synology/icons/icon_{size}.png").read_bytes())
    metadata = {
        "package": PACKAGE, "version": "0.1.0-0001", "os_min_ver": "7.0-40000", "arch": "noarch",
        "description": "DSM menu launcher for the Transmission VPN web app. Install its Container Manager project separately.",
        "maintainer": "transmission_vpn_synology", "displayname": "Transmission VPN",
        "thirdparty": "yes", "dsmuidir": "ui", "dsmappname": "org.transmissionvpn.Launcher",
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w") as archive:
        add(archive, "INFO", "\n".join(key + "=" + json.dumps(value) for key, value in metadata.items()) + "\n")
        add(archive, "package.tgz", ui.getvalue())
        add(archive, "conf/privilege", json.dumps({"defaults": {"run-as": "package"}}))
        for name in ("preinst", "postinst", "preuninst", "postuninst", "preupgrade", "postupgrade"):
            add(archive, "scripts/" + name, "#!/bin/sh\n# Menu launcher only; preserve the project and its data.\nexit 0\n", 0o755)
        add(archive, "scripts/start-stop-status", '#!/bin/sh\ncase "$1" in start|stop|status) exit 0 ;; *) exit 1 ;; esac\n', 0o755)
        add(archive, "PACKAGE_ICON.PNG", (ROOT / "synology/icons/icon_64.png").read_bytes())
        add(archive, "PACKAGE_ICON_256.PNG", (ROOT / "synology/icons/icon_256.png").read_bytes())
    return output.resolve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="", help="HTTPS portal root URL; default opens this NAS on port 8080")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output", default=str(ROOT / "dist/TransmissionVPN-Launcher.spk"))
    arguments = parser.parse_args()
    try:
        print(build(arguments.output, arguments.url, arguments.port))
    except ValueError as exc:
        parser.error(str(exc))
