"""Convert uploaded client profiles into controlled, full-tunnel configurations."""

import base64
import copy
import json
from pathlib import Path
import re
import shlex

from .common import UserError, write_private


SAFE_NAME = re.compile(r"[^/\\\x00-\x1f\x7f]{1,128}\Z")
INLINE = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}
OPTIONS = {
    "client", "dev", "dev-type", "proto", "remote", "remote-random",
    "remote-random-hostname", "remote-cert-tls", "verify-x509-name", "auth-user-pass",
    "auth-nocache", "nobind", "resolv-retry", "persist-key", "persist-tun", "ca",
    "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "cipher",
    "data-ciphers", "data-ciphers-fallback", "auth", "verb", "mute", "reneg-sec",
    "tls-version-min", "tls-version-max", "tls-cipher", "tls-ciphersuites", "tls-client",
    "float", "ping", "ping-restart", "ping-exit", "connect-timeout", "connect-retry",
    "connect-retry-max", "server-poll-timeout", "explicit-exit-notify", "sndbuf", "rcvbuf",
    "fast-io", "mssfix", "tun-mtu", "fragment", "comp-lzo", "compress", "setenv",
    "redirect-gateway", "pull", "dhcp-option", "mute-replay-warnings", "remote-cert-eku",
    "remote-cert-ku", "tls-timeout", "hand-window", "tran-window", "auth-retry",
    "pull-filter", "tun-ipv6",
}
PROXIES = {"vless", "vmess", "trojan", "shadowsocks"}
# The app installs its own IPv4 full-tunnel route and disables IPv6 in Compose.
# Keep pushed IPv4 addressing/route-gateway, but never let a server replace this
# policy with another redirect (including a mixed IPv4/IPv6 redirect).
OPENVPN_PUSH_IGNORES = ("redirect-gateway", "redirect-private", "route-ipv6",
                        "ifconfig-ipv6", "tun-ipv6", "block-outside-dns")


def decode_upload(upload):
    if not isinstance(upload, dict) or not isinstance(upload.get("name"), str) or not SAFE_NAME.fullmatch(upload["name"]) or upload["name"] in (".", ".."):
        raise UserError("Use a file name without slashes or control characters.")
    try:
        data = base64.b64decode(upload["data"], validate=True)
    except (ValueError, KeyError, TypeError):
        raise UserError("The uploaded file could not be read. Please select it again.") from None
    if not data or len(data) > 2 * 1024 * 1024:
        raise UserError("Choose a nonempty configuration file smaller than 2 MB.")
    return upload["name"], data


def openvpn_profile(text, assets, directory, username="", password=""):
    lines, block, remote = [], None, False
    needs_auth, protocol = False, "udp4"
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if block:
            lines.append(raw)
            if line == f"</{block}>":
                block = None
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<"):
            block = line[1:-1]
            if block not in INLINE or line != f"<{block}>":
                raise UserError(f"The OpenVPN profile has an unsupported inline section on line {number}.")
            lines.append(raw)
            continue
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            raise UserError(f"The OpenVPN profile contains an incomplete quoted value on line {number}.") from None
        if not words:
            continue
        option, arguments = words[0].removeprefix("--"), words[1:]
        # Nyr and other cross-platform exports include this Windows-only DNS
        # flag. Torrent DNS already follows the guarded tunnel on Linux. Drop
        # only this exact compatibility marker, never a general ignore list
        # that could hide a misspelled or unsupported security option.
        if (option == "ignore-unknown-option" and arguments == ["block-outside-dns"]
                or option == "block-outside-dns" and not arguments):
            continue
        if option not in OPTIONS:
            # Report only a plausible directive name, never the whole line or
            # its arguments (which may contain credentials or private paths).
            setting = f"option '{option}'" if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", option) else "setting"
            raise UserError(f"OpenVPN {setting} on line {number} is not supported. Use a standard Linux TUN client profile without custom scripts or routes.")
        if option == "dev" and (not arguments or not arguments[0].startswith("tun")):
            raise UserError("Choose a TUN OpenVPN profile. TAP profiles are not supported.")
        if option == "proto":
            if arguments and arguments[0] in ("tcp", "tcp-client", "tcp4", "tcp4-client"):
                protocol = "tcp4-client"
            elif not arguments or arguments[0] not in ("udp", "udp4"):
                raise UserError("Choose an IPv4 OpenVPN client profile using UDP or TCP.")
        if option == "remote":
            if len(arguments) < 1 or len(arguments) > 2:
                raise UserError("Use one server address and an optional port per OpenVPN remote line.")
            remote = True
        if option == "auth-user-pass":
            needs_auth = True
            continue
        # The app owns route, interface, DNS and logging behavior. Windows-only
        # setenv opt flags are deliberately omitted from the Linux profile.
        if option in {"dev", "dev-type", "proto", "redirect-gateway", "dhcp-option", "setenv", "verb", "auth-retry", "pull-filter", "tun-ipv6"}:
            continue
        if option in INLINE:
            if not arguments:
                raise UserError("A referenced certificate or key file is missing.")
            name = Path(arguments[0].replace("\\", "/")).name
            if name not in assets:
                raise UserError(f"Also upload the supporting file '{name}' with this profile.")
            arguments[0] = str(directory / "assets" / name)
            line = option + " " + " ".join(shlex.quote(value) for value in arguments)
        lines.append(line)
    if block or not remote:
        raise UserError("Choose a complete OpenVPN client profile containing a remote server.")
    if needs_auth or username or password:
        if not username.strip() or not password or any(c in username + password for c in "\r\n\0"):
            raise UserError("This profile needs both a VPN username and password.")
        write_private(directory / "auth.txt", username + "\n" + password + "\n")
        lines.append("auth-user-pass " + str(directory / "auth.txt"))
    lines += ["dev tun0", "proto " + protocol, "redirect-gateway def1", "auth-nocache", "verb 3"]
    lines += [f'pull-filter ignore "{option}"' for option in OPENVPN_PUSH_IGNORES]
    return "\n".join(lines) + "\n"


def xray_profile(text, interface="eth0"):
    try:
        source = json.loads(text)
    except ValueError:
        raise UserError("Choose a valid Xray client JSON file.") from None
    if not isinstance(source, dict) or not isinstance(source.get("outbounds"), list):
        raise UserError("The Xray JSON must contain an outbounds list with a configured proxy.")
    candidates = [out for out in source["outbounds"] if isinstance(out, dict) and out.get("protocol") in PROXIES]
    if len(candidates) != 1:
        raise UserError("Choose an Xray client JSON with exactly one proxy server. Direct and blocked entries may also be present.")
    proxy = copy.deepcopy(candidates[0])
    if not isinstance(proxy.get("settings"), dict):
        raise UserError("The Xray proxy is missing its server settings.")
    # Import the remote proxy, replacing desktop listeners and split/direct
    # routing. Every intercepted connection uses this single remote outbound.
    proxy["tag"] = "vpn"
    proxy.pop("sendThrough", None)
    mux = proxy.get("mux") or {}
    if not isinstance(mux, dict):
        raise UserError("The Xray multiplexing settings must be a JSON object.")
    if proxy.get("proxySettings") or mux.get("enabled"):
        # Existing mux combinations differ in UDP handling; leave it disabled.
        if proxy.get("proxySettings"):
            raise UserError("Chained Xray proxies are not supported. Export a single-server profile.")
        proxy.pop("mux", None)
    stream = proxy.setdefault("streamSettings", {})
    if not isinstance(stream, dict):
        raise UserError("The Xray transport settings must be a JSON object.")
    sockopt = stream.setdefault("sockopt", {})
    if not isinstance(sockopt, dict) or sockopt.get("dialerProxy"):
        raise UserError("Chained Xray transports are not supported.")
    sockopt["interface"] = interface
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {"servers": ["1.1.1.1"]},
        "inbounds": [{"tag": "tunnel", "protocol": "tun", "settings": {
            "name": "tun0", "mtu": 1500, "gateway": ["172.31.255.1/30"],
            "autoSystemRoutingTable": ["0.0.0.0/0"], "autoOutboundsInterface": interface,
        }}],
        "outbounds": [proxy],
    }
