"""Interface-based isolation: no socket-owner match or custom kernel modules."""
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys

from .common import read_json, write_private


def configure_link(interface, settings):
    """Set only this namespace's per-link IPv4 settings via rtnetlink.

    Docker mounts /proc/sys read-only. IFLA_AF_SPEC/IFLA_INET_CONF has supported
    per-interface IPv4 configuration since before Linux 3.10 and needs only
    NET_ADMIN. Global/default forwarding stay off, so newly created namespaces
    and interfaces cannot forward before their firewall is ready.
    """
    identifiers = {"forwarding": 1, "accept_redirects": 4,
                   "secure_redirects": 5, "accept_source_route": 9}
    paths = {name: Path(f"/proc/sys/net/ipv4/conf/{interface}/{name}") for name in settings}
    if all(paths[name].read_text().strip() == str(int(value)) for name, value in settings.items()):
        return
    def attribute(kind, data):
        size = 4 + len(data)
        return struct.pack("=HH", size, kind) + data + b"\0" * (-size % 4)
    config = b"".join(attribute(identifiers[name], struct.pack("=I", int(value)))
                      for name, value in settings.items())
    inet = attribute(1 | 0x8000, config)  # IFLA_INET_CONF
    af = attribute(socket.AF_INET | 0x8000, inet)
    attrs = attribute(26 | 0x8000, af)  # IFLA_AF_SPEC
    info = struct.pack("=BBHiII", 0, 0, 0, socket.if_nametoindex(interface), 0, 0)
    header = struct.pack("=IHHII", 16 + len(info) + len(attrs), 16, 5, 1, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as connection:
        connection.settimeout(3)
        connection.bind((0, 0))
        connection.send(header + info + attrs)
        reply = connection.recv(65536)
    if len(reply) < 20 or struct.unpack_from("=H", reply, 4)[0] != 2:
        raise RuntimeError("Missing forwarding configuration acknowledgment")
    error = struct.unpack_from("=i", reply, 16)[0]
    if error:
        raise OSError(-error, os.strerror(-error))
    if not all(paths[name].read_text().strip() == str(int(value)) for name, value in settings.items()):
        raise RuntimeError("Kernel did not apply the IPv4 link configuration")


def set_forwarding(interface, enabled):
    configure_link(interface, {"forwarding": int(enabled), "accept_redirects": 0, "accept_source_route": 0})


def run_firewall(command, timeout=15):
    try:
        return subprocess.run(command, check=True, capture_output=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr or b"No error detail returned"
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        print("firewall command failed: " + " ".join(command) + "\n" + detail[:2048], file=sys.stderr, flush=True)
        raise
    except subprocess.TimeoutExpired:
        print("firewall command timed out: " + " ".join(command), file=sys.stderr, flush=True)
        raise


def interfaces():
    values = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show"], timeout=3))
    result = {}
    for value in values:
        if value["ifname"] == "lo":
            continue
        addresses = [item for item in value.get("addr_info", []) if item.get("family") == "inet"]
        if addresses:
            item = addresses[0]
            result[value["ifname"]] = ipaddress.IPv4Interface(f'{item["local"]}/{item["prefixlen"]}')
    return result


def gateway_network():
    addresses = interfaces()
    router_ip = socket.gethostbyname("vpn-router")
    control_ip = socket.gethostbyname("vpn-control")
    inside = [name for name, value in addresses.items() if str(value.ip) == router_ip]
    outside = [name for name, value in addresses.items() if str(value.ip) == control_ip]
    if len(inside) != 1 or len(outside) != 1 or inside == outside:
        raise RuntimeError("Gateway requires exactly one torrent bridge and one control bridge")
    outside = outside[0]
    # Compose uses Docker's automatic IPAM on the control bridge. Its gateway is
    # the first host address. Select it explicitly: network attachment ordering
    # and newer gw_priority options differ across DSM/current Docker versions.
    gateway = str(addresses[outside].network.network_address + 1)
    subprocess.run(["ip", "-4", "route", "replace", "default", "via", gateway, "dev", outside],
                   check=True, capture_output=True, timeout=3)
    address = addresses[inside[0]]
    return {"outside": outside, "inside": inside[0], "address": str(address.ip),
            "subnet": str(address.network), "control_address": str(addresses[outside].ip)}


def firewall_commands(interface, chain, tunnel_chain=None, binary="iptables"):
    tunnel_chain = tunnel_chain or chain + "_VPN"
    return [
        [binary, "-w", "-N", tunnel_chain],
        [binary, "-w", "-N", chain],
        [binary, "-w", "-A", chain, "-j", tunnel_chain],
        [binary, "-w", "-A", chain, "-j", "DROP"],
    ]


def install_firewall(interface, state_file=None, subnet=None):
    """Prepare a complete routed guard, then attach it; pin the chosen backend."""
    namespace = os.readlink("/proc/self/ns/net")
    previous = read_json(state_file, {}) if state_file else {}
    binaries = ("iptables", "iptables-legacy")
    if previous.get("namespace") == namespace:
        if previous.get("binary") not in binaries:
            raise RuntimeError("Invalid saved firewall backend")
        binaries = (previous["binary"],)
    last_error = None
    for binary in binaries:
        chain = "TVPN_" + secrets.token_hex(5)
        tunnel_chain, incoming = chain + "_VPN", chain + "_IN"
        commands = firewall_commands(interface, chain, tunnel_chain, binary)
        commands += [
            [binary, "-w", "-N", incoming],
            # Only replies to the gateway's own RPC connections reach its INPUT.
            [binary, "-w", "-A", incoming, "-p", "tcp", "--sport", "9091", "-m", "conntrack",
             "--ctstate", "ESTABLISHED", "--ctdir", "REPLY", "-j", "ACCEPT"],
            [binary, "-w", "-A", incoming, "-j", "DROP"],
        ]
        created = []
        try:
            for command in commands:
                run_firewall(command)
                if "-N" in command:
                    created.append(command[-1])
            # Probe every required match/target before attaching live rules.
            run_firewall([binary, "-w", "-A", tunnel_chain, "-i", "tun0", "-m", "conntrack",
                          "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"])
            run_firewall([binary, "-w", "-F", tunnel_chain])
            if subnet:
                nat_chain = chain + "_NAT"
                run_firewall([binary, "-w", "-t", "nat", "-N", nat_chain])
                created.append(("nat", nat_chain))
                run_firewall([binary, "-w", "-t", "nat", "-A", nat_chain, "-s", subnet,
                              "-o", "tun0", "-j", "MASQUERADE"])
        except (OSError, subprocess.SubprocessError) as exc:
            last_error = exc
            print(f"gateway: {binary} could not prepare the guard; trying the next backend", flush=True)
            for entry in reversed(created):
                table, name = entry if isinstance(entry, tuple) else ("filter", entry)
                for action in ("-F", "-X"):
                    try:
                        run_firewall([binary, "-w", "1", "-t", table, action, name], timeout=3)
                    except (OSError, subprocess.SubprocessError):
                        pass
            continue
        if state_file:
            write_private(state_file, json.dumps({"namespace": namespace, "binary": binary,
                                                  "gate": tunnel_chain, "interface": interface}))
        # Any failure after the first attachment is fatal. Never switch a live
        # guard to another backend or grant daemon permission on partial setup.
        run_firewall([binary, "-w", "-I", "FORWARD", "1", "-i", interface, "-j", chain])
        run_firewall([binary, "-w", "-I", "FORWARD", "1", "-o", interface, "-j", chain])
        run_firewall([binary, "-w", "-I", "INPUT", "1", "-i", interface, "-j", incoming])
        if subnet:
            run_firewall([binary, "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-j", nat_chain])
        print(f"gateway: torrent traffic guard installed with {binary} (routed isolation; no owner match)", flush=True)
        return binary, tunnel_chain
    raise RuntimeError("No firewall backend could prepare torrent protection; check kernel support and NET_ADMIN") from last_error


def engine_commands(binary, chain, interface, address, router, subnet):
    prefix = [binary, "-w", "-A", chain]
    return [
        [binary, "-w", "-N", chain],
        # The only local service permitted is Transmission RPC. In particular,
        # Docker's 127.0.0.11 DNS proxy must never resolve torrent DNS externally.
        prefix + ["-o", "lo", "-d", "127.0.0.1", "-p", "tcp", "--dport", "9091", "-j", "ACCEPT"],
        prefix + ["-o", "lo", "-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "tcp", "--sport", "9091", "-j", "ACCEPT"],
        prefix + ["-o", "lo", "-j", "DROP"],
        prefix + ["-d", "224.0.0.0/4", "-j", "DROP"],
        prefix + ["-d", "255.255.255.255/32", "-j", "DROP"],
        prefix + ["-o", interface, "-d", router, "-j", "ACCEPT"],
        # Prevent direct access to Docker's bridge host and bridge peers, even
        # if a socket requests a link route. Only the VPN router is on-link.
        prefix + ["-d", subnet, "-j", "DROP"],
        prefix + ["-o", interface, "-s", address, "-j", "ACCEPT"],
        prefix + ["-j", "DROP"],
    ]


def drop_network_capabilities():
    """Permanently remove NET_ADMIN/NET_RAW from this process and descendants."""
    libc = ctypes.CDLL(None, use_errno=True)
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]
    header, data = Header(0x20080522, 0), (Data * 2)()
    if libc.capget(ctypes.byref(header), data):
        raise OSError(ctypes.get_errno(), "Cannot read process capabilities")
    for capability in (12, 13):
        if libc.prctl(24, capability, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "Cannot drop network administration capability")
    mask = ~((1 << 12) | (1 << 13)) & 0xffffffff
    data[0].effective &= mask
    data[0].permitted &= mask
    data[0].inheritable &= mask
    if libc.capset(ctypes.byref(header), data):
        raise OSError(ctypes.get_errno(), "Cannot drop network administration capability")


def prepare_engine(router):
    addresses = interfaces()
    if len(addresses) != 1:
        raise RuntimeError("Torrent service must have exactly one network interface")
    interface, address = next(iter(addresses.items()))
    gateway = ipaddress.IPv4Address(router["address"])
    if gateway == address.ip or gateway not in address.network or str(address.network) != router["subnet"]:
        raise RuntimeError("Torrent router does not match this network")
    # With forwarding enabled, Linux accepts redirects only when BOTH the
    # interface and conf/all permit them. This avoids interface-specific Docker
    # sysctl options that differ between old DSM Docker and current Docker.
    configure_link(interface, {"forwarding": 1, "accept_redirects": 0,
                               "secure_redirects": 0, "accept_source_route": 0})
    previous = read_json("/run/transmission-vpn/network.json", {})
    binaries = (previous["binary"],) if previous.get("binary") in ("iptables", "iptables-legacy") else ("iptables", "iptables-legacy")
    for binary in binaries:
        chain = "TVPN_ENGINE_" + secrets.token_hex(4)
        created = False
        try:
            for command in engine_commands(binary, chain, interface, str(address.ip), str(gateway), str(address.network)):
                run_firewall(command)
                if "-N" in command:
                    created = True
        except (OSError, subprocess.SubprocessError):
            if created:
                for action in ("-F", "-X"):
                    try:
                        run_firewall([binary, "-w", "1", action, chain], timeout=3)
                    except (OSError, subprocess.SubprocessError):
                        pass
            continue
        # Pin before attachment; never switch after an uncertain OUTPUT change.
        write_private("/run/transmission-vpn/network.json", json.dumps({"binary": binary}))
        run_firewall([binary, "-w", "-I", "OUTPUT", "1", "-j", chain])
        break
    else:
        raise RuntimeError("Cannot protect the torrent network")
    def ip(*args):
        subprocess.run(["ip", "-4", *args], check=True, capture_output=True, timeout=3)
    ip("route", "replace", str(gateway) + "/32", "dev", interface, "scope", "link")
    ip("route", "replace", "default", "via", str(gateway), "dev", interface)
    # Remove Docker's connected bridge route, so host/peer addresses cannot
    # bypass the VPN router. The local table still owns our own interface IP.
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show"], timeout=3))
    if any(route.get("dst") == str(address.network) and route.get("dev") == interface for route in routes):
        ip("route", "del", str(address.network), "dev", interface)
    Path("/etc/resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 9.9.9.9\n")
    drop_network_capabilities()
    print(f"transmission: isolated routing ready with {binary}; NET_ADMIN dropped; NET_RAW dropped", flush=True)
    return str(address.ip)
