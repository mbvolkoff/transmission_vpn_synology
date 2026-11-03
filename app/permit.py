"""Authenticated, short-lived permission to run Transmission in this namespace."""

import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import time

from .common import write_private


LEASE_SECONDS = 12
PERMIT_FILE = "torrent-permit.json"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def rpc_token(token):
    return hmac.new(token.encode(), b"transmission-rpc-v2", hashlib.sha256).hexdigest()


def publish_router(directory, token, network):
    value = dict(network, namespace=os.readlink("/proc/self/ns/net"))
    signature = hmac.new(token.encode(), b"router-v2:" + _canonical(value), hashlib.sha256).hexdigest()
    write_private(Path(directory) / "router.json", json.dumps({"router": value, "signature": signature}))


def read_router(directory, token):
    try:
        value = json.loads((Path(directory) / "router.json").read_text())
        network, signature = value["router"], value["signature"]
        expected = hmac.new(token.encode(), b"router-v2:" + _canonical(network), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        address, subnet = ipaddress.IPv4Address(network["address"]), ipaddress.IPv4Network(network["subnet"])
        if address not in subnet or not isinstance(network["namespace"], str) or not network["namespace"]:
            return None
        return network
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def publish(directory, token, allowed, generation, tunnel_ip=None):
    permit = {"allowed": allowed, "generation": generation,
              "namespace": os.readlink("/proc/self/ns/net"),
              "issued": time.monotonic(), "tunnel_ip": tunnel_ip,
              "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    signature = hmac.new(token.encode(), _canonical(permit), hashlib.sha256).hexdigest()
    write_private(Path(directory) / PERMIT_FILE, json.dumps({"permit": permit, "signature": signature}))
    return permit


def read(directory, token, now=None, namespace=None):
    """Missing, stale, malformed, revoked or foreign permissions deny startup."""
    try:
        value = json.loads((Path(directory) / PERMIT_FILE).read_text())
        permit, signature = value["permit"], value["signature"]
        expected = hmac.new(token.encode(), _canonical(permit), hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            return None
        if permit["allowed"] is not True:
            return None
        if permit["boot"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
            return None
        issued = permit["issued"]
        if type(issued) not in (float, int) or not math.isfinite(issued):
            return None
        age = (time.monotonic() if now is None else now) - issued
        if not 0 <= age < LEASE_SECONDS:
            return None
        own_namespace = os.readlink("/proc/self/ns/net") if namespace is None else namespace
        if permit["namespace"] != own_namespace or not isinstance(permit["generation"], str) or not permit["generation"]:
            return None
        address = ipaddress.IPv4Address(permit["tunnel_ip"])
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            return None
        return permit
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def vpn_ready(status):
    return (isinstance(status, dict) and status.get("state") == "connected"
            and status.get("protected") is True and status.get("torrents_allowed") is True)
