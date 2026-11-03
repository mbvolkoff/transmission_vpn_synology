# Web-managed gateway architecture

The original chat proposed `haugene/transmission-openvpn`, a convenient single
service for an OpenVPN-only deployment. This implementation separates the web
management process, privileged VPN process, and torrent process while building
one shared Alpine image. Ordinary users see one app, not these internal roles.

```text
Browser / DSM HTTPS portal
          |
       web:8080                 control bridge
          |                            |
          +-- gateway:8081 (agent) -----+
          +-- gateway:9091 (RPC relay)
                      |
                  gateway              torrent bridge
                 /       \
       VPN transport    transmission:9091
              |           (own namespace)
             tun0 <--- routed torrent traffic
              |
        remote VPN server
```

## Services and hardware

All three services use one Alpine image targeting Linux amd64/x86-64 and ARM64.
There are no model-specific kernel builds, Docker socket mounts, host-network
mode, frontend build tools or external web assets. Requirements are Docker/
Container Manager, TUN, IPv4 forwarding/conntrack/NAT and NET_ADMIN during setup.
An unsupported required operation fails startup without launching the daemon.

- **web:** authenticated UI/API, storage picker and constrained RPC operations.
  It has no VPN volume, Docker socket or NET_ADMIN/NET_RAW. It stays usable while
  the VPN is off.
- **gateway:** private VPN configuration, OpenVPN or Xray, a control API and a
  bounded-duration TCP relay to Transmission RPC. It has NET_ADMIN and TUN. It
  joins the control and torrent bridges, forwarding between the torrent bridge
  and `tun0` only when the VPN is verified.
- **transmission:** its own namespace, attached only to the torrent bridge with
  no published ports. Its root supervisor installs routing/firewall restrictions,
  then permanently removes NET_ADMIN and NET_RAW from its effective, permitted,
  inheritable and bounding sets. Legacy iptables needs NET_RAW only during
  bootstrap to open its control socket. The daemon runs as
  non-root and cannot restore either capability or change its network setup.

The web service and torrent service do not share a bridge. Only the gateway
connects their networks. Control-network aliases identify the gateway's interfaces
without relying on Docker's interface or network attachment order. The control
bridge uses Docker's automatic IPAM and first-host gateway; custom control IPAM
is outside this deployment configuration.

## Packet protection without owner matching

No `xt_owner`, socket marks or custom kernel module is required. The torrent
namespace replaces Docker's default next hop with the VPN router. It retains
only the router's /32 link route and removes its connected bridge-subnet route.
The bridge has host masquerading disabled. Its OUTPUT guard blocks other bridge
addresses, multicast/broadcast, Docker's loopback DNS proxy and other loopback
services; only local Transmission RPC is exempted. Its DNS resolvers are public
addresses reached through the VPN router. IPv6 and source routing are disabled.
Router-mode redirect semantics with `accept_redirects=0` prevent ICMP redirects
from installing an alternative next hop. Setup verifies the required sysctls.

The gateway attaches permanent FORWARD guards on both incoming and outgoing
traffic for the torrent bridge. Their final action is DROP. A separate,
initially empty child chain allows only:

1. Torrent-bridge traffic going out through `tun0`, after VPN verification.
2. Established/related return traffic arriving from `tun0` and returning to the
   torrent bridge.

There is no blanket ESTABLISHED exception for outgoing traffic. An established
peer session whose route changes to the control/physical interface is dropped.
Closing the child chain denies both directions while the parent DROP remains.
The gateway masquerades torrent-subnet traffic only when it leaves `tun0`.

An INPUT guard denies torrent-bridge access to the agent, RPC relay and gateway
services. Its only exception is established TCP replies from port 9091 to RPC
connections initiated by the gateway. The relay listens on the control address,
then connects to Transmission through the torrent bridge. Transmission RPC uses
a derived credential distinct from the agent/permission signing credential.
Reading its own settings does not give the daemon an agent or signing key.

The gateway namespace starts with global/default forwarding disabled by Compose.
After its permanent guard is attached, it enables forwarding only on the torrent
link; the tunnel link is enabled only when granting verified traffic. Standard
rtnetlink IPv4 link configuration works with a read-only `/proc/sys` and does not
require SYS_ADMIN or host sysctl changes. New namespaces/interfaces therefore
cannot physically forward during application startup, including after a crash
while an old daemon lease is still valid. Link settings also explicitly disable
redirects and source routing, independently of Docker sysctl application order.

Both services prepare complete chains with nftables iptables, falling back to
legacy iptables before attachment when needed. The selected backend is pinned
before the first attachment; attachment failure is fatal. Later gate changes
use that backend. Failed preparation cleans only newly created unattached chains;
no host firewall or existing live protection is flushed.

## Verified daemon permission

After a tunnel-bound HTTPS probe succeeds, the gateway opens the packet gate
and publishes an HMAC-signed permission in a read-only shared control volume.
It includes the gateway namespace, host boot ID, connection generation, tunnel
IPv4 address and monotonic issue time. A separately authenticated router record
identifies the expected gateway namespace and private address/subnet.

The torrent supervisor accepts only a correctly signed permission for that router
and host boot, less than 12 seconds old. It checks every 250 ms and again before
spawning. Corruption, revocation, expiry, a different router address or a changed
connection binding stops the daemon (TERM, then KILL after five seconds). The
non-root daemon binds to its own isolated interface address; the gateway performs
VPN-side NAT. No daemon or backend RPC listener exists without permission; the
control-side relay itself stays available and returns no backend data when idle.

The gateway probes every five seconds with a five-second network timeout. During
outage detection and shutdown the permanent route/interface guard still blocks
physical fallback. Explicit disconnect closes the gate and revokes permission
before VPN teardown. A stale `tun0` alone cannot authorize the daemon or packets.
Reconnection changes the permission generation and safely restarts the daemon.

OpenVPN uses an option allowlist and script-security 1. Cross-platform profiles
may include `ignore-unknown-option block-outside-dns`; the importer discards only
that exact Windows-only compatibility marker and a standalone `block-outside-dns`
line. It also filters that option from server pushes, along with pushed
redirects and IPv6 interface/route settings. The app supplies its own IPv4
full-tunnel route and retains pushed IPv4 addressing and `route-gateway`. Startup
enforces these filters for saved profiles too. General unknown-option ignore
lists, custom scripts and routes remain rejected. Validation errors show
the option name and line number without its arguments. Xray imports one supported
proxy outbound, removes direct/split routing and desktop listeners, and receives
its own native TUN inbound. Its transport binds to the actual control interface.
Existing Xray profiles are normalized again when started, including after a
network-layout migration. Neither user uploads nor the UI can execute arbitrary
scripts. The gateway has configurable public external DNS upstreams so its
Internet check need not depend on a LAN resolver after the VPN redirect.
Docker's embedded DNS continues to resolve private service names. Magnets and
uploaded metainfo go to Transmission; the web process never
fetches torrent payloads on its own network. Offline lists show cached zero rates
and all management actions require verified permission.

## State and authentication

Private Docker named volumes keep VPN configuration, internal credentials and
application state out of the Git/build context. VPN status returns only state,
protocol, original file name and the verified exit IP. Profile/password content
is not retrievable through the API. Connection logs remain in the VPN volume.

Initial enrollment requires a random code visible only to the DSM administrator
in the web container log. The app uses PBKDF2-SHA256 password hashes, expiring
random sessions, HttpOnly/SameSite cookies, CSRF tokens, same-origin checks and
login throttling. Enable Secure cookies behind an HTTPS DSM portal. This is a
single app account, independent of DSM login; no DSM password is collected.

The agent's Docker health check means the guard is installed and the API ready.
It intentionally does not require an established VPN: users must be able to open
an unconfigured app and upload their first profile. The UI reports Connected only
when the selected process is running, an HTTPS IP check bound to tun0 succeeds,
the packet gate is open and a fresh daemon permission has been published.

## Testing and remaining deployment checks

Automated tests cover profile/import safety, private storage, authentication,
folder traversal, permission signatures/boot binding, separate RPC credentials,
cross-namespace router validation, lifecycle and disconnect ordering. The cold
smoke test uses the three real services and real non-root daemon with synthetic
permission, keeping the packet gate closed throughout.

The routed smoke test opens the actual gate to a disposable local sink and checks
TCP/UDP forwarding, source NAT, Docker-DNS/bridge/agent blocking and dropped
capabilities. It establishes a TCP connection, then forces the SAME destination
onto a working physical/control route: root control requests still succeed while
both the existing TCP session and new TCP/UDP torrent-namespace requests fail.
It also checks recovery and explicit gate close. An abrupt gateway crash leaves
a fresh daemon lease valid, then delays the new agent by five seconds to prove
that physical traffic stays blocked before any new firewall exists. Both nft and
legacy test variants deliberately reject owner matches.

The local validation host is x86-64, Docker 29.9.2, Linux
`7.1.1-76070101-generic`. Both nft and real legacy variants pass, including the
five-second startup delay after a crash with a live daemon/old valid lease.
The 61 application/security regression tests pass, including UDP/TCP client
exports from the supplied Nyr installer, saved-profile push filters, rejection
of unsafe ignore lists, failed probe/permission handling and disconnected
HTTP clients. The three-service smoke test also checks internal service lookup
with explicit external DNS upstreams.

On November 3, the user reported that the updated bundle connects to OpenVPN,
accepts torrent files and downloads successfully on the NAS. This is a reported
functional result; independent torrent-IP, outage/crash and restart evidence is
still pending. See the [first-review checklist](nas-test.md#0-first-successful-download-what-to-check-and-report).

The simulated test interface is not a real VPN. Actual ARM64 DSM behavior, live
OpenVPN/Xray routing, UDP/DHT and peer IP must pass the NAS acceptance test on each
hardware/DSM/provider combination. The earlier DS124 owner-match failure is
addressed by removing that prerequisite, but the new build still needs testing
on the actual DS124 and Intel NAS. See [migration/test notes](ds124-compatibility.md).

References: [Xray TUN](https://xtls.github.io/en/config/inbounds/tun.html),
[official Xray image](https://github.com/XTLS/Xray-core/blob/main/.github/docker/Dockerfile),
[Transmission RPC 4.0](https://github.com/transmission/transmission/blob/4.0.6/docs/rpc-spec.md),
[Synology web app projects](https://kb.synology.com/en-eu/insights/Use_Container_Manager_to_run_web_app),
[Docker bridge options](https://docs.docker.com/engine/network/drivers/bridge/),
[Linux redirect controls](https://docs.kernel.org/networking/ip-sysctl.html),
[Linux IPv4 link configuration](https://github.com/torvalds/linux/blob/v3.10/net/ipv4/devinet.c),
and [DSM desktop app packaging](https://help.synology.com/developer-guide/integrate_dsm/desktopapp.html).
