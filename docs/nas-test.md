# Real NAS acceptance test

Goal: verify setup, downloads and **no torrent traffic without a verified VPN**
on the actual Synology. Repeat the connection/outage tests for OpenVPN and Xray
with real profiles. Use a legal, well-seeded test torrent and a BitTorrent IP-check
magnet/torrent. The web page's VPN IP alone does not verify the torrent peer IP.

Test **both ARM64 and Intel/amd64 NAS models** with the same Compose file. Record
the exact model, DSM/kernel and Container Manager versions for each. The portable
build uses routed isolation and requires no `xt_owner` or custom kernel module.
For the reported DS124, see [migration notes](ds124-compatibility.md).

## 0. First successful download: what to check and report

The November 3 report confirms a successful OpenVPN connection, torrent upload
and download on the deployed bundle. VPN-server traffic peaks are useful
functional evidence; the following checks establish the torrent exit address
and behavior when VPN permission is lost.

1. **Check the torrent's external address.** Open
   [IPLeak](https://ipleak.net/), activate **Torrent Address detection** and copy
   its test magnet into this NAS app's **Add download → Magnet** form. The
   service observes a tracker request from the torrent client. Its address
   should be the VPN exit address, distinct from the ordinary ISP address.
   The browser IP/WebRTC/DNS sections measure the browser's machine. This
   tracker check alone does not cover every peer connection, UDP or DNS path.
2. **Disconnect during an active transfer.** Use the app's **Disconnect** button.
   Downloads must change to **Waiting for VPN** and new/resumed transfers must
   be refused. After shutdown, the section 3 snapshot must show no daemon and
   no RPC listener. Reconnect and confirm resumption.
3. **Interrupt the VPN endpoint for at least 60 seconds.** Temporarily block all
   configured VPN endpoint IPs/ports for this NAS, or stop the OpenVPN service
   on the server you control. Keep the NAS's ordinary Internet connection up.
   Capture a section 3 snapshot during the outage and after recovery. An old
   IPLeak result can remain visible after a client stops; use timestamps and
   fresh observations rather than treating a cached result as new traffic.

During the outage, this command should still return the ordinary ISP address,
showing that a direct fallback would have working Internet access. The **web**
container is outside the torrent VPN path:

```sh
sudo docker exec transmission-vpn-test-web-1 curl -4 --fail --show-error --silent --max-time 10 https://api.ipify.org
```

Then run the crash and offline-start rows in section 2. For stronger evidence
about brief fallback windows, observe filtered peer/tracker/DNS traffic on the
NAS's external path or router during the outage/crash. No torrent traffic may
appear there outside the encrypted VPN transport. Unrelated NAS services and
VPN endpoint bootstrap lookups need to be distinguished from torrent traffic.
Record the observation and counters; do not share an unfiltered packet capture.

**Send for the first review:**

- NAS model, DSM/Container Manager versions and bundle checksum/source revision.
- A screenshot of the app's connected status and the torrent address result.
  You may replace addresses consistently with `VPN_EXIT` and `ISP_EXIT`.
- A small pass/fail table with timestamps for connected, explicit disconnect,
  endpoint outage, recovery, process crash and offline project restart.
- Section 3 process/RPC snapshots while connected, after disconnect, and at
  least 30 seconds into the outage. Show that the direct web-container probe
  still worked during the outage.
- Sanitized gateway and transmission logs around those tests; include the
  private VPN connection log only if connection/recovery failed. Section 4
  lists the commands and redactions.

After these pass, check a completed file in the selected File Station folder,
restart persistence, seeding/UDP behavior and CPU/RAM during a longer transfer.
Repeat the privacy tests separately on Intel/amd64 and Xray before marking those
combinations as tested.

## 1. Deploy

1. Record NAS model/CPU, DSM and Container Manager versions, and source revision.
   Confirm `/dev/net/tun` exists; the NAS must support iptables forwarding, conntrack and NAT.
2. In File Station, copy the repository to
   `/volume1/docker/transmission-vpn-test` and create
   `/volume1/docker/transmission-vpn-test/downloads`, alongside `compose.yaml`.
   Use dedicated test storage. Grant the configured non-root `PUID`/`PGID` write
   access; those IDs must match in all three services.
3. In **Container Manager → Project → Create**, name the project
   **transmission-vpn-test**, select that directory and `compose.yaml`, then
   proceed to **Web portal settings**. Use the normal Compose file;
   `tests/compose.smoke.yaml` is synthetic
   and must not be used for this test.
4. In **Web portal settings**, leave **Set up web portal via Web Station**
   **unchecked**. No dropdown values are required. Click **Next**, review the
   summary, keep **Start the project once it is created** enabled and click
   **Done**. Finish creating/building the project before opening Web Station.
   This optional integration can be configured afterward; Compose already
   publishes the app on NAS port 8080 by default.
5. After the build/start finishes, open **Container Manager → Project → select
   the project → Details → Containers**. Confirm `gateway`, `transmission` and
   `web` exist and become healthy. Open `http://<NAS-LAN-IP>:8080` (or your changed
   host port) and confirm the setup/login page appears. This is a connectivity
   check; configure HTTPS before submitting passwords/profiles. If containers
   are missing or the page fails, inspect the project build/start output and
   container logs first.
6. Configure HTTPS through the **DSM reverse proxy** described below, or the
   optional Web Station integration after project creation. Set
   `SECURE_COOKIES=true` for HTTPS-only access and apply that configuration to
   the project, then open the app through its HTTPS address.
7. Copy the first-time setup code from the **web container → Details → Log**,
   create the app password and sign in. If the log is empty, use the
   [setup-code fallback below](#first-time-setup-code-and-empty-dsm-logs).
   All three containers should be healthy even before VPN configuration; an idle
   torrent supervisor is healthy.

Publish only `web`; leave the gateway API and Transmission RPC internal.

### First-time setup code and empty DSM logs

The code confirms that the person creating the first app account has access to
the NAS's container administration. Otherwise, another person who reaches the
unconfigured web page could set its password first and take control of the app.
This code is generated locally by the **web** service. It is separate from the
DSM password and VPN credentials; there is no email or external activation
service. Enter it once, then use your chosen app password for later sign-ins.

1. In **Container Manager → Container**, select
   **transmission-vpn-test-web-1 → Details → Log**. Copy only the value after
   `First-time setup code:` into the setup form. The **gateway** and
   **transmission** logs do not contain this code. Use your actual web container
   name if you chose a different project name.
2. If the **web** log is also empty, open that container's **Terminal** / **Open
   terminal** action in DSM and start a `/bin/sh` shell if prompted. Run this
   read-only command **inside the web container**:

   ```sh
   cat /data/setup-code
   ```

   The image includes `/bin/sh`; do not select `/bin/bash`. The file is in the
   web container's private data volume, not the project folder in File Station.
   The same `/data` path in the torrent container is a different volume.
3. Alternatively, over SSH on the NAS, run this from any directory:

   ```sh
   sudo docker exec transmission-vpn-test-web-1 cat /data/setup-code
   ```

   To check web startup output independently of DSM's log viewer:

   ```sh
   sudo docker logs --timestamps --tail 100 transmission-vpn-test-web-1
   ```

Paste the code into **One-time setup code**, choose an app password of at least
12 characters, confirm it and click **Create account**. Keep the code private;
redact it before sharing logs or screenshots. The code file is removed after
successful account creation, and the code is no longer accepted. An older
startup log entry can remain. If an account already exists, refresh the page
and use the password login; do not delete volumes to retrieve a setup code.

No rebuild or project recreation is needed to read the code. A healthy gateway
and a reachable setup page confirm startup progress; they do not establish a
working VPN or verify that torrent traffic uses it. Continue with section 2
after account setup.

### Optional HTTPS portal configuration

**Optional Web Station integration, after project creation:** open **Container
Manager → Project → select the project → Details → Settings** and enable its web
portal with **web / 8080 / HTTP**. `web` is the Compose service; DSM may show a
longer name. Then open **Web Station → Web Portal → Create → Web service portal**
and select the existing service for this project in **Service**. Its label may
include `transmission-vpn-test`, `Docker Project` or `Container Manager`.
Configure an HTTPS portal with a suitable certificate and available port/hostname;
NAS port 8080 is already occupied by Compose. HTTP describes the internal app
connection; HTTPS protects the browser connection.

**If Web Station says no web services exist, or offers “Create new web service”:**
click **Later** and close its wizard. If still creating the Container Manager
project, return to step 4, uncheck the optional Web Station box and finish the
project first. The **Create Web Service → Select a service type** wizard creates
a separate website and is not required for this app. Once the app is running,
use the DSM reverse proxy if Web Station registration remains unavailable.

**DSM reverse proxy option:** after confirming the app works on its published
port, open **Control Panel → Login Portal → Advanced → Reverse Proxy → Create**.
Give the rule a description such as `Transmission VPN` and set:

| Side | Protocol | Hostname | Port |
| --- | --- | --- | --- |
| Source (browser) | HTTPS | A hostname that resolves to this NAS | An unused HTTPS port, e.g. 8443 |
| Destination (app) | HTTP | 127.0.0.1 | 8080, or your changed Compose host port |

Assign a certificate valid for the source hostname in **Control Panel → Security
→ Certificate**, then open `https://<source-hostname>:8443` (use your chosen port).
This route uses the running app directly and does not require a Web Station
service registration. Keep the same `SECURE_COOKIES=true` setting for HTTPS use.

DSM labels vary; see Synology's [project help](https://kb.synology.com/en-global/DSM/help/ContainerManager/docker_project?version=7)
and [container details/log help](https://kb.synology.com/en-me/DSM/help/ContainerManager/docker_container?version=7).
Synology also documents [enabling HTTPS on a Web Station portal](https://kb.synology.com/da-dk/insights/Accessing_your_website).
The [DSM reverse proxy setup](https://kb.synology.com/en-af/DSM/tutorial/Quick_Start_Synology_SSO)
describes the source/destination settings and hostname/certificate requirements.
The separate [Web Service creation wizard](https://kb.synology.com/index.php/en-us/DSM/help/WebStation/application_webserv_webservice?version=7)
builds new websites and is not needed for this container app.

### If startup reports “gateway is unhealthy”

The image may have built successfully even though the gateway failed to start.
The web and torrent containers deliberately wait for a healthy gateway. A green
running indicator alone is insufficient, and an empty DSM Log tab does not show
the health-check history. Keep the gateway health dependency enabled.

Run these read-only commands over SSH on the NAS; they work from any directory
and do not require `docker compose`:

```sh
sudo docker logs --timestamps --tail 100 transmission-vpn-test-gateway-1 2>&1
sudo docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} health={{json .State.Health}}' transmission-vpn-test-gateway-1
```

Paste the output when reporting the failure. `restarts` identifies a crash loop;
`oom=true` identifies an out-of-memory kill. Health-check output is stored
separately from normal container stdout/stderr, as described in
[Docker's health-check reference](https://docs.docker.com/reference/dockerfile/#healthcheck).
Older app builds may have empty health-check output; the status and restart
information are still useful.

**If the traceback ends in `iptables ... -N TVPN_...` with exit status 4:** the
gateway failed while creating its first firewall chain. The exit code alone does
not identify the kernel/backend error. Run this isolated probe to expose stderr,
even while the gateway is restarting:

```sh
sudo docker run --rm --network none --cap-add NET_ADMIN --entrypoint /bin/sh transmission-vpn:local -c '
uname -r
iptables --version
iptables -w 3 -S
'
```

This disposable container uses the same image and NET_ADMIN capability, with its
own network namespace, no external network and no private volumes. It does not
alter the NAS host firewall. Share all output, including the iptables error.
The image's `iptables` implementation may require kernel features unavailable on
the NAS; stderr is needed to distinguish this from permissions or locking errors.
Updated images include `iptables-legacy` and automatically try that backend if
the nftables guard cannot be prepared. The gateway still requires a complete
guard before becoming healthy; the selected backend appears in its startup log.

**If the log still mentions `--uid-owner` or missing `xt_owner`:** an older
image is running. The portable version never requests that match. Apply the
complete portable update, including `compose.yaml` and all application files;
the previous three-file firewall update is insufficient. Do not install a custom
module for the current version.

To update an existing project:

1. Stop the complete project. Extract `TransmissionVPN-PortableUpdate.zip` into
   its existing source directory (reported path:
   `/volume1/docker/transmission_vpn_synology`), overwriting source/Compose files.
   Keep `.env`, named volumes, downloads and private data.
2. Ensure Container Manager's **YAML Configurations** contains the new
   `compose.yaml`. It must attach Transmission to the `torrent` network and
   contain no `network_mode: service:gateway`. Gateway `net.ipv4.ip_forward`
   must start at `"0"`. Replace DSM's saved YAML if it still shows the old
   configuration.
3. Build the image and recreate/start **all three containers** using the updated
   YAML, preserving named volumes and storage. All three must be recreated for
   this network-layout migration. Do not use **Clean/Delete data**.
4. Check the gateway log for `(routed isolation; no owner match)` and Transmission
   for `isolated routing ready ... NET_ADMIN dropped`. Confirm all three healthy
   before configuring the web portal or uploading a VPN profile.

If the container stays running, these additional read-only checks identify the
kernel/firewall version and test the local control API:

```sh
sudo docker exec transmission-vpn-test-gateway-1 uname -r
sudo docker exec transmission-vpn-test-gateway-1 iptables --version
sudo docker exec transmission-vpn-test-gateway-1 iptables -w 3 -S
sudo docker exec transmission-vpn-test-gateway-1 curl --noproxy '*' -v --max-time 5 http://127.0.0.1:8081/health
```

These commands inspect only the gateway container's network namespace. If an
`exec` command reports that the container is restarting, preserve the first two
outputs instead. Startup/health failure does not require uploading a VPN profile.
Once the cause is corrected, build/start the complete project again while
preserving its volumes. Web Station setup comes after this check succeeds.

### If an OpenVPN profile is rejected during upload

If the app still says **Not configured** and reports an unsupported profile
option after **Save & connect**, validation failed before a connection attempt.
Gateway connection logs will not explain that rejection. Current builds identify
the rejected option name and its original line number in the browser error, for
example `OpenVPN option 'up' on line 8 is not supported`.

Report that option name and the app/provider that exported the profile. Do not
share the full `.ovpn` file, credentials, server addresses, or certificate/key
blocks. The older generic “unsupported scripts or advanced options” message does
not identify the cause: it is also used for unrecognized non-script options.
Use a standard Linux TUN client export when available. Keep the option allowlist
and script restrictions enabled; review the specific directive before editing
the profile or changing the importer. Invalid imports leave any previously saved
VPN profile active and do not authorize torrent traffic on an unconfigured app.

**Profiles generated by Nyr's `openvpn-install.sh`:** the supplied script's
client template contains `ignore-unknown-option block-outside-dns`. Earlier app
builds rejected that line. Current builds discard that exact Windows-only
compatibility marker (and a standalone `block-outside-dns` line), and filter out
the same option if pushed by the server. General ignore lists remain rejected;
scripts and custom routes are still refused. The Linux torrent network guard
continues to enforce tunnel-only DNS and peer traffic. See the
[OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)
for the Windows-specific meaning of `block-outside-dns`.

To test immediately on an older build, edit a local copy of the `.ovpn` file,
remove only this line, and upload the copy:

```text
ignore-unknown-option block-outside-dns
```

Keep all certificate/key blocks and other settings. The supplied script creates
certificate-based client profiles, so leave **VPN username** and **VPN password**
empty unless you separately configured username/password authentication on the
server. This workaround needs no container rebuild. Alternatively, apply the
updated source bundle and rebuild/recreate the project while preserving its
named volumes and downloads; then upload the original profile unchanged.

### If the profile is saved but the connection fails or the operation times out

**Saved profile: ...** confirms the import passed validation. **Connection
failed** means the app has not verified a working VPN connection; it does not
identify whether OpenVPN exited, the server is unreachable, or the tunnel's
Internet check failed. **The operation timed out** may also be the browser's
35-second request deadline. The gateway can continue working after that request
ends, so collect evidence before repeatedly saving/uploading the profile.

Run these read-only commands over SSH on the NAS, from any directory. They do
not require Docker Compose and apply to the current portable project as well:

```sh
sudo docker exec transmission-vpn-test-gateway-1 tail -n 100 /vpn/connection.log
sudo docker logs --timestamps --tail 80 transmission-vpn-test-gateway-1 2>&1
```

The first command reads the actual OpenVPN/Xray output, which is stored in the
private VPN volume rather than the ordinary DSM container log. The second reads
gateway supervisor/firewall messages. If the first command says the file does
not exist, report that along with the supervisor output; do not attach the
profile or private volume. If using DSM's container terminal instead of SSH,
open the **gateway** container, start `/bin/sh` and run
`tail -n 100 /vpn/connection.log` inside it.

If OpenVPN's log includes **Initialization Sequence Completed** but the app
still shows a failure, test the same tunnel-bound Internet check that the app
requires before permitting downloads:

```sh
sudo docker exec transmission-vpn-test-gateway-1 ip -4 address show dev tun0
sudo docker exec transmission-vpn-test-gateway-1 curl -4 --interface tun0 --fail --show-error --silent --max-time 5 https://api.ipify.org
```

Report the curl error/exit code, or that it returned an IPv4 address. A running
tunnel alone is insufficient to authorize torrent traffic. Keep the existing
verification and packet guard enabled while diagnosing it. Redact endpoint/exit
addresses, hostnames and certificate identities before sharing log output;
preserve originals privately. No image update is required to collect these logs.

### DNS lookup times out after OpenVPN connects

The reported DS124 log reaches **Initialization Sequence Completed** and creates
an IPv4 tunnel, but the verification curl fails with **Resolving timed out**.
Its default resolver is Docker's `127.0.0.11`, while a direct query to `1.1.1.1`
successfully resolves the verification hostname:

```sh
sudo docker exec transmission-vpn-test-gateway-1 cat /etc/resolv.conf
sudo docker exec transmission-vpn-test-gateway-1 nslookup api.ipify.org 1.1.1.1
```

This identifies a failure in the default DNS lookup path. It does not yet prove
HTTPS/Internet access through the tunnel. If needed, repeat the tunnel-bound
curl with `--resolve api.ipify.org:443:<one-current-A-record-from-nslookup>` to
bypass DNS for that one diagnostic request. Keep HTTPS certificate verification
enabled and use a freshly returned address, not a permanent pinned IP.

Current `compose.yaml` sets external DNS upstreams on **gateway**. For the
existing project, add this property **inside its existing gateway service** in
DSM's **YAML Configurations**, at the same indentation level as `networks`:

```yaml
    dns:
      - 1.1.1.1
      - 9.9.9.9
```

Save the YAML and recreate the complete project's containers with the same
project name, preserving its named volumes, profiles, account and downloads.
A restart alone does not change an existing container's DNS configuration.
This DNS-only change does not require rebuilding the image. For all code fixes,
apply the updated source bundle, ensure DSM uses the included Compose YAML,
then build and recreate all three containers as described in section 1.

The defaults can be overridden with `VPN_DNS_PRIMARY` and `VPN_DNS_SECONDARY`.
Choose upstreams reachable before and after connecting. `/etc/resolv.conf` can
still contain `127.0.0.11`: Docker keeps its embedded resolver for service-name
discovery and changes the external upstreams. See Docker's
[DNS networking documentation](https://docs.docker.com/engine/network/#dns-services)
and [Compose DNS setting](https://docs.docker.com/reference/compose-file/services/#dns).

After recreation, repeat the **original curl without `--resolve`** and check the
web connection status. It must return an IPv4 address through `tun0`, and the
app must verify it before authorizing downloads. Then run the torrent peer-IP
and outage tests; a successful gateway probe alone does not complete acceptance.

### IPv6 route errors or broken-pipe traces in these logs

The supplied Nyr server pushes `redirect-gateway def1 ipv6 bypass-dhcp`,
`tun-ipv6` and `ifconfig-ipv6`. Earlier builds filtered the IPv6 address but left
the mixed redirect in place, causing duplicate-redirect warnings and attempts
to install IPv6 routes on an IPv4-only tunnel. Current builds filter pushed
redirects and IPv6 settings while installing their own IPv4 full-tunnel route.
IPv4 addressing and `route-gateway` are still accepted. These filters are also
enforced when starting an already-saved profile, without re-uploading it.

The **IPv6 is disabled on nexthop device** messages do not prove that OpenVPN
failed: the supplied log proceeds to **Initialization Sequence Completed**.
Diagnose the tunnel Internet check separately. The **BrokenPipeError** traces
in the gateway log show clients closing before the HTTP reply was written;
current builds handle these disconnects without retrying a response or
misreporting a VPN startup failure. Verification failures now log fixed failure
stages and curl exit codes, without raw profile values or exception messages.

## 2. Run the tests

Record the time and result of each row. Keep the NAS's ordinary Internet access
and DSM connection working during the outage test so a direct fallback would be
possible. Zero speeds in the UI alone are insufficient evidence.

| Test | Action and expected result |
| --- | --- |
| Before VPN | Attempt to add a download. It must be refused; diagnostics below show `waiting_for_vpn`, `pid: null`, no daemon and a closed RPC port. |
| Connected | In **Connection & storage**, upload the real profile, select/create a folder, and **Save & connect**. Verify a VPN exit IP, a successful torrent download to that NAS folder, and pause/resume. The IP-check service must report the VPN IP, never the NAS's public ISP IP. Test seeding and UDP trackers/DHT if the service supports them. |
| Explicit off | With a download/seeding session active, click **Disconnect**. Existing activity must stop; the list shows **Waiting for VPN**, rates become zero and new/resumed downloads are refused. After shutdown, diagnostics must show no daemon/RPC. Reconnect and verify saved state returns. |
| Unexpected outage | While transferring, temporarily block **all configured VPN endpoint IPs/ports for this NAS** at the router, or stop the VPN service on a server you control. Keep the interruption for at least 60 seconds. Transmission must stop after verification/permission expires, with no direct peer traffic or ISP IP observed. Confirm the web container still has direct Internet access and run the direct-network check below during the block. |
| Recovery | Remove the endpoint block. Allow up to two minutes for retries/provider negotiation; verify reconnection, the VPN peer IP and resumed transfers. Collect logs if recovery fails. |
| VPN process crash | During a transfer, run the command below to kill only OpenVPN inside the gateway. The packet guard must block direct fallback while the supervisor detects the loss and automatically reconnects. Observe fresh peer/tracker traffic or an appropriately filtered external capture; a cached torrent-IP result alone cannot rule out a brief leak. |
| Offline project restart | With the endpoint still unavailable, restart the complete project. The UI should load, but Transmission must remain absent and downloads blocked. Restore the endpoint and verify automatic recovery. |
| Project restart | Restart the complete project in DSM. An enabled connection should reconnect; a deliberately disconnected connection should stay off with no daemon. Account, destination, torrent state and downloaded files must survive. |

For the OpenVPN process-crash test, this command targets only the OpenVPN process
in the project's gateway container, not the NAS host or the remote server:

```sh
sudo docker exec transmission-vpn-test-gateway-1 killall -KILL openvpn
```

Without renewal, VPN permission expires after 12 seconds; supervision polls every
250 ms and allows five seconds for graceful daemon exit before killing it.
The direct-network firewall must block torrent traffic throughout that interval.
Recreate/restart the complete project together when required; avoid recreating
only the gateway during an update because the private router address may change.

## 3. Administrator diagnostics

The first block needs administrator SSH access but no Docker Compose or project
directory. Use the actual container name if the DSM project has a different
name. Run it before connecting, while connected, after disconnecting and at least
30 seconds into the unexpected outage. It independently checks actual daemon
processes and the RPC socket, alongside the supervisor's own report:

```sh
sudo docker exec -i transmission-vpn-test-transmission-1 python3 - <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
print('Collected at:', datetime.now(timezone.utc).isoformat())
print(json.loads(Path('/run/transmission-vpn/supervisor.json').read_text()))
daemons = []
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        if path.read_bytes().split(b'\0')[0].rsplit(b'/', 1)[-1] == b'transmission-daemon':
            daemons.append(path.parent.name)
    except OSError:
        pass
print('Transmission PIDs:', daemons)
with socket.socket() as connection:
    connection.settimeout(2)
    print('RPC listening:', connection.connect_ex(('127.0.0.1', 9091)) == 0)
print('IPv6 disabled (all/default):', [Path('/proc/sys/net/ipv6/conf', name, 'disable_ipv6').read_text().strip() for name in ('all', 'default')])
PY
```

Connected: expect `state: running`, a daemon PID and `RPC listening: True`.
Disconnected or after outage shutdown: expect `state: waiting_for_vpn`,
`pid: null`, `Transmission PIDs: []` and `RPC listening: False`.
Both IPv6 flags should be `1` in every state.

Check direct-network blocking against the web container's local Docker address.
The gateway route must use its control interface (its name may vary), its root
control request must succeed, and
the torrent UID's request must fail/time out. If the route differs or the control
fails too, the result is inconclusive. This advanced block uses Docker Compose
v2; first change to the actual project directory containing the deployed YAML
(for example `/volume1/docker/TransmissionVPN-PortableUpdate`). Repeat in each
VPN state:

```sh
TEST_WEB_ID=$(sudo docker compose -p transmission-vpn-test ps -q web)
TEST_WEB_IP=$(sudo docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TEST_WEB_ID")
sudo docker compose -p transmission-vpn-test exec -T gateway ip -4 route get "$TEST_WEB_IP"
sudo docker compose -p transmission-vpn-test exec -T gateway curl --noproxy '*' -fsS --max-time 5 "http://$TEST_WEB_IP:8080/api/session"
sudo docker compose -p transmission-vpn-test exec -T transmission python3 -c 'import os,sys; from app.common import storage_ids; u,g=storage_ids(); os.setgroups([]); os.setgid(g); os.setuid(u); os.execvp("curl", ["curl", "--noproxy", "*", "-fsS", "--max-time", "5", sys.argv[1]])' "http://$TEST_WEB_IP:8080/api/session"
```

## 4. Collect logs and report

In DSM, save the project build/start output, each container's **Details → Log**,
and screenshots of app status plus Container Manager CPU/memory statistics.
OpenVPN/Xray output is stored separately in `/vpn/connection.log`; it is not in
the gateway container's ordinary log stream.

Run immediately after a failure or test phase. Each run creates a separate folder
under `private/`, which is excluded from Git and the Docker build context:

```sh
umask 077
TEST_LOG_DIR="private/nas-test-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$TEST_LOG_DIR"
chmod 700 "$TEST_LOG_DIR"
date -Iseconds > "$TEST_LOG_DIR/collected-at.txt"
sudo docker version > "$TEST_LOG_DIR/docker-version.txt" 2>&1
sudo docker compose version > "$TEST_LOG_DIR/compose-version.txt" 2>&1
sudo docker compose -p transmission-vpn-test ps -a > "$TEST_LOG_DIR/containers.txt" 2>&1
sudo docker compose -p transmission-vpn-test logs --no-color --timestamps --since 30m > "$TEST_LOG_DIR/containers.log" 2>&1
sudo docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} health={{json .State.Health}}' transmission-vpn-test-gateway-1 > "$TEST_LOG_DIR/gateway-health.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T gateway tail -n 200 /vpn/connection.log > "$TEST_LOG_DIR/vpn.log" 2>&1
sudo docker compose -p transmission-vpn-test exec -T gateway iptables-save -c > "$TEST_LOG_DIR/firewall.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T gateway iptables-legacy-save -c > "$TEST_LOG_DIR/firewall-legacy.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T transmission ip -4 route > "$TEST_LOG_DIR/torrent-routes.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T transmission iptables-save -c > "$TEST_LOG_DIR/torrent-firewall.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T transmission iptables-legacy-save -c > "$TEST_LOG_DIR/torrent-firewall-legacy.txt" 2>&1
sudo docker compose -p transmission-vpn-test exec -T transmission cat /run/transmission-vpn/supervisor.json > "$TEST_LOG_DIR/supervisor.json" 2>&1
```

Log options are documented in [Docker Compose logs](https://docs.docker.com/reference/cli/docker/compose/logs/).
If a container has exited, preserve its ordinary logs and note which `exec`
commands failed. Capture separate diagnostic snapshots during each test phase.

Share the version/model details, test timestamps/time zone, protocol/transport,
pass/fail per row and sanitized logs. Redact setup codes, credentials, endpoint
and exit IPs/hostnames, certificate identities, torrent names and personal paths
as appropriate. Never attach profiles, private keys, `/control` contents,
Transmission settings or volume/container exports. Preserve originals privately.

After testing, remove any temporary endpoint block and stop the test project.
Keep its named volumes and downloaded files until results are reviewed; avoid
DSM **Clean/Delete data** and `docker compose down -v` if that state is needed.
