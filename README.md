# Transmission: private downloads, managed in your browser

A Synology Container Manager project with one web interface for setup and daily use.
Users do not edit configuration files or use a terminal.

From the app, users can:

- Choose **OpenVPN** or **Xray** and upload their client profile.
- Supply VPN credentials and supporting OpenVPN certificates when needed.
- Browse available NAS storage, create a folder, and select a download destination.
- Connect/disconnect and see the VPN exit IP.
- Upload `.torrent` files or paste magnet links; view, pause, resume and remove downloads.

The web interface stays available while the VPN is disconnected. Profiles and
credentials are stored in private Docker volumes, outside the Git checkout and
image. All three internal services use the same Alpine-based image.

**Transmission starts only after the VPN is verified.** Disconnecting closes the
torrent traffic gate before the VPN is stopped and shuts down Transmission.
A permanent firewall also blocks the torrent identity from sending traffic over
the ordinary network interface, including during a VPN failure or restart.

## For the DSM administrator: install once

The same image and Compose project target **Linux ARM64 and x86-64/amd64**,
including Realtek ARM NAS models and Intel Celeron NAS models. You need Container
Manager/Docker, a working `/dev/net/tun`, NET_ADMIN for VPN/routing setup, and
standard IPv4 iptables forwarding, conntrack and NAT support. The image tries
nftables, then legacy iptables if preparation fails. Unsupported hosts fail closed.

**No `xt_owner` match or model-specific kernel module is required.** Transmission
has its own namespace and routes through the VPN gateway. Its supervisor installs
its local restrictions, then permanently drops NET_ADMIN and NET_RAW before launching the
non-root daemon. The gateway forwards torrent traffic only through a verified
`tun0`; it never permits a direct-network fallback. Docker DNS and direct bridge
access are blocked in the torrent namespace.

ARM64 image support does not establish compatibility with every DSM/kernel or
VPN provider. Run the [NAS acceptance test](docs/nas-test.md) on each NAS; the
[DS124 notes](docs/ds124-compatibility.md) describe migration from the earlier build.

1. Use **File Station** to put this repository in a dedicated project directory,
   for example `docker/transmission-vpn`. Keep `Dockerfile`, `compose.yaml`, `app/`
   and `transmission/` together. Create an empty `downloads` folder there if DSM
   does not create the bind-mount directory automatically.
2. Open **Container Manager → Project → Create**. Select that project directory
   and upload/select the included `compose.yaml` as the Compose source. On
   **Web portal settings**, leave **Set up web portal via Web Station** unchecked,
   click **Next** and finish the wizard with project startup enabled. Build/start
   the project before configuring its portal. The build downloads public base
   images and packages; it does not need VPN credentials.
3. Make the app available through the project's **Web Station web portal**, using
   the **web** service and container port **8080**. Alternatively, configure a DSM
   reverse proxy hostname pointing at `http://127.0.0.1:8080`. Use HTTPS for the
   user-facing portal because users enter passwords and upload private profiles.
   The portal launches the app in a browser. App login is independent of DSM
   single sign-on. An optional DSM menu launcher is described below.
4. In **Container Manager → Container → this project's web container → Details →
   Log**, copy the value after **First-time setup code**. Open the app through the
   portal, enter that code, and create an app password of at least 12 characters.
   This one-time code prevents another LAN visitor from claiming an unconfigured
   installation. It is accepted only during first account creation; later
   sign-ins use the app password. If DSM shows no logs, see the
   [setup-code fallback](docs/nas-test.md#first-time-setup-code-and-empty-dsm-logs).
5. Give the user the portal link and app password. Everything else is done in
   the browser.

DSM labels vary with the version. Synology documents
[project creation and web portals](https://kb.synology.com/en-global/DSM/help/ContainerManager/docker_project?version=7)
and [running a web app through Container Manager](https://kb.synology.com/en-eu/insights/Use_Container_Manager_to_run_web_app).

No `.env` file is required. Defaults publish the web interface on NAS port 8080
and mount the project's dedicated `downloads` folder. If the port is occupied,
change the host port in the Compose editor. `.env.example` lists optional installer
settings. With an HTTPS-only portal, set `SECURE_COOKIES=true`; keep it false if
accessing the app directly over HTTP during a trusted local installation.

The gateway uses public external DNS upstreams (`1.1.1.1` and `9.9.9.9` by
default), configurable with `VPN_DNS_PRIMARY` and `VPN_DNS_SECONDARY`. A NAS/LAN
resolver may become unreachable after the VPN installs its default route.
Docker's internal service-name lookup remains available. See the
[DNS troubleshooting steps](docs/nas-test.md#dns-lookup-times-out-after-openvpn-connects)
if OpenVPN connects but the app cannot verify Internet access.

Do not publish the gateway agent or Transmission RPC ports. Only the web service
has a host port. Keep the portal on a trusted LAN/private remote-access network.

### Optional DSM menu icon

For a direct **Transmission VPN** icon in DSM's main menu, manually install
`dist/TransmissionVPN-Launcher.spk` through **Package Center → Manual Install**.
This small launcher runs as an unprivileged package user and opens the installed
web app on the same NAS, port 8080. It adds no daemon and never changes the
Container Manager project, downloads or private data, including on uninstall.
An administrator may make its icon available to the intended DSM users.

The archive structure and metadata are tested; actual installation/menu behavior
still needs verification on DSM. The launcher is optional: the Web Station portal
works independently. For an HTTPS portal or a different port, maintainers can
build a launcher targeting that address before handing the package to users:

```sh
python3 scripts/build_dsm_launcher.py --url https://downloads.example.com/
# Or use the same NAS hostname with a different HTTP port:
python3 scripts/build_dsm_launcher.py --port 8088
```

The provided package is a launcher rather than a Container Manager installer.
The administrator still installs the project and grants storage access once.

### Make NAS folders available

The browser can only see directories deliberately mounted into the containers;
it cannot grant itself access to arbitrary NAS shares. This is the one-time
administrator responsibility, just like other DSM containerized applications.

By default, **Available storage** in the picker is the project's `downloads`
folder. A new, empty mounted root is initialized for the app's download identity.
The user can create their own subfolders from the picker.

For an existing shared folder, change the source of **both** `/downloads` mounts
in `compose.yaml` (the web and transmission services) to the same dedicated NAS
folder, such as `/volume1/downloads/transmission`. Grant the configured download
identity read/write permissions through DSM. Existing content and its permissions
are not recursively changed by the app. The user can then browse its subfolders.

The download identity defaults to numeric user/group 1000:1000. Administrators
may set `PUID` and `PGID` to a suitable existing account/group, identically in all
three services. Neither may be zero: the daemon must run without root privileges. Restart/recreate the complete project
when changing these IDs or storage mounts. The UI checks write access as the
actual download identity before accepting a folder.

## For users: first connection

1. Open the app from the DSM portal and sign in.
2. Open **Connection & storage**. Select **OpenVPN** or **Xray**.
3. Choose the profile supplied by your VPN service:
   - **OpenVPN:** upload the standard Linux `.ovpn` client file. If it references
     separate CA/certificate/key files, open the supporting-files section and
     upload those too. Enter the VPN username/password if the service requires
     them. Profiles with inline certificates need no supporting upload.
   - **Xray:** upload a client JSON with one VLESS, VMess, Trojan or Shadowsocks
     proxy. The app imports that server and creates its own TUN listener. It
     removes desktop proxy listeners, direct outbounds and split-routing rules,
     so downloads cannot select a direct fallback. Multi-server/chained profiles,
     subscription links, and JSON with comments are not supported.
4. Click **Browse folders**, select or create a folder, then **Use this folder**.
5. Click **Save & connect**. Wait for **Connected** and a VPN exit IP.

The exit IP check uses an HTTPS request bound to the tunnel interface. It checks
Internet connectivity, not UDP tracker/DHT support or port forwarding. Your VPN
service/Xray transport must support the traffic you need. A service allowing TCP
only can connect successfully while UDP trackers/DHT fail.

Uploaded profiles are treated as data: OpenVPN scripts/plugins/route overrides
are rejected, and the app manages routes and DNS. Export a standard Linux client
profile if your provider's desktop-specific export contains unsupported options.
The app supports IPv4 TUN connections; IPv6 and TAP are disabled/unsupported.
Certificate-only OpenVPN profiles need no username/password. Interactive MFA or
private-key passphrase prompts are not supported by this unattended workflow.

Profiles and passwords are not downloadable through the web API or included in
status responses. Upload a new profile to replace a saved connection; the app
never fills an old VPN password back into the browser.

## For users: downloads

- Click **Add download**, select one or more `.torrent` files, or choose the
  **Magnet link** tab. New downloads use the selected folder.
- Use the download list to monitor progress, pause or resume. Removing a download
  from the list keeps its downloaded files.
- Change the destination under **Connection & storage**. A change applies to
  future downloads; it does not move existing files.
- Click **Disconnect** to stop the VPN and Transmission. Downloads and seeding
  stop; the last known list stays visible as **Waiting for VPN**, with zero
  transfer rates. Adding or managing downloads requires a verified connection.
- Reconnect the VPN to restart Transmission and restore its saved torrent state.

The gateway verifies the tunnel before granting a short-lived permission to run
Transmission. Lost verification, a missing tunnel, an invalid permission or a
stopped gateway causes the daemon to stop. Permissions expire after 12 seconds
without renewal; the supervisor checks every 250 ms and allows up to five seconds
for a clean daemon shutdown before killing it. The firewall continuously blocks
physical-interface torrent traffic throughout detection and shutdown. A tunnel
device left behind after a failed connection does not authorize torrent traffic.

Profiles, app account, destination and torrent state survive project restarts.
The connection reconnects automatically after a restart if it was enabled.

## Privacy, storage and limits

| Data | Location |
| --- | --- |
| Uploaded VPN configuration, keys and private connection log | Docker volume `vpn-state` (gateway only) |
| Password hash, selected destination and cached torrent list | Docker volume `web-state` (web only) |
| Internal service credential and signed VPN permission | Docker volume `service-control`, writable only by the gateway |
| Torrent settings and resume state | Docker volume `transmission-state` |
| Downloaded files | The NAS folder mounted at `/downloads` |

These volumes have the project name as a prefix. Files use restricted permissions,
but this is not encrypted storage and NAS/Docker administrators can access them.
Back up the private volumes as sensitive data. Do not delete project volumes when
updating the image. DSM's **Clean/Delete** actions may remove volumes; review the
DSM confirmation carefully. Removing containers alone does not remove downloads.

Defaults limit activity to two downloading torrents, three seeding torrents,
80 peers globally, 30 peers per torrent, and an 8 MB cache. Memory ceilings are
128 MB for the gateway, 192 MB for Transmission and 64 MB for the web service;
these are caps, not promises of actual usage. Check Container Manager Statistics
on your NAS. Logs rotate; the gateway's private connection log is bounded.
The amd64 image built during development was about 99 MB uncompressed; actual
memory consumption depends on activity and the chosen VPN transport.

For updates, stop the complete project, apply both source and Compose changes,
build the new image, then recreate/start all services together. Recreating the
whole project also refreshes its private router addresses. Keep its named volumes
and downloads. Automatic installation of the Container Manager project from Package Center
and DSM SSO integration are separate future work; the optional SPK only adds the
menu launcher.

## Validation and development

```sh
python3 -m unittest discover -s tests -v
node --check app/static/app.js
# Normal installation with a working host TUN device:
docker compose up -d --build
```

For maintainers on a host without a TUN device, the isolated smoke project uses
temporary Docker volumes. It verifies daemon absence before VPN permission,
shutdown on disconnect/permission expiry, and physical-interface blocking.
A synthetic tunnel and signed permission exercise the real daemon lifecycle
while its packet gate stays closed; this does not exercise a live VPN:

```sh
docker compose -p tvpn-smoke -f compose.yaml -f tests/compose.smoke.yaml up -d --build --wait
python3 tests/smoke.py
python3 tests/network_smoke.py
docker compose -p tvpn-smoke -f compose.yaml -f tests/compose.smoke.yaml down -v
```

To verify legacy fallback on a test kernel supporting legacy iptables, add
`-f tests/compose.legacy-smoke.yaml` to the smoke project's Compose commands and
run the same `python3 tests/smoke.py` checks. This test-only override simulates
an unavailable nftables backend; the real legacy guards must install successfully.
Both smoke variants reject any attempted owner match. `network_smoke.py` verifies
real TCP/UDP forwarding, VPN-side NAT, direct bridge/Docker-DNS blocking, capability
dropping, and an established TCP session whose route falls back to a reachable
physical destination. The simulated tunnel tests the routing guard; it does not
replace a real OpenVPN/Xray endpoint test.

`tests/demo_server.py` runs a UI-only local fixture with fake VPN/RPC services.
Neither the fixture nor test credentials are included in the image.

Before production use, test on the actual NAS with a real profile: verify the
BitTorrent peer IP using a torrent IP-check service, interrupt an established
VPN connection, and confirm no traffic uses the ISP connection. Restore the
endpoint and confirm reconnection. The automated cold-start test cannot replace
this real-endpoint outage test. See [the architecture notes](docs/gateways.md).
Follow the [real NAS test guide](docs/nas-test.md) for deployment, acceptance checks
and private log collection.
