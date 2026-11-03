# DS124 and Intel NAS compatibility

The default deployment now uses the same image and Compose file on Linux ARM64
and amd64/x86-64, including Realtek RTD1619B and Intel Celeron. It requires
Container Manager/Docker, TUN, network administration during setup, and standard
IPv4 forwarding/conntrack/NAT support. CPU architecture alone is not a guarantee
that every DSM kernel or VPN provider will pass the acceptance test.

The reported DS124 has RTD1619B, 1 GB RAM, DSM 7.4.1-90080 Update 1 and kernel
`5.10.55+`. The earlier shared-namespace build failed because its owner match was
missing. **The portable build does not use `xt_owner`; no custom module is needed.**
The earlier experimental module package is superseded. If already loaded, it is
unused by this version and need not be unloaded to test; its manual load lasts
only until reboot. No module loader or boot task is part of the current package.

## Update the existing NAS project

1. Stop the complete `transmission-vpn-test` project in Container Manager.
2. Extract `TransmissionVPN-PortableUpdate.zip` into the existing project folder,
   `/volume1/docker/transmission_vpn_synology` in the reported deployment.
   Keep `.env`, Docker volumes and downloads.
3. Replace Container Manager's saved YAML with the updated `compose.yaml` if
   necessary. Transmission must have its own `torrent` network. The old
   `network_mode: service:gateway` line must be absent. Gateway
   `net.ipv4.ip_forward` must start at `"0"`; the agent enables its protected
   links only after installing the guard.
4. Build the image, then recreate/start **all three services**, preserving their
   named volumes and downloads. This changes the network layout; replacing only
   the image is insufficient.
5. Confirm the gateway logs `(routed isolation; no owner match)` and Transmission
   logs `isolated routing ready ... NET_ADMIN dropped`. All services should be
   healthy before a VPN is configured. Finish HTTPS/DSM portal setup afterward.
6. Run the [NAS acceptance test](nas-test.md), including peer IP, explicit off,
   unexpected endpoint outage while ordinary Internet still works, recovery and
   a whole-project restart. Repeat on the Intel NAS and for each VPN protocol.

No SSH kernel-module installation is required. First installation and later
ordinary user operation remain in DSM and the container web UI. SSH commands in
the test guide are administrator diagnostics when validation fails.

On the 1 GB DS124, record CPU/memory during startup and transfers. The limits are
ceilings, not measured usage; memory pressure must be diagnosed separately from
routing compatibility. If startup fails, collect ordinary logs and health output:

```sh
sudo docker logs --timestamps --tail 100 transmission-vpn-test-gateway-1 2>&1
sudo docker logs --timestamps --tail 100 transmission-vpn-test-transmission-1 2>&1
sudo docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} health={{json .State.Health}}' transmission-vpn-test-gateway-1
sudo docker stats --no-stream
```

Automated validation runs on a local amd64 Docker host, using real packet rules
while deliberately rejecting owner matches. Real ARM64 DSM behavior and live
OpenVPN/Xray outage tests remain to be confirmed on the NAS hardware.
