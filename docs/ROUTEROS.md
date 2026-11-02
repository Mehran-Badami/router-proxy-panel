# RouterOS deployment guide

This is a reviewed recipe, not a universal installer. Do not paste the entire
document into a production router. Keep a private export/backup and use Safe Mode
for routing/firewall work. This public release has not been installed on your router.

## 1. Prerequisites

- RouterOS v7 with the container package, supported ARM64 or x86-64 hardware,
  adequate RAM and external storage. This project's image targets ARM64/AMD64.
- Enable container device mode using MikroTik's documented physical confirmation.
- Correct router time and a trusted CA store for certificate-verified HTTPS.
- An unused container subnet. The example below uses `10.77.0.0/24` purely as an
  example; replace it and all storage/interface names for your own network.
- Read the [official container guide](https://manual.mikrotik.com/docs/containers/).
  Minor releases differ in `envlist`/`envlists` and mount syntax; check CLI completion.

## 2. Isolated panel network

Example, after checking for conflicts:

```routeros
/interface bridge add name=rpp-containers
/ip address add address=10.77.0.1/24 interface=rpp-containers
/interface veth add name=rpp-panel address=10.77.0.2/24 gateway=10.77.0.1
/interface bridge port add bridge=rpp-containers interface=rpp-panel
/ip firewall nat add chain=srcnat src-address=10.77.0.0/24 out-interface-list=WAN action=masquerade comment="RPP container egress"
/container envs add list=RPP key=PUBLIC_ORIGIN value="http://10.77.0.2:8080"
/container envs add list=RPP key=ALLOW_SYSTEM_BOOTSTRAP value="true"
/container mounts add list=RPP_DATA src=disk1/rpp-data dst=/data
```

Restrict forwarding to `10.77.0.2:8080` to your management LAN/VPN. Permit SOCKS
TCP/UDP 1080 only from your intended gateway/clients, and DoH TCP 8443 only from
the router or explicitly trusted clients. Put these rules before general drop
rules and verify existing accepts cannot bypass the restrictions. The container
bridge should not be added to a broadly trusted interface list blindly.

Do not enable bridge-wide firewall processing merely for this application;
containers sharing one bridge can communicate without crossing routed rules.
Only place trusted containers on this subnet.

## 3. Install image and persist state

For a local ARM64 build/export on a Docker workstation:

```sh
docker buildx build --platform linux/arm64 --load -t router-proxy-panel:arm64 .
docker save -o router-proxy-panel-arm64.tar router-proxy-panel:arm64
```

Upload this clean image tar to external storage. Never publish a tar created by
exporting your running container: that can include private runtime data.

```routeros
/container add file=disk1/router-proxy-panel-arm64.tar interface=rpp-panel root-dir=disk1/rpp-root mountlists=RPP_DATA envlists=RPP name=rpp-panel start-on-boot=yes logging=yes
```

Alternatively pull the versioned public GHCR image using your registry settings.
Do not overwrite global registry settings without considering other containers.
Configure a reachable ordinary DNS server for container bootstrap if RouterOS has
no static/dynamic DNS server; see the container `dns` option.

The image runs as UID/GID `10001`. The mounted data directory must be writable by
that identity. If a newly created RouterOS mount is root-owned, provision ownership
before production startup: temporarily run this container as root with the entrypoint
`/bin/sh` and command `-c "chown 10001:10001 /data && chmod 700 /data"`, wait for it
to exit, then restore `user=10001:10001`, `entrypoint="python /app/manager.py"` and
empty `cmd`. Use `entrypoint="python /app/entrypoint.py"` for builds from this branch.
Do not leave the service running as root to work around permissions. Native TUN
mode has its own startup and privilege-drop procedure in [NATIVE_TUN.md](NATIVE_TUN.md).

Start the panel; enter its shell and run `python /app/manager.py --print-token`.
Use the resulting private key at `http://10.77.0.2:8080/`. Import your own
subscription and select a tested server. Nothing in this repository supplies one.

## 4. DNS-over-HTTPS through the selected VPN

Only continue after a working outbound is selected. The panel's TCP port 8443
passes TLS through the VPN to Google; RouterOS remains the TLS client and checks
Google's certificate. No substitute CA or certificate bypass is needed.

From your workstation generate scripts **outside this repository**:

```sh
python tools/render_routeros.py --panel-ip 10.77.0.2 --output ../my-router-config
```

Review `enable-dns.rsc`, save original DNS/NAT settings privately, and import it.
It creates one OUTPUT NAT mapping to the relay, a named `RPP Secure DNS` forwarder,
and sets the global DoH endpoint. It does not intercept application-owned DoH/DoT.
Existing FWD rules still have their original destinations; migrate intended rules
to `RPP Secure DNS` manually, preserving `address-list` attributes.

If LAN clients should use the router resolver, enable `allow-remote-requests` only
with input firewall restrictions for your LAN/VPN, and advertise that resolver in
DHCP. Do not expose an open resolver on WAN. DNS interception is optional and not
automatically installed.

## 5. Optional continuity fallback

This explicitly permits ordinary, unencrypted DNS during an outage. Choose
resolvers reachable on your own connection; the example is not a recommendation
for any particular ISP:

```sh
python tools/render_routeros.py --panel-ip 10.77.0.2 --fallback-dns 9.9.9.9 149.112.112.112 --output ../my-router-config
```

Generate either strict or fallback scripts for a fresh integration, not both.
The watchdog probes verified HTTPS to Google's IP through the relay independently
of the current DNS mode. After continuous failure for at least 60 seconds it
switches DNS to the specified resolvers; after at least 30 seconds of health it
restores DoH. Detection also depends on the 30-second probe interval and timeout.
Ordinary DNS can be poisoned; devices may cache those answers until their TTL
expires even after recovery. Reopen affected applications if necessary.

Test on a lab router: disable the relay, confirm fallback, re-enable it and confirm
recovery. Observe logs and real client resolution; an `up` status alone is insufficient.
The generated `rollback-dns.rsc` stops automation and disables its NAT rule;
restore your own original DNS settings and any changed FWD rules from backup.

## 6. Selective whole-network traffic

For a new build from this branch, [native TUN mode](NATIVE_TUN.md) provides the
gateway inside the panel container at `10.77.0.2`. It does not need tun2socks.
The separate-gateway instructions below remain available for older images and
existing installations. Choose one gateway, then point the policy route at it.

Use the official [tun2socks](https://github.com/xjasonlyu/tun2socks) image/release,
for example the pinned `v2.7.0` release, in a second container (`10.77.0.3` here).
Its `PROXY` is `socks5://10.77.0.2:1080`. Follow the upstream
[gateway examples](https://github.com/xjasonlyu/tun2socks/wiki/Examples) and
[Docker entrypoint](https://github.com/xjasonlyu/tun2socks/blob/main/docker/entrypoint.sh).
Configure TUN support, forwarding, routes and reverse-path filtering for your
RouterOS/kernel combination. Verify return traffic before enabling policy routing.

In RouterOS, the design is:

1. Create a FIB table `rpp-proxy` with default gateway `10.77.0.2` for native TUN,
   or `10.77.0.3` for the separate gateway.
2. Use selected DNS FWD domains with `address-list=rpp-sites`,
   `forward-to="RPP Secure DNS"` and `match-subdomain=yes`.
3. In LAN prerouting, mark new connections to `rpp-sites`; mark their routing
   table `rpp-proxy`. Exclude router-local and container-network destinations.
4. Exclude these marked connections from FastTrack in **both directions** and
   permit the return path through the gateway before drop rules.
5. Handle UDP/QUIC and IPv6 deliberately. An IPv4-only policy does not cover IPv6.
6. Validate DNS, messaging, media and ordinary sites from real clients.

Example service suffixes: `youtube.com`, `googlevideo.com`, `ytimg.com`,
`youtubei.googleapis.com`, `whatsapp.com`, `whatsapp.net`, `telegram.org`,
`t.me`, `instagram.com`, `cdninstagram.com`, `spotify.com`, `scdn.co`.
This is not an exhaustive or permanently correct domain list. Telegram and other
apps can use direct IPs. Shared CDN IPs prevent perfect domain isolation.

Do not globally route `google.com` or `googleapis.com` unless that is your policy.
DNS encryption and selective traffic routing solve different problems.

## 7. Upgrade / remove

Once routing works, [connect the panel to RouterOS](SITES.md) to manage selected
domains through the Sites section instead of manually editing DNS records.

Keep a private backup of `/data` and the old image tag. Stop the old container,
replace only the application image, and remount the same volume. Validate login,
selected server and DNS before considering the upgrade complete. Roll back the
image if validation fails; do not discard the data directory.

Before removal, disable the watchdog, restore DNS and disable application-specific
policy-routing rules. Then stop containers. Remove only objects you explicitly
created for this deployment. This guide deliberately does not provide a recursive
storage deletion command.
