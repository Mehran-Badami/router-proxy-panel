# Router Proxy Panel

A small, self-hosted Persian-language control panel for Xray on a trusted LAN,
with container packaging and optional MikroTik RouterOS integration.

**Early beta:** the panel and image are tested in isolation. Router recipes must
be adapted and validated on a separate lab router before production use.
No account, subscription, credentials, customer export or operational history is included.

[راهنمای فارسی](README.fa.md) · [RouterOS installation](docs/ROUTEROS.md) · [Security](SECURITY.md)

## Features

- Editable service presets and custom domain groups, with authenticated RouterOS
  DNS synchronization, readback verification and last-apply rollback.
  See [site management and one-time integration](docs/SITES.md).

- Import TLS/Reality VLESS links or verified HTTPS subscriptions into separate groups.
- Update, soft-delete and restore groups; show provider-reported quota/expiry information.
- HTTPS reachability tests, optional 2 MB download tests and manual server selection.
- Keep a healthy server; automatically try verified alternatives after repeated failures.
- TLS passthrough to Google DoH over the selected VPN, independent of the website-proxy toggle.
- Fresh per-install access key, persistent login cookie and a login form compatible with bookmarks.
- Opt-in RouterOS DNS fallback scripts with recovery hysteresis and rollback instructions.
- Optional native Xray TUN gateway: panel, VPN core and IPv4 forwarding in one
  container. See the [native gateway guide](docs/NATIVE_TUN.md).

This is not a VPN provider. A valid subscription is required. It does not install a
router rules automatically. Selective routing needs RouterOS policy routing and
either the native TUN mode in this source branch or an existing external gateway.
Native TUN is not included in the older published images shown below.

## Local Docker quick start

Public multi-architecture image (AMD64 / ARM64):

```sh
docker pull ghcr.io/mehran-badami/router-proxy-panel:v0.2.2-beta.1
docker run -d --name router-proxy-panel --restart unless-stopped \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:1080:1080 -p 127.0.0.1:8443:8443 \
  -e PUBLIC_ORIGIN=http://localhost:8080 -v router-proxy-panel-data:/data \
  ghcr.io/mehran-badami/router-proxy-panel:v0.2.2-beta.1
docker exec router-proxy-panel python /app/manager.py --print-token
```

Alternatively, build from this repository:

```sh
docker compose up -d --build
docker compose exec panel python /app/manager.py --print-token
```

Open `http://localhost:8080`, enter the locally generated access key, then bookmark
the page. Import a subscription and choose a server. The panel starts without an
outbound configured; SOCKS/DoH listeners start only after a successful selection.
The example Compose file publishes all ports on loopback only.

For LAN deployment, change `PUBLIC_ORIGIN` to the exact URL users open, publish
only to the intended interface, and restrict access with the host/router firewall.
For off-site management, use an authenticated VPN with routes and firewall rules
to the container network. Do not expose the management port to WAN.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `APP_DATA` | `/data` | Private writable state volume; UID/GID 10001 |
| `PUBLIC_ORIGIN` | `http://localhost:8080` | Exact trusted browser origin; no path |
| `BIND_ADDRESS` / `PORT` | `0.0.0.0` / `8080` | HTTP listener |
| `SOCKS_PORT` | `1080` | Unauthenticated SOCKS listener; isolate at firewall |
| `DOH_PORT` | `8443` | TCP TLS relay to the configured public DNS IP |
| `DOH_HOST` / `DOH_IP` | `dns.google` / `8.8.8.8` | Provider must support Google-compatible JSON `/resolve` for probes/bootstrap |
| `ALLOW_SYSTEM_BOOTSTRAP` | `true` | Allow ordinary DNS for a new VPN server hostname if secure bootstrap is unavailable |
| `SESSION_DAYS` | `30` | Persistent login lifetime |
| `XRAY_CORE` | `/usr/local/bin/xray` | Xray binary path |

The RouterOS script generator currently targets Google DoH defaults. Custom
providers require corresponding manual changes to the generated integration.

The selected server's bootstrap IP is cached for cold starts. DNS changes at the
provider can make a cached IP stale; import an updated subscription or refresh the
bootstrap cache with verified addresses. Strict bootstrap mode needs an initial
literal server IP or a private preseeded cache. Do not publish that cache.

## DNS and routing behavior

```text
Browser -> authenticated panel -> Xray selected outbound
Router DNS -> verified HTTPS -> local TCP relay -> selected VPN -> Google DoH
Selected LAN destinations -> separate tun2socks gateway -> Xray SOCKS
With native TUN enabled: Selected LAN destinations -> same container -> Xray TUN
```

After the one-time HTTPS integration, the panel updates its managed RouterOS DNS
rules. Initial network, firewall and routing setup remains an installation step.
Without fallback, loss of the VPN can stop uncached DNS resolution.
With explicit fallback, ordinary DNS may be manipulated and does not unblock sites.
DoH alone does not hide the SNI of a site's separate direct connection.
IP-based selective routing can include unrelated services sharing the same IP.
IPv6, QUIC/UDP, private DNS in applications and FastTrack require deliberate router policy.

Automatic monitoring performs small real HTTPS/DNS requests. A speed test runs
only when requested. An expired subscription cannot be repaired by selecting
another server in the same expired subscription.

## Development and release

Python 3.12; application and unit tests use the standard library. Runtime additionally
needs curl, iproute2 and Xray (provided in the container). The optional native TUN
integration test uses `cryptography` to generate disposable test certificates.

```sh
python -m unittest discover -s tests -v
python tools/privacy_guard.py
python tools/package_release.py
docker build -t router-proxy-panel:local .
python tests/integration/container_smoke.py --image router-proxy-panel:local
```

GitHub Actions runs tests and container smoke checks. Publishing requires a
version tag or an explicit manual publish request and uses GHCR in the repository
owner's namespace. Source archives are built from an allowlist, not from a live
working directory or container export. See [release notes](docs/RELEASING.md).

`tests/` contains regression tests for authentication, configuration, recovery,
domain updates and rollback. `tests/integration/` holds the two reusable container
checks: a clean panel install and the native gateway's real traffic/recovery path.
Temporary deployment diagnostics and real router fixtures are not source files.
The Docker build includes only `app/` and license notices; tests and developer
tools are not copied into the deployed image.

## License

MIT for this panel. Xray-core and other components retain their own licenses;
see [third-party notices](THIRD_PARTY_NOTICES.md). Independent project, not an
official MikroTik or Xray product.
