# One-container IPv4 gateway

This source branch adds an optional native Xray TUN gateway. The panel, Xray and
forwarded application traffic run in one container; tun2socks is not needed.
Older published tags do not include this feature. Build from this branch until
a release explicitly includes it. Keep a private backup and the previous image.

## What changes

```text
Selected client IPv4 traffic -> RouterOS policy route -> panel container TUN -> VPN
Router DNS -> same container TCP relay -> VPN -> verified public DoH
Panel and VPN server bootstrap -> container's normal route
```

Only forwarded packets from explicitly listed client networks enter the TUN.
Container-originated connections keep their ordinary route, avoiding a VPN
bootstrap loop. Private/LAN destinations bypass the TUN policy table. This is
IPv4 only; IPv6 needs an explicit separate policy. RouterOS still chooses which
destinations go to the container using the site's DNS address list.

Turning the panel's VPN toggle off sends application traffic through Xray's
direct outbound. Secure DNS retains its VPN outbound and existing RouterOS
fallback policy. Selecting a server or restarting Xray preserves the open TUN
device. Restarting the container recreates it.

## RouterOS setup

First prepare the network, firewall, writable data mount and subscription as
described in [ROUTEROS.md](ROUTEROS.md). The addresses below are examples, not
values to copy over an existing installation:

- Router container bridge: `10.77.0.1/24`.
- Panel/gateway veth: `rpp-panel`, address `10.77.0.2/24`.
- Client LAN: `10.20.0.0/24`.

Build and upload a clean ARM64 image using the deployment guide. Before its
first start, add these variables to its environment list:

```routeros
/container envs add list=RPP key=RPP_GATEWAY_MODE value=tun
/container envs add list=RPP key=RPP_GATEWAY_INTERFACE value=rpp-panel
/container envs add list=RPP key=RPP_LAN_CIDRS value="10.20.0.0/24"
/container set [find where name="rpp-panel"] user=0:0
```

RouterOS retains the veth name inside the container: use that exact name rather
than assuming `eth0`. The image must use its default `python /app/entrypoint.py`
entrypoint. A previous override to `manager.py` would skip TUN initialization.

Root is needed only at startup to create `/dev/net/tun`, configure routes and
initialize data-directory ownership. Before starting the panel and Xray, the
entrypoint permanently drops to UID/GID 10001, removes supplementary groups and
sets `no_new_privs`. Both long-running processes have no effective capabilities.
Existing files in `/data` must already be writable by UID 10001; the helper does
not recursively change file ownership. Unsupported kernels or conflicting
network settings cause startup to fail instead of silently routing incorrectly.

After verifying the panel and selected server, set the **selected-sites routing
table** default gateway to `10.77.0.2`. Do not change the router's main default
route. Preserve exclusions for router-local/container destinations, return-path
firewall rules, MSS settings and FastTrack exclusions in both directions. Do not
masquerade client traffic on its way into the container: the TUN policy must see
the client source subnet. Internet-facing NAT remains part of router setup.

The panel's HTTPS RouterOS integration and private data mount do not change.
Existing groups, private subscriptions and site selections stay in `/data`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `RPP_GATEWAY_MODE` | `off` | `tun` enables the native gateway |
| `RPP_GATEWAY_INTERFACE` | `eth0` | Actual incoming container interface; RouterOS uses its veth name |
| `RPP_LAN_CIDRS` | Required in TUN mode | Comma-separated IPv4 client subnets; no default route |
| `RPP_TUN_NAME` | `rpp0` | Unused TUN interface name |
| `RPP_TUN_MTU` | `1500` | TUN MTU; separate from router MSS clamping |

Table 1001 and rule priority 11000 are reserved **inside the container namespace**.
Do not use host networking or a shared namespace containing those rules. Linux
Docker requires access to `/dev/net/tun` and startup capabilities `NET_ADMIN`,
`SETUID`, `SETGID`, `CHOWN`, `FOWNER`, `DAC_OVERRIDE`; the ordinary Compose quick
start deliberately keeps TUN disabled. RouterOS capability handling differs.

## Migration and rollback

1. Save a router backup/export and a private copy of the complete `/data` volume,
   including private site groups, access key, subscription state and HTTPS trust.
2. Test the new image on an isolated veth and a copy of the data. Keep router
   write credentials out of the test copy. Verify actual TCP/HTTPS and UDP traffic.
3. Stop the old panel before starting the replacement on its IP and data mount.
   Never let two managers write the same data concurrently.
4. Verify the replacement, then change only the selected-sites gateway from the
   previous gateway to the panel IP. Existing connections may need to reconnect.
5. Test client video, messaging, DNS and ordinary sites. Stop the old gateway only
   after these succeed; retain its configuration and image until stability is clear.

To roll back, stop the replacement, restart the previous panel on its original
mount and restore the selected-sites route to the previous gateway. Start that
gateway if it was stopped. Do not erase the shared data or restore an old domain
list over edits made since the backup.

## Validation

The local test needs a Linux Docker engine and disposable TLS certificates:

```sh
python -m pip install cryptography
docker build -t router-proxy-panel:native .
python tools/native_tun_smoke.py --image router-proxy-panel:native
```

It creates isolated disposable client, gateway and TLS server containers. It
verifies routed HTTP/HTTPS body hashes, UDP datagrams, unprivileged services,
probe isolation, Xray recovery, the VPN toggle and full container restart. It
uses no real subscription. See [VALIDATION.md](VALIDATION.md) for hardware results
and limitations. Fewer containers alone do not establish lower CPU use or faster
streaming; compare the same server and workload before making performance claims.
