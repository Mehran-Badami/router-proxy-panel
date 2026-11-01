# Manage sites from the panel

The Sites section contains editable starter groups for YouTube, Telegram,
WhatsApp, Instagram, X, Clubhouse and Spotify. Google Assistant and Google Home
are separate, initially disabled groups. These lists are starting points, not
exhaustive service inventories. Direct-IP traffic, voice/media endpoints, IPv6,
shared CDNs and client-side private DNS can require additional policy.

Add a custom group, give it a name and enter one bare domain per line. Choose
whether to include subdomains. Save, then Apply. Disabling or deleting a group
takes effect on the router only after Apply. Duplicate domains are combined;
if another enabled group still uses a domain, it remains selected.

## One-time router integration

First complete [RouterOS setup](ROUTEROS.md): a working tunnel, the named DNS
forwarder `RPP Secure DNS`, address list `rpp-sites`, connection/routing marks,
and an active default route in table `rpp-proxy`. LAN clients must use the router
resolver. Scope the routing rules to LAN clients, exclude local/container
destinations and configure firewall/IPv6 policy. FastTrack rules must select
`connection-mark=no-mark`; review the effect on other marked connections first.
This feature updates site selection, not the initial tunnel or firewall setup.

Enable RouterOS HTTPS REST (`www-ssl`) with a certificate whose name/IP matches
the configured URL. Restrict access to the panel container's address. Use a
dedicated RouterOS account with `read,write,rest-api`; these permissions are
broader than DNS-only, because RouterOS does not provide per-record REST ACLs.
Do not expose REST to WAN. Follow the [official REST documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%2BAPI).

Set these container environment variables privately:

| Variable | Meaning |
|---|---|
| `ROUTEROS_URL` | HTTPS origin, e.g. `https://router.example` (no `/rest` suffix) |
| `ROUTEROS_USER` | Dedicated router account |
| `ROUTEROS_PASSWORD_FILE` | Path to a mounted private password file, readable by UID 10001 |
| `ROUTEROS_CA_FILE` | Optional mounted PEM CA certificate for a private CA |

Certificate verification is mandatory. Redirects are not followed. Credentials
are not returned to the browser. Keep password files and `/data` out of source,
images, releases and issue reports. Restart the container after configuration.

## Apply and recovery semantics

- Only DNS static records with comments starting `RPP sites: ` are owned by this
  feature. Reserve that prefix; do not use it for unrelated records.
- The panel checks basic routing prerequisites and rejects overlapping unmanaged
  DNS records or active regex rules before writing. It does not prove all routing
  or firewall rules are correct.
- Records use `type=FWD`, `address-list=rpp-sites`, the named forwarder and the
  chosen subdomain behavior. See [RouterOS DNS](https://manual.mikrotik.com/docs/network-management/dns/).
- Apply reconciles additions, edits and removals, then verifies a readback. It is
  not a transaction. If a network error occurs, partial changes may remain and
  the UI does not report success. Retry converges; Rollback restores the owned
  DNS records saved before the last apply attempt. A failed retry preserves that
  original snapshot. Do not edit these owned records concurrently elsewhere.
- Rollback preserves the edited panel list as a draft; it does not undo unrelated
  DNS/firewall settings. The private snapshot persists across container restarts.
- Existing connections and cached addresses may continue using their previous
  route until expiry/reconnection. No global connection or DNS-cache flush is
  performed. Test real client behavior after changes.

The unit suite uses a simulated RouterOS REST backend. Container tests cover
authenticated save, persistence and unconfigured apply rejection. Hardware and
real-router routing validation remain required before production deployment.
