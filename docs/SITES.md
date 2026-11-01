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
dedicated RouterOS account with `read,write,api,rest-api`; these permissions are
broader than DNS-only, because RouterOS does not provide per-record REST ACLs.
Do not expose REST to WAN. Follow the [official REST documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%2BAPI).

Set these container environment variables privately:

| Variable | Meaning |
|---|---|
| `ROUTEROS_URL` | HTTPS origin, e.g. `https://router.example` (no `/rest` suffix) |
| `ROUTEROS_USER` | Dedicated router account |
| `ROUTEROS_PASSWORD_FILE` | Path to a mounted private password file, readable by UID 10001 |
| `ROUTEROS_CA_FILE` | Optional mounted PEM CA certificate for a private CA |
| `ROUTEROS_SITE_LIST` | Existing destination address list; default `rpp-sites` |
| `ROUTEROS_DNS_FORWARDER` | Existing named DNS forwarder; default `RPP Secure DNS` |
| `ROUTEROS_ROUTING_TABLE` | Existing routing mark/table; default `rpp-proxy` |

Certificate verification is mandatory. Redirects are not followed. Credentials
are not returned to the browser. Keep password files and `/data` out of source,
images, releases and issue reports. Restart the container after configuration.

Existing installations can retain their routing names with the three optional
variables above. Names must refer to already configured router objects; the panel
does not rename or create them. Existing DNS rules are not automatically adopted:
back them up and review overlaps before assigning the reserved ownership comment.
Keep any watchdog and direct-IP rules in place. Do not add the ownership prefix
to unrelated or disabled DNS rules.
An explicitly adopted rule that remains identical can retain an existing
overlap; this is not evidence that the old overlap routes correctly. New or
changed overlapping rules are rejected. After deleting such a legacy rule,
re-adding it or rolling it back can require an administrator to resolve the
overlap first. Active regex rules always block synchronization.

## Apply and recovery semantics

- Only DNS static records with comments starting `RPP sites: ` are owned by this
  feature. Reserve that prefix; do not use it for unrelated records.
- The panel checks basic routing prerequisites and rejects overlapping unmanaged
  DNS records or active regex rules before writing. It does not prove all routing
  or firewall rules are correct.
- Records use `type=FWD`, `address-list=rpp-sites`, the named forwarder and the
  chosen subdomain behavior. See [RouterOS DNS](https://manual.mikrotik.com/docs/network-management/dns/).
- Apply reconciles additions, edits and removals, then verifies a readback. It is
  not a transaction. On failure, the panel attempts to restore and verify the
  previous owned records automatically. If that fails too, partial changes may
  remain; the UI reports the failure and keeps the original snapshot for manual
  Rollback or retry. Rollback restores only the owned DNS records. Do not edit these owned records concurrently elsewhere.
- Rollback preserves the edited panel list as a draft; it does not undo unrelated
  DNS/firewall settings. The private snapshot persists across container restarts.
- Existing connections and cached addresses may continue using their previous
  route until expiry/reconnection. No global connection or DNS-cache flush is
  performed. Test real client behavior after changes.

The unit suite uses a simulated RouterOS REST backend. Container tests cover
authenticated save, persistence and unconfigured apply rejection. Hardware and
real-router routing validation remain required before production deployment.

## Simple setup screen

The three-step guide checks router prerequisites without modifying the router,
then guides the user through subscription import, automatic connection testing
and service selection. Advanced server controls remain available in a collapsed
section. Initial container, tunnel and HTTPS management setup still requires the
RouterOS installation guide; this is not a universal automatic installer.

Preset updates are explicit: they add missing suggested domains while preserving
custom domains and existing enabled/disabled choices. Removed preset groups may
be added again. Shared Google media domains can affect other Google services;
Assistant and Home remain opt-in. Changes still require Save and Apply.
