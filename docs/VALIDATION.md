# Beta validation

## v0.3.0-beta.1 native TUN (2026-11-02)

After removing a duplicate privacy-audit wrapper, 65 unit tests remain. The
privacy guard still runs explicitly in CI and packaging. The two reusable
container checks live under `tests/integration/`; deployment diagnostics are
not part of the repository or image.

The AMD64 native gateway integration test passed with actual routed HTTP/HTTPS
body verification, UDP payloads up to 4096 bytes, root privilege removal, probe
isolation, Xray crash recovery, VPN off/on and full container restart. The normal
non-gateway container smoke test also passed. ARM64 images built successfully.

On a physical ARM64 MikroTik hAP ax3 running RouterOS 7.23.7, an isolated veth
test passed actual HTTPS page transfers, certificate verification and a UDP STUN
response from a client routed through native TUN. After a manual container
stop/start, HTTPS and UDP tests passed again and the TUN packet counters increased.
The application and core ran as UID 10001 with no effective capabilities.

The same image was then activated on that installation, reusing its private data
volume and changing the selected-sites gateway. Normal client routing returned
verified HTTPS pages for YouTube, WhatsApp, Telegram, Spotify and ordinary sites;
secure DoH and authenticated RouterOS HTTPS readiness checks also passed. Existing
site data matched the pre-migration backup exactly. The operator confirmed phone
video and messaging worked. Previous containers were retained stopped for rollback.

The ARM64 gateway smoke test under x86 emulation failed while querying Linux
network rules. This emulated test is not recorded as passed; physical RouterOS
testing is a separate result. Performance, every RouterOS/kernel combination,
long-term stability and every provider remain unproven. No private deployment
identifiers, state, domain groups or subscriptions are test fixtures.

## v0.2.4-beta.1 site toggle routing

60 automated tests pass, including scoped route cleanup, shared destinations,
retry checkpoints, cached-address restoration and RouterOS duplicate-address
handling. On a private RouterOS 7 installation, a temporary test domain was
enabled and a real HTTPS response was received through a proxy-marked connection.
Disabling it removed its two DNS-derived routes and the exact marked connection;
re-enabling restored both routes from unexpired DNS cache and another proxied
HTTPS request succeeded. The temporary group was then removed.

Private user groups are not source presets or release fixtures. Static/manual
routes and shared IPs remain protected; this is not an exact application switch.

## v0.2.3-beta.1 HTTPS site integration

50 automated tests pass, including custom routing names, literal RouterOS record
IDs and preservation of unchanged, explicitly adopted legacy overlaps. ARM64 and
AMD64 container smoke tests passed. On one private RouterOS 7 installation, HTTPS REST
was tested with a dedicated source-restricted account and a private CA; an
untrusted CA was rejected. The panel's readiness check and real DNS rule creation
and deletion passed. Existing rules were compared before and after; unrelated
rules were unchanged. Real HTTPS page and secure-DNS checks also passed.

This validates that installation, not arbitrary router configurations. Existing
overlaps still require operator review, and deleting a legacy overlapping rule
may prevent its re-creation until the overlap is resolved. No operational
identifiers, credentials, subscription data or router exports are published.

## v0.2.0-beta.1 site management

35 tests pass, including simulated RouterOS reconciliation, conflict rejection,
domain validation, idempotence and preserved rollback snapshots after failed
retries. Container smoke tests additionally exercise authenticated site storage,
restart persistence and rejection of apply without router configuration.
The REST integration has not been exercised against physical RouterOS hardware.
Presets are editable starting points, not verified exhaustive service inventories.

## Initial container baseline

Validated on 2026-11-01:

- 27 automated tests passed: parsing, certificate policy, secure downloads,
  bootstrap behavior, recovery selection, login/authentication, Origin checks,
  source privacy checks and opt-in RouterOS DNS fallback generation.
- Docker images built successfully for Linux AMD64 and ARM64.
- Both images passed isolated runtime smoke tests: empty first install,
  authentication, persistent login after restart, cross-origin rejection and
  configuration validation by the bundled Xray binary for TCP, WebSocket,
  XHTTP, gRPC and HTTPUpgrade.
- ARM64 execution used Docker emulation, not physical router hardware.
- Source was compared against private deployment identifiers before publication.
  The repository contains no deployment state or real subscription fixtures.

These checks do not prove connectivity through every VPN provider. No real
subscription is used by CI. The RouterOS integration recipe still requires
validation on an isolated lab router, including firewall, routing, IPv6,
certificate trust, storage ownership and DNS failover behavior.
