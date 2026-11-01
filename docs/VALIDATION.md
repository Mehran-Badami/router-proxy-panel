# Beta validation

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
