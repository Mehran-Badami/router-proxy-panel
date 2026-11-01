# Beta validation

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
