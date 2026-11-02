# Security and privacy

This is an early public release for a trusted LAN or an authenticated VPN.
Do not forward the panel, SOCKS or DoH relay ports from the public Internet.
HTTP is acceptable only inside a trusted network or encrypted VPN. For a TLS
reverse proxy, set PUBLIC_ORIGIN to its exact HTTPS origin; cookies then use Secure.

Each installation generates a different access key in /data/access-token.
Login cookies are HttpOnly, SameSite=Strict and expire after 30 days by default.
Bookmark the root page after logging in. There is also a login form if cookies expire.
Treat the key, private login URL, browser cookie, QR code, subscription URLs,
Xray configurations, catalogs and bootstrap cache as secrets or private operational data.

No analytics or telemetry is implemented. Startup does not print an access key.
The status API excludes subscription URLs and raw outbound configurations.
Health probes contact example.com via Google DNS, YouTube and WhatsApp.
An explicit speed test downloads approximately 2 MB from Cloudflare.
Configured subscription providers receive requests only when importing/updating a group.

Subscription downloads require verified HTTPS, reject private/reserved DNS targets,
pin the validated address for the actual TLS connection and revalidate redirects.
Only TLS/Reality VLESS links are supported; insecure certificate flags are rejected.
The SOCKS and DoH relay services rely on network firewall isolation, not application login.

Native TUN mode requires a dedicated container network namespace and initial
root privileges for network setup. The entrypoint then permanently drops to UID
10001 before running the panel or Xray; the core inherits an already-open TUN
descriptor. This mode does not authenticate forwarded packets. Restrict access
at the router and explicitly configure only the intended client subnets.

DoH failure does not enable plaintext DNS by itself. The optional RouterOS fallback
recipe is a separate explicit deployment choice. System DNS bootstrap for VPN server
hostnames is enabled by default so a fresh subscription can be used without a working
tunnel; set ALLOW_SYSTEM_BOOTSTRAP=false for strict behavior and supply a bootstrap IP.

Before sharing a fork, run `python tools/privacy_guard.py` and inspect the staged diff.
The release packager uses a file allowlist and excludes .git and runtime state.
These checks reduce accidental disclosure; they are not a guarantee against arbitrary secrets.
Never publish a copy of an operational data volume or a real router export.

Report vulnerabilities through GitHub private vulnerability reporting if enabled.
Otherwise contact the repository owner privately; do not include tokens in public issues.
