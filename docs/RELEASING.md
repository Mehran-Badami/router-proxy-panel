# Release procedure

1. Work in a clean clone. Never copy an operational data directory or router export.
2. Run unit/integration tests and the source privacy guard.
3. Build the container and run `tools/container_smoke.py` on AMD64 and ARM64.
   For native gateway changes, also run `tools/native_tun_smoke.py` on native
   AMD64 Linux with Docker and the `cryptography` test dependency. Record ARM64
   gateway validation separately on physical hardware; emulation is not equivalent.
4. Review the staged diff and file list; use a non-private commit author email.
5. Run `tools/package_release.py`; inspect archive filenames before uploading.
6. Tag a reviewed version such as `v0.1.0-beta.1` and push that tag. The publish
   workflow repeats tests and publishes only if checks pass.
7. Verify the GHCR package's visibility and pull the image without authentication
   before calling it publicly available. GitHub can create a package as private
   even when its source repository is public; review package settings.
8. On a separate lab router, test installation, restart, updates, DNS fallback,
   recovery, selective routing and rollback. Record hardware/RouterOS versions
   only with the lab operator's consent. Do not publish operational identifiers.

The Dockerfile pins the Xray image by digest. Update that version and source/license
references together, then rerun the configuration matrix against the new core.
There is no bundled subscription or guarantee that a provider will support a
particular VLESS extension indefinitely.

The included CI workflow uses GitHub-hosted runners and GHCR via GITHUB_TOKEN.
It does not require copying an operator's Docker password into the repository.
Do not enable deployment to a real router in public pull-request workflows.
