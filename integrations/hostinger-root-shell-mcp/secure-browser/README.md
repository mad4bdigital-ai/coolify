# MAD4B Secure Browser Workspace (staged source; not deployed)

An **opt-in**, independently deployed LinuxServer Webtop workspace for interactive Hostinger hPanel sign-in and future operator GUIs. This directory does not change the Registry deployment, the root-shell MCP service, production traffic, or any existing OAuth identity.

## Preflight and security gates

1. Deploy as a **separate Coolify Docker Compose resource**; do not merge with `../compose.yaml` or `../hostinger-oauth/compose.oauth.yaml`.
2. Provide real, pre-created directories `BROWSER_CONFIG_DIR` and `BROWSER_OAUTH_STATE_DIR` on the VPS. Neither path may contain SSH private keys, Docker socket mounts or existing production application state. Protect the latter with restrictive host permissions and matching container access ownership. Back it up encrypted.
3. No host `ports:` are published. `3001` is available only on the Docker network; do not expose that network via a public ingress until the gateway is deployed and tested. Verify Docker network attach rules and Coolify's actual proxy configuration before attempting public routing.
4. Configure **independent HTTPS + SSO/MFA**, limited named users, access logs and session expiry at the gateway. Webtop's optional built-in Basic Auth is **not** a substitute for this. Fail closed if the gateway is absent; never publish 3000/3001 directly.
5. LinuxServer warns that Webtop has a passwordless-sudo terminal. `PUID`/`PGID`, `cap_drop` and `no-new-privileges` reduce risk but do not make this an unprivileged browser sandbox. No `privileged`, Docker socket, host PID/network mode, or VPS root mounts. Check the selected image works with these restrictions before authorizing deployment.
6. Image tag must be reviewed and pinned to a verified digest for production. `ubuntu-xfce` is a staging reference, **not** a pinned artifact. Update deliberately after compatibility tests.
7. Store separate browser profiles and **separate OAuth state directories per account**. A single workspace can be used interactively in sequence, but avoid concurrent cross-account sessions in one shared profile.
8. Hostinger's official OAuth MCP CLI currently runs as a separate stdio worker (`../hostinger-oauth/`). Docker bridge networking does **not** share `127.0.0.1` with Webtop. Merely attaching the existing worker to `browser-access` cannot complete a localhost OAuth callback. Choose a reviewed same-container execution plan or dedicated shared network namespace, and test the actual CLI callback address/port before any sign-in.
9. The existing `HOSTINGER_API_TOKEN` (if any) must never be inherited into OAuth enrollment because it bypasses interactive OAuth. Do not copy tokens across Hostinger accounts.
10. Do not enable the future dynamic Registry bridge until account identity, token storage, scope boundaries, token refresh and read-only inventory are validated.

## Staged environment template

```dotenv
BROWSER_UID=1000
BROWSER_GID=1000
BROWSER_TZ=Africa/Cairo
BROWSER_CONFIG_DIR=/opt/mad4b-secure-browser/config
BROWSER_OAUTH_STATE_DIR=/opt/mad4b-secure-browser/oauth-state
```

Create directories beforehand and verify their owners and permissions. The `compose.yaml` intentionally fails without the two directory variables and sets `create_host_path: false`.

## Acceptance sequence

- [ ] Compose validates and image runs with all supplied restrictions on staging.
- [ ] Gateway enforces TLS, SSO, MFA and an allowlist; unauthorized requests do not reach Webtop.
- [ ] Confirm no published host desktop/VNC ports, no Docker socket, and no SSH key mounts.
- [ ] Webtop starts, Chromium is available, and browser profile data survives a container restart.
- [ ] Validate official Hostinger MCP version, supported `--login` flow, and concrete loopback callback binding from the **same network namespace** as the initiating browser.
- [ ] Operator signs in to one named Cloud Startup account, with identity checked before any inventory request.
- [ ] Credentials survive restart in dedicated secret storage; no tokens appear in logs or Git.
- [ ] Perform only authorized read-only inventory of the ten Cloud Startup websites; reconcile identities and counts.
- [ ] Verify a clean rollback of this resource leaves Registry, root-shell MCP, and production unchanged.

**Current status:** Source-only implementation. No deployment, OAuth exchange, secret initialization or inventory execution is asserted.
