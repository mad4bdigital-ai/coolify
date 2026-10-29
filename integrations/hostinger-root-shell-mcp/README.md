# Hostinger VPS: unrestricted root Shell via MCP (experimental)

## Scope

Separate MCP server for **real root-level Bash commands on the VPS via SSH**. No command allowlist: arbitrary commands, Docker, package manager, filesystem and service operations execute with **root permissions**. This is distinct from the original read-only Coolify MCP integration.

**Not deployed. Do not auto-deploy this branch. Do not merge to the running OAuth adapter's branch.** Deployment exposes a high-impact administrative capability to anyone who passes the configured OAuth sign-in. Review identity restrictions before any public HTTPS endpoint is enabled.

## Components

- Python MCP SDK Streamable HTTP server on private network, port 8000, `exec_root_shell` tool.
- OpenSSH client authenticates **as root** against Hostinger with dedicated SSH private key and **pinned known_hosts**.
- Separate Google OIDC OAuth proxy on port 8080 (the only service to expose via HTTPS), separate Redis.
- No host network, no Docker socket mount, no published host ports.
- Compose uses an absolute existing key mount path. It does **not** create root credentials or change sshd on the VPS.

## Prerequisites (manual owner-controlled)

1. Review and explicitly authorize enabling **root-level** remote command execution on the Hostinger VPS. Create and install a **new dedicated SSH key** for this integration; do not reuse the host's existing Coolify/GitHub keys. `PermitRootLogin prohibit-password`/key-only root login may be appropriate, but verify your sshd policy and key permissions. No configuration changes are automated here.
2. Capture the VPS SSH host key through an independently verified fingerprint; place it into a read-only `known_hosts` file. **Do not use `StrictHostKeyChecking=no`.**
3. Provision both credential files on the Docker deployment host and supply their **absolute paths** as `ROOT_SSH_PRIVATE_KEY_PATH` and `ROOT_SSH_KNOWN_HOSTS_PATH` within Coolify. Never place file content in environment variables, Git, logs or chat.
4. Register a **separate Google OIDC web client** or additional callback for the **new** host: `https://<dedicated-shell-host>/callback`. Restrict the allowed identities independently of Google's Testing user list; the upstream proxy authenticates a Google identity but does not by itself enforce a single authorized operator.
5. Require manually reviewed deployment, separate resource/domain from the currently functional `coolify-mcp-oauth`. Set `SHELL_PROXY_BASE_URL` to a dedicated HTTPS origin, and supply remaining `SHELL_*` secrets via Coolify's secure editor.
6. Never expose port 8000 or private networks publicly; set service domain on `shell-oauth` port 8080 ONLY. The internal MCP backend has **no additional bearer authorization**; its isolation depends on the private Docker network and the OAuth proxy. Review this trust boundary before deployment.

## Commands

Tool: `exec_root_shell(command: str, timeout_seconds: int = 60)`.
Each invocation runs `bash -lc` as root on the configured host, using SSH without a pseudo-terminal. Output includes exit code, truncated stdout/stderr, and timeout result. **Calls do not preserve shell state between executions**; persistent interactive PTY support is a separate future capability. Timeout 1–300 seconds, maximum 256 KiB stdout and stderr.

## Risks and non-goals

- Root commands may irreversibly modify the VPS, secrets and running workloads. Authentication is required even though the **command set is unrestricted**.
- The server has no command filter, no extra per-command confirmation layer, and does not provide a full interactive PTY in this initial implementation.
- The dedicated root key enables passwordless high-privilege SSH. Protect it, monitor audit logs, revoke it immediately if compromised, and avoid deploying an unrestricted tool without a strict identity allowlist and explicit owner acceptance.
- The host-key and credential mount mechanism must be tested on this Coolify version. Compose interpolates runtime secrets and may expose them in rendered configuration; no raw secret is committed here.
- Python MCP SDK version is range-constrained to v2 but not digest-locked; pin a tested exact version and image digests before production.
- No write is performed on the VPS in this PR, and this is not an authorization to grant root SSH access.

## Initial acceptance checks

Build the image in an isolated environment; test MCP initialize, tools/list, rejected unauthenticated requests by the proxy, successful owner-only OAuth, and read-only root command `id -u` returning 0. Test error/timeout cases and ensure secrets never appear in logs. Confirm original Coolify MCP stays independently functional.

## Rollback

Disable/delete the **new shell resource**, then remove its dedicated root public key from `authorized_keys`. This does not require any change to the existing Coolify MCP proxy.


## Selecting from multiple existing SSH keys

The application lists keys only from the operator-approved host directory mounted by `SHELL_KEY_DIRECTORY` (mapped read-only to `/run/secrets/ssh-keys`). It does **not** scan the VPS filesystem or the existing Coolify deployment's secrets.

- `list_ssh_keys()` returns available **file names only**; never key contents.
- `exec_root_shell(command, key_name, timeout_seconds)` requires an exact `key_name` from that list. If no key is chosen or the name is unavailable, it returns `selection_required=true` with choices, without executing a command.
- Multiple keys are valid, and no key is auto-selected; the user or caller chooses for each command.
- Keep `ROOT_SSH_KNOWN_HOSTS_PATH` pinned to independently verified host keys. A listed key does not imply SSH authentication or Root access will succeed.
- The account behind Google OAuth controls access to this MCP endpoint; for unrestricted Root execution, Google sign-in must be restricted to the explicitly approved operator(s). The shell code contains no separate account registry.

**Do not mount a broad SSH folder containing unrelated credentials.** Create a dedicated directory containing only the specific existing key files authorized for this service. Key paths remain on the VPS, never in GitHub.

## ChatGPT MCP registration lifecycle (owner-approved)

The `shell-oauth` service explicitly sets `CLIENT_REGISTRATION_TTL: "0"` for
`ghcr.io/babs/mcp-auth-proxy:2.1.0`. In this image **0 disables expiry for
newly issued, sealed Dynamic Client Registration (`client_id`) records**.
This prevents the seven-day `invalid_client / client_registration_expired`
failure with clients that do not automatically re-register. It does **not**
extend OAuth access tokens, refresh tokens, OIDC sessions, or SSH credentials.

Security trade-off: a non-expiring registration removes the client-id reuse
window bound. Keep `PROD_MODE=true`, mandatory Google OIDC, owner-identity
restrictions, signing key custody, replay protection, and private upstream
network isolation. Never commit or rotate `TOKEN_SIGNING_SECRET` during this
configuration-only change.

**Existing expired `client_id` values remain expired.** After a controlled
deployment of the source Compose through Coolify, reconnect affected ChatGPT
MCP apps to issue fresh registrations. Verify runtime has
`CLIENT_REGISTRATION_TTL=0`, then test OAuth sign-in and `tools/list`
through the domain. Keep a rollback copy of the previous Compose and avoid
recreating the Redis or SSH services. Rolling back to the image default will
restore seven-day expiry **only for newly issued registrations**; use an
explicit key-revocation procedure for compromised registrations.

This integration config covers the shell proxy used for Registry and Shell
MCP applications when both are deployed from this source file. The separate
`coolify-mcp-oauth` service has a different source/image and is not changed
by this setting.
