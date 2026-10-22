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
