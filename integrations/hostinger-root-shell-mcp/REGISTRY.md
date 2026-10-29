# Dynamic Infrastructure Registry (phase 1)

This branch adds `list_infrastructure_targets(environment="", kind="")` to the existing Shell MCP server. It reads an **explicitly approved** JSON inventory, never scans external networks, and never returns credentials. Targets are displayed with ID, provider-agnostic type, host, port, label, environment, and enabled flag.

Supported target kinds: `ssh`, `sftp`, `mysql`, `postgres`, `https_api`, `wordpress`. This first phase is **inventory only**, not automatic remote access. The pre-existing `exec_root_shell` is unchanged.

Configuration:
- Image contains a non-secret example at `/app/infrastructure-registry.json`, which may be replaced by a read-only mount from an operator-approved inventory file.
- Override path with `INFRA_REGISTRY_FILE` if needed.
- The JSON root must include `{"targets":[...]}`. Each ID must be unique and use lowercase letters, digits, underscores or dashes.
- Do **not** put passwords, tokens, private keys or other secrets in inventory JSON. Credential bindings will be separately implemented later.
- All future remote connections will require an explicit target ID, independent credential binding, and distinct authorization policy. Scanning arbitrary hosts is not part of registry discovery.

Acceptance:
1. Local syntax test for `registry.py` and `server.py`.
2. Image build and MCP discovery of `list_infrastructure_targets`.
3. Query the example entry and verify only metadata is exposed.
4. Supply an authorized inventory via read-only mount; verify invalid/duplicate IDs are rejected.
5. Confirm the original `infra.mad4b` and deployed Shell resource remain unchanged.

**No deployment is included in this PR.** Create a separate test resource or explicitly approve the new branch as a deployment source after validation.

## Completed development checks (source)

- Added offline tests for missing inventory, filtering, duplicate/invalid IDs, host and port validation, IPv6, and secret-field exclusion.
- Added scoped GitHub Actions workflow `.github/workflows/hostinger-infrastructure-registry.yml`, which does not read deployment credentials.
- Any new host must be explicitly enrolled in the registry. No automatic probing or access to hosts outside the registry is authorized by this feature.
- Integration tests against new external infrastructure are still pending.


## Provider adapters — current scope

The `providers.py` module and exposed MCP tools provide **unauthenticated** checks for enrolled targets:

- `probe_registered_target(target_id, timeout_seconds=5)`: bounded TCP handshake for SSH/SFTP/MySQL/Postgres/HTTPS; returns `authenticated=false` and `data_access_verified=false`, even when reachable.
- `probe_registered_https(target_id)`: TLS-verified HTTPS HEAD for a registered `wordpress` or `https_api` origin; no redirects or credential headers.
- Both reject unknown and disabled inventory entries.

**Authentication and data transfer remain separate pending features.** A TCP handshake cannot prove access to a database, SSH user, or WordPress account. No credentials should be embedded into `infrastructure-registry.json`, passed as MCP tool arguments, or committed to this repository.

### Planned credential boundary

Each target will reference an operator-approved secret binding by stable identifier. The binding will be resolved only inside the service from an isolated secret store or read-only mount; tools will expose the binding status and provider type, never secret values. Actual authenticated sessions require independent tests with least-privilege accounts, TLS/SSH host verification and audit logging.

Current production deployment source is still `feat/hostinger-root-shell-mcp`, not this branch.

## Hostinger Multi-Account Gateway — initial implementation

The gateway currently records three independent hPanel account aliases: `cloud-startup`, `allroyalegypt` and `egypttourgates` bound respectively to `hosting-1`, `hosting-2` and `hosting-3`.

MCP tools:
- `list_hostinger_hpanel_accounts()`: non-secret routing metadata and capability catalog.
- `plan_hostinger_import(target_id, category)`: a read-only plan targeting `hostinger-primary`. Categories: inventory, websites, databases, backups and domains. Mail is intentionally excluded.

Important: This stage does not claim to have authenticated to hPanel. Every account reports `credential_binding=not_configured`. No hPanel API requests, backup exports, secret provisioning, migrations or DNS changes are performed by these tools.

Next integration boundary: individually provision limited-scope hPanel API credentials in a secure per-account secret mount; inspect official endpoint availability and scopes before implementing live read-only inventory. Require explicit approval and verified source/destination for data movement. No mailbox transfer to VPS.

The running Registry resource must not be redeployed until CI and OAuth acceptance are complete.

## Hostinger API read-only adapter

Added tools:
- `hostinger_account_binding_status()` returns only whether a token file exists for each alias.
- `list_hostinger_websites(target_id)` performs a read-only GET against the official `/api/hosting/v1/websites` endpoint after resolving the account alias; results are projected to domain/type/username.

Expected operator-provisioned read-only secret paths (NOT committed):
- `/run/secrets/hostinger-accounts/cloud-startup.token`
- `/run/secrets/hostinger-accounts/allroyalegypt.token`
- `/run/secrets/hostinger-accounts/egypttourgates.token`

Credentials must be separately mounted read-only into the Registry container before live API use. No secrets are currently provisioned by this branch, and source hPanel identities are not assumed to be authorized by existing SSH credentials. Do not expose email mailbox data, or enable write operations. The current adapter does not export database or website backups.

## Existing SSH identities on the enrolled VPS (operator-verified 2026-10-22)

**Do not recreate target keys or restart SSH discovery from /root/.ssh.**
The prepared external-target identities exist on the primary VPS at
`/opt/hostinger-shell-mcp/external-targets/<target_id>/` for all three
`hosting-1`, `hosting-2`, and `hosting-3`. Each directory contains:
- `id_ed25519` (mode 0600) and `id_ed25519.pub`: key pairs checked locally as matching;
- `host_keys_candidate`: one observed SSH host-key record for the enrolled
  endpoint on port 65002. **These are candidates, NOT verified/pinned trust anchors.**

Enrolled identities are:
- `hosting-1`: `u338416126@147.93.49.130:65002`;
- `hosting-2` (All Royal Egypt): `u948953904@92.113.28.241:65002`;
- `hosting-3` (Egypt Tour Gates): `u783534439@82.198.227.227:65002`.

Read-only verification found the public key for `hosting-2` and `hosting-3`
in their respective *archived migration copies* of `authorized_keys`:
`/opt/hostinger-migrations/hosting-{2,3}/account-files/.ssh/authorized_keys`.
An archive match is **not proof of current remote authorization**.

Staging Registry service bind-mounts the prepared directory read-only into
`/run/secrets/external-targets`. The existing `list_infrastructure_targets`
tool includes per-target `ssh_binding.status` and safe Boolean fields.
This is **inventory/readiness only**, not SSH authentication or shell execution.
The `exec_root_shell` tool remains restricted to the primary VPS. Never use
`host_keys_candidate` as a verified known-hosts file: independently verify
Hostinger's server SSH key before provisioning an approved
`known_hosts_verified` trust file and performing an authorized login probe.

The original `shell_access` identity and `/run/secrets/ssh-keys` remain
separate from external targets. No credentials or private keys are committed.
