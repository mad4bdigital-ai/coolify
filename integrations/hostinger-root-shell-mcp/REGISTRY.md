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
