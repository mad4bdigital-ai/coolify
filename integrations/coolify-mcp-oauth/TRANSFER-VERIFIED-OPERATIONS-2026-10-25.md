# MAD4B file transfer — verified operations and acceptance (25 October 2026)

> Operational evidence snapshot. PASS applies only to the explicitly tested scope, not to all attachment sources, production, or zero-downtime deployment. Never report file installation from a successful quarantine receipt.

## Verified on the connected Staging VPS

| Check | Result | Evidence |
|---|---|---|
| Connected upload MCP catalog | PASS | Eight upload operations advertised; `upload_file`, `upload_begin`, `upload_chunk`, `upload_status`, `upload_commit`, `upload_attachment`, `upload_server_file`, `upload_from_url` |
| Real inline-byte MCP intake | PASS | 36-byte smoke file reached `quarantined` |
| MCP quarantine → VPS promotion | PASS | `upload_server_file` returned `stored_on_vps`, `verified: true`, `already_present: false` |
| Verified repeat request | PASS | Same promotion returned `already_present: true`; VPS SHA-256 confirmed |
| Large chunked upload (synthetic bytes) | PASS | 1,585,902 bytes sent in 6 chunks, committed to quarantine, promoted and verified on VPS |
| SHA-256 integrity of synthetic large file | PASS | `c83bfb62eb825c5b93ec26681d17b292a89148210226612059b971f27047d155` |
| Source test suite at `7a6e08ca` | PASS | 60/60 Python unit tests |
| Native ChatGPT ZIP attachment → MCP | **NOT ACCEPTED** | Tool cannot read a conversation file ID, file_uri or container path directly; synthetic data is not the original attachment |
| JetWooBuilder 2.3.5 transferred or installed | **NOT DONE** | Original 1,585,902-byte ZIP SHA-256 `caeaa0c464c55e77f6acfc225288909da1fa470771412cd89e80b1c2f82ac219` not received on VPS; WooCommerce Lab remains 2.3.3 |
| OAuth zero-downtime deployment | **NOT ACCEPTED** | HTTP 503 observed during repeated Compose deployments |

### Known verified artifacts (do not confuse them)

- 36-byte live smoke: `/opt/mad4b/uploads/quarantine/mad4b-transfer-live-smoke-20261025.txt`, SHA-256 `aa85271c011673ce28eafd938fe34d7ed230cf3ca42ac3065425ed136963ebf0`.
- Synthetic large capacity file: `/opt/mad4b/uploads/quarantine/mad4b-transfer-1585902-byte-capacity-test.bin`, 1,585,902 bytes, SHA-256 `c83bfb62eb825c5b93ec26681d17b292a89148210226612059b971f27047d155`.
- Original JetWooBuilder ZIP: **different SHA** `caeaa0c464c55e77f6acfc225288909da1fa470771412cd89e80b1c2f82ac219`. Never rename/reuse synthetic bytes as the package.
- Lab rollback archive for installed JetWooBuilder 2.3.3: `/opt/hostinger-migrations/hosting-3/etg-woocommerce-lab/jetwoobuilder-233-rollback-20261025.tar.gz`; lab-only installer guard: `install-verified-builder.sh`. It must fail closed until exact ZIP digest matches.

## Recommended routine

1. Verify OAuth endpoints: `/healthz` HTTP 200, unauthenticated `/mcp` HTTP 401, bare `/authorize` HTTP 400. These confirm routing only, **not** full interactive OAuth success.
2. Use `upload_attachment` with **actual** client-provided Base64 bytes OR a real authorized allowlisted HTTPS URL, not both; the tool does not resolve ChatGPT `file_id`, `file_uri`, `sandbox:` or filesystem paths.
3. For large files whose bytes are available to an authorized client, use `upload_begin(size,sha256)`, then ordered `upload_chunk(transfer_id,offset,base64)` operations (<= advertised max chunk), `upload_status` as needed and `upload_commit`. The commit result means `quarantined`, not VPS stored.
4. Promote only the verified digest via `upload_server_file(sha256, filename)`; inspect `stored_on_vps`, `verified`, bytes and `already_present`. Independently hash the VPS file.
5. Only after original ZIP checksum matches, use lab-only installation guard with pre-existing rollback backup, verify installed version and plugin operation. Never update Production implicitly.

## GitHub/Coolify publishing

- Branch: `feat/chatgpt-mcp-oauth`, PR #1, repo `mad4bdigital-ai/coolify`.
- Coolify application UUID: `kj048gjsiptuxet1jfqjhzaz`. On 25 Oct 2026, `is_auto_deploy_enabled` was explicitly restored to **true** at the user's request. Do not silently disable it.
- Multiple commits may queue multiple deployments and cause OAuth 503 because the existing Compose replacement is not proven zero-downtime. Prefer grouping related updates in one cohesive commit/deploy window and monitor public endpoints. Do not label the pipeline zero-downtime until verified during a real redeploy.
- Traefik routers pin `traefik.docker.network=coolify` to avoid unpredictable Docker network selection after redeploy.
- Do not claim an operation is accepted based only on CI, tool declaration, a transfer initiation, or a matching byte count.

## Future acceptance gates

- Verify genuine user-provided attachment bytes reach MCP with exact original digest.
- Verify the actual original ZIP is promoted to VPS and Lab-only installer reports version 2.3.5; verify rollback.
- Verify external OAuth flow and 503-free deployment across multiple consecutive deploys.
