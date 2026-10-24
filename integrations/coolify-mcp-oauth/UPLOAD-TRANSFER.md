# Unified file transport — PR #1

Two transports share the **existing OAuth MCP identity** and quarantine storage, with no additional end-user login:

1. **HTTPS single request** — `POST /v1/uploads` with a signed dynamic upload grant, Content-Type application/octet-stream and X-Content-SHA256. The grant is issued/revoked via `POST /v1/grants` and `POST /v1/grants/revoke`, protected by existing OAuth validation. Each grant has a positive dynamically chosen expiry without a coded maximum.
2. **Resumable transport for Shell / MCP** — `POST /v1/transfers/{begin,chunk,status,commit}` using the existing OAuth access token. Equivalent JSON-RPC MCP tools are provided at **the upload companion's** `/mcp-upload`: `upload_begin`, `upload_chunk`, `upload_status`, `upload_commit`. Begin takes size and sha256; chunk takes transfer_id, offset and base64; status takes transfer_id; commit validates size/hash and quarantines file.

Only fixed quarantine paths are accepted; no arbitrary destination, extraction, execution or WordPress plugin installation. Each chunk is limited to 512 KiB; transfer size defaults to 32 MiB. Requests fail closed on missing OAuth, expired partial upload (24h), wrong offset or checksum. New file bytes are not trusted until commit succeeds.

**Connectivity scope:** These operations are implemented in the upload sidecar; they are **not automatically added to the existing upstream Coolify native MCP tool catalog**. Coolify must explicitly route the service's HTTPS hostname to port 8080 and register /mcp-upload as an MCP resource/connector before tools can be invoked from ChatGPT. Direct HTTP requests to the upload service likewise require the HTTPS route. A Shell agent may call the authenticated HTTP interface, but the existing read-only upstream MCP token must not be repurposed as upload authorization.

**Important open issues before public rollout:** Bind each upload/transfer to an authenticated subject with write authorization (currently the proxy validates any logged-in OAuth bearer), add durable per-transfer atomic locks for concurrent chunks, request throttling, anti-abuse quotas, cleanup of expired partial uploads, HTTPS routing, and fully exercising approved OAuth token and browser/CORS clients. Dynamic grant length does not remove size controls. Current implementation is staging-only.

All changes in this directory are in PR #1. PR #3 Shell MCP remains independent; it does not need to be merged into PR #1 to expose a resumable transport API.
