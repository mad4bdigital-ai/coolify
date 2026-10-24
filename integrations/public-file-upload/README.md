# Public upload companion for Coolify MCP PR #1

Independent Internet-facing HTTPS upload API managed as a separate Coolify application from the read-only OAuth MCP adapter. It deliberately does not change native Coolify's /mcp authorization.

Endpoints:
- GET /healthz: no secrets.
- POST /v1/grants: issue upload grant, authenticated by Bearer UPLOAD_ADMIN_TOKEN. JSON `{"expires_in_seconds": 3600, "max_bytes": 16777216, "sha256": "<64-character lowercase SHA256>"}`. Expiry **is selected per grant with no hard-coded maximum**; must be a positive integer. The SHA-256 may be omitted, but exact-hash grants are preferred.
- POST /v1/uploads: Bearer token returned by /v1/grants; Content-Type application/octet-stream; X-Content-SHA256 header; raw binary body. Only stores bytes to a private quarantine volume, without extracting or installing.
- POST /v1/grants/revoke: administrator Bearer token, JSON `{"grant_id":"<32 hexadecimal digits>"}`.

Security: UPLOAD_ADMIN_TOKEN and UPLOAD_SIGNING_SECRET are distinct 32+ character secrets; provide them through Coolify environment secrets, never Git. Publish on a distinct HTTPS hostname and route to internal port 8080. Configure edge request-size and rate limits. No unauthenticated writes. Restrict origin CORS; the API does not emit CORS headers by default. Duration may be customized per issuance without a fixed global upper bound, but long grants increase risk and should be used intentionally. There is no path selection and no file execution. Revocation persists in the same volume. The API handles only intake: no download, deletion, shell or WordPress install endpoint.

Deployment: create a separate Coolify application in the staging project, repository mad4bdigital-ai/coolify branch feat/chatgpt-mcp-oauth, base directory /integrations/public-file-upload, Compose file /compose.yaml. Configure the upload hostname and secrets, deploy, test health/auth/checksum/expiry/revocation. Maintain the existing OAuth MCP adapter as a separate resource. **The native read-only Coolify MCP tool catalog cannot issue these grants without a separately deployed, permission-scoped MCP tool**, which remains to be implemented and tested; do not claim it is already callable by ChatGPT's Coolify connector.

Caution: all files are quarantined and must undergo separate archive inspection and explicit authorized import into the WooCommerce Lab. This intake is not a public anonymous file host.
