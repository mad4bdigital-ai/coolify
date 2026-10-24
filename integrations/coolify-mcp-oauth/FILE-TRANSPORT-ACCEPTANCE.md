# File transports — acceptance matrix (24 October 2026)

This feature branch contains the following capabilities in the existing OAuth application Compose stack. All files go to isolated quarantine, not to WordPress paths.

| Mode | Implementation | Test / remaining condition |
|---|---|---|
| Temporary HTTPS download link | POST /v1/import-url; `url_import.py` | Syntax and untrusted-URL rejection tests pass; allowlist must be configured; genuine expiring URL acceptance not yet shown |
| Base64 chunks via Shell | `shell_transfer_cli.py` calls /v1/transfers/begin, status, chunk and commit, with local state for restart | Transfer unit tests pass; needs reachable HTTPS endpoint and a valid OAuth bearer in the invoking Shell environment |
| Native attachment from ChatGPT | `upload_file` MCP method accepts content_base64 and SHA256; quarantine validates bytes | **Not an actual file_uri transfer.** ChatGPT plugin runtime/connector must expose a supported attachment reference or content bytes as tool input |
| Public HTTPS intake | `public-file-upload` sidecar inside existing Coolify OAuth Compose service | Healthy on Staging; no independently verified public upload hostname and auth acceptance |
| Shell MCP native upload tool | Thin Shell client provided; MCP tool catalog exposed by upload sidecar at /mcp-upload | Existing Hostinger root-shell MCP catalogue is separate. Tool registration and ChatGPT connection still require configuration |

Current OAuth verification is delegated to the existing proxy with `initialize`, not an explicit upload-scope authorization. Do not publicly publish /v1/import-url, /v1/grants or /mcp-upload before verifying specific upload authorization, durable principal identity, non-replay protections and quotas.

Do not equate automatic branch redeploy with automatic registration of tools in ChatGPT. Also do not interpret the presence of `file_uri` as permission or ability to dereference a private ChatGPT attachment: there must be a supported host-provided file transport.

The archive JetWooBuilder 2.3.5 has known expected SHA-256 `caeaa0c464c55e77f6acfc225288909da1fa470771412cd89e80b1c2f82ac219`; no claim of delivery to VPS until independent hash readback on VPS.

## Explicit outcome semantics and hardening (24 October 2026)

Treat the following as distinct, independently verified states:

- `transfer_started`: an allocation and transfer ID only; zero bytes may have arrived.
- `bytes_received`: status offset confirmed; partial bytes are **not** an uploaded artifact.
- `quarantined`: commit returned after validating full length and SHA-256 on the upload service; **not** delivered to VPS.
- `stored_on_vps`: `upload_server_file` copied the verified quarantine artifact to the fixed VPS staging directory. Read back SHA-256 on the target to establish independent confirmation.
- `installed_in_lab`: separate, explicit WordPress Lab operation and plugin-version readback; none of the upload tools installs or activates software.

`upload_attachment` is a legacy name for Base64 content ingestion; it does not dereference ChatGPT attachment IDs, `file_uri`, local paths, or conversation files. A native attachment workflow requires an explicitly authorized runtime-provided byte bridge or binary HTTPS upload. Never pass arbitrary private ChatGPT URLs to `upload_from_url`.

**Authorization:** Only `UPLOAD_AUTHORIZATION_MODE=strict` with an explicit verified `files:upload` permission and principal is allowed. A successful OAuth login/initialize alone cannot grant upload rights; `oauth_login` and unknown modes deny. Revise any staging configuration relying on the previous login-only mode before deployment.

**Claims:** A successful PR check or local unit test does not certify public HTTPS routing, attachment-byte access from ChatGPT, production readiness, full malware safety, SFTP arrival, or WordPress installation. In reports, include the verified state, artifact digest, target, and evidence; use `not_verified` for missing stages.

## Two executable intake methods (explicit client, no invented ChatGPT file access)

The checked-in `upload/attachment_transport_client.py` provides both paths through the same strict OAuth upload sidecar. The caller must obtain the source bytes or HTTPS URL separately and lawfully; it cannot discover ChatGPT attachments or read a `file_uri` from MCP metadata.

1. **Binary upload from an authorized local file** (no Base64 at the client):
   `MAD4B_UPLOAD_OAUTH_TOKEN=... python3 attachment_transport_client.py --origin https://<configured-upload-host> --file /path/to/authorized-attachment.zip --sha256 <expected-64-hex>`.
   The helper requests a short-lived SHA-bound upload grant from `/v1/grants`, then sends application/octet-stream bytes to `/v1/uploads`.
2. **HTTPS source import:** 
   `MAD4B_UPLOAD_OAUTH_TOKEN=... python3 attachment_transport_client.py --origin https://<configured-upload-host> --url https://<operator-allowlisted-source>/archive.zip --sha256 <expected-64-hex>`.
   The service accepts only the operator's exact `UPLOAD_URL_ALLOWED_HOSTS`; its URL importer pins public DNS resolution, refuses redirects and verifies full SHA-256. Private attachment URLs must not be assumed reachable or permitted.

Both methods return **quarantined**, never installed or delivered to VPS. A later authenticated `upload_server_file` promotion and independent VPS hash readback are required. Do not put tokens or signed URLs in CI logs, shell history or issue comments. OAuth permission `files:upload` must be actually enforced before enabling either route.
