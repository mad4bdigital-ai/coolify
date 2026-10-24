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
