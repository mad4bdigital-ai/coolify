# ChatGPT ↔ Coolify native MCP — integration workstream

Status: **development only; not deployed**. Owner repo: `mad4bdigital-ai/coolify`; feature branch: `feat/chatgpt-mcp-oauth`.

## Confirmed baseline (13 Oct 2026)

The VPS at `srv2030908` runs the native Coolify MCP endpoint at `https://coolify.infra.mad4b.com/mcp`. The operator observed:

- unauthenticated POST initialize → HTTP 401
- authenticated POST initialize → HTTP 200; JSON; MCP protocol `2025-11-25`
- authenticated POST tools/list → HTTP 200, 45 tools, no session-id header

**No credentials are stored in this repository**. These are owner-reported production observations, not CI results.

## Upstream code seam

- `routes/ai.php` registers `Mcp::web('/mcp', CoolifyServer::class)` protected by `mcp.enabled`, `auth:sanctum`, `api.token.team`, `mcp.team.enabled`.
- `app/Mcp/Servers/CoolifyServer.php` registers the tool catalog.
- `tests/Feature/Mcp/McpEndpointTest.php` already exercises Sanctum authentication, token-team permissions and tool listing.

**Do not change these routes, tools or permission checks** just to provide OAuth to a client.

## Minimal compatible solution

Prefer a small standalone OAuth-to-Bearer adapter based on a vetted maintained open-source OAuth/MCP proxy, packaged separately *in this fork* if selected. This is a client-auth compatibility bridge, not a new infrastructure control plane:

ChatGPT (OAuth authorization code + PKCE) → adapter (OAuth token validation) → Coolify native `/mcp` (Sanctum Bearer).

The adapter must expose correct OAuth authorization-server metadata, protected-resource metadata when required, an interactive authorization flow and token exchange, and a protected MCP endpoint. It must handle POST/GET/DELETE where applicable, JSON and event-stream responses, MCP protocol headers and streaming safely. An arbitrary `client_id` plus a reverse proxy is **not** an OAuth authorization server.

Do not expose a static upstream Bearer credential to ChatGPT, log it, put it in the URL, or commit it. Bound team/token abilities are inherited from Coolify's existing `read` token. For a single configured upstream token, all successfully authorized clients have that token's permissions.

## OSS candidates (not yet adopted)

- `babs/mcp-auth-proxy` — OAuth 2.1/OIDC MCP proxy; check requirement for a separate IdP, license, maintenance, transport and proxying semantics.
- `famma-ai/mcp-auth` — Cloudflare Worker reverse-proxy approach; check credentials, runtime dependencies, deployment model and OAuth support.
- Native upstream Coolify issue/discussion on OAuth — track it to avoid duplicating upstream functionality.

**Selection gate:** verify current repository code/licensing and run an end-to-end OAuth + MCP handshake in an isolated environment before adding third-party code or deploying.

## Acceptance contract

1. Unauthenticated adapter MCP request produces valid OAuth resource challenge (not unprotected access).
2. OAuth metadata and authorization code + PKCE login/token exchange work from ChatGPT's actual client configuration, with redirect URIs validated.
3. Unauthorized/malformed tokens are rejected; an authorized request is forwarded to native Coolify without changing team and tool semantics.
4. `initialize` and `tools/list` return successful JSON-RPC; 45 tools in the observed baseline, or a documented upstream catalog difference.
5. `tools/call` read-only smoke succeeds through the adapter (e.g. `get_current_team`) without leaking upstream secrets.
6. MCP endpoint can be added in ChatGPT and tools invoked via **that connector**, not just VPS curl.
7. Existing native `/mcp` with Sanctum token still works. No changes to production Docker/SSH/Firewall/Redis backup during this development.

## Next implementation steps

- Choose a tested OAuth/MCP proxy dependency and pin its version and license.
- Add deployment example and isolated tests in this folder; do not duplicate all 45 tool definitions.
- Open review PR and validate in a disposable staging service before production.
- Only after acceptance, point ChatGPT at the new adapter hostname; retain native Coolify `/mcp` URL.

## Safety constraints

No production deployment authorized by this branch. Never publish API tokens, secret keys, or credentials to public GitHub. No Docker restart, SSH changes, automatic backup pruning, or new R2 upload as a side effect of this work.
