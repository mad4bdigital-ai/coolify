# Coolify → ChatGPT MCP OAuth bridge (staging only)

This directory provides a *deployment template*, **not a forked implementation** of OAuth. It uses [babs/mcp-auth-proxy release v2.1.0](https://github.com/babs/mcp-auth-proxy/releases/tag/v2.1.0) (Apache-2.0) with its documented fixed `UPSTREAM_AUTHORIZATION_HEADER` option. Upstream source tag resolves to `b0062463c4810a21aed62237253c837d4801aa8f`. Verify the published image digest/signature before deploying; no digest has been independently attested by this repo.

## Preconditions

- Native Coolify MCP on `https://coolify.infra.mad4b.com/mcp` works with the operator's read-only Sanctum API token (confirmed initialize 200 / tools/list 200 / 45 tools on 13 Oct 2026).
- A **real OIDC issuer**, for example existing Google Workspace-compatible OIDC broker, Authentik or Keycloak, and an OAuth client registered there with the adapter's callback redirect URI. Do **not** enter the Coolify API token as OIDC client ID/secret.
- A **separate** Redis instance or logically isolated DB with credentials. Do not point at Coolify's existing Redis without explicit resource/data isolation and authorization.
- A dedicated HTTPS subdomain configured in Coolify and routed to container port 8080. Neither the subdomain nor its DNS/TLS have been deployed yet.
- Secret values provided through Coolify's secret environment editor; they MUST NOT be committed, pasted into logs or supplied as command-line arguments.

## Deploy in a separate staging resource

1. In the existing Coolify UI, create a *new* Docker Compose-based resource under a development project. Paste `compose.yaml` as the new resource's Compose definition (do not edit `/data/coolify/source/docker-compose*.yml`).
2. Configure `PROXY_BASE_URL=https://YOUR-NEW-SUBDOMAIN`, `UPSTREAM_MCP_URL=https://coolify.infra.mad4b.com/mcp`, `UPSTREAM_AUTHORIZATION_HEADER=Bearer YOUR-READONLY-TOKEN`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `TOKEN_SIGNING_SECRET` and `REDIS_URL` **in Coolify only**. Only the values of `PROXY_BASE_URL` and `UPSTREAM_MCP_URL` are nonsensitive.
3. Configure this service's HTTPS hostname to route to port `8080`. The Compose file only uses `expose` and must not bind a host port.
4. Set the image to the pinned `ghcr.io/babs/mcp-auth-proxy:2.1.0` only after verifying its signature/digest. The template does not recreate the Coolify platform.
5. Before OAuth login: GET `https://YOUR-NEW-SUBDOMAIN/.well-known/oauth-authorization-server` should return valid JSON; unauthenticated POST `/mcp` should not return protected Coolify data.
6. Connect ChatGPT to `https://YOUR-NEW-SUBDOMAIN/mcp` using OAuth; complete PKCE sign-in, then check `initialize`, `tools/list` and read-only `get_current_team` from **ChatGPT connector itself**. Distinguish authentication failure from tooling or service errors.
7. Rollback: disable/delete *the new staging resource only*. This leaves native Coolify MCP and VPS Docker/Firewall/Systemd backups alone.

### Minimal test contract

| Check | Expected |
|---|---|
| OAuth AS discovery | `200`, valid issuer + authorization + token endpoints |
| OAuth protected resource discovery | `200`, usable authorization server metadata |
| Anonymous MCP POST | `401`, protected-resource challenge |
| Valid OAuth sign-in | Authorization Code + PKCE completes in ChatGPT |
| MCP initialize via connector | valid JSON-RPC response |
| MCP tools/list via connector | tool catalog visible (baseline: 45) |
| MCP read tool call | `get_current_team` succeeds with scoped upstream token |
| Native MCP | continues accepting pre-existing Sanctum token |
| Rollback | removes adapter only |

**Status:** Template committed; not deployed or tested. No credentials requested in GitHub.


## Live staging acceptance and pending hardening — 22 Oct 2026

- Resource: `kj048gjsiptuxet1jfqjhzaz` in `Infrastructure Integrations / staging`. This logical environment shares the VPS with production workloads.
- Deployed commit: `00d4ce4f39737545beff8ea58e13b7518d64f09a`. Redis starts successfully with `user: redis`; prior `setpriv` failure fixed.
- Verified: TLS trust; `/healthz` 200; OAuth discovery 200; protected-resource metadata 200; unauthenticated `/mcp` 401; Google login and token 200; authenticated ChatGPT `server/discover` 200 and `tools/list` 200. Native MCP `initialize` and `server/discover` 200. Direct ChatGPT calls to `coolify_help` and `get_infrastructure_overview` succeeded.
- Coolify readback: app running, zero restarts, `health_check_enabled=false`, `running:unknown`.

### Pending Coolify UI configuration (not performed through read-only MCP)

1. In `Environment Variables`, `OIDC_CLIENT_SECRET`, `UPSTREAM_AUTHORIZATION_HEADER`, and `TOKEN_SIGNING_SECRET` are currently both build-time and runtime. Prefer **runtime-only** and masked values, but test carefully: Coolify's Compose deployment interpolates environment variables. If build-time deactivation breaks interpolation, halt and plan a secret-injection alternative; never expose secrets in rendered Compose or logs.
2. In the application's healthcheck settings, set an HTTP check on internal port `8080`, path `/healthz`, method GET, expected 200, scheme http. Do not use `/` (404 by design). Verify Coolify's Docker Compose support and that the probe targets the adapter rather than Redis.
3. Once these settings are reviewed and applied to this resource only, verify Redis healthy; adapter healthy/running; valid HTTPS; successful authenticated ChatGPT read tool invocation. Do not change Traefik, global Docker, or core Coolify Redis.
4. Preserve a least-privilege `read` Coolify API token. All allowed Google identities share this upstream team credential; enforce a durable identity allowlist before broader use. Google OAuth Testing mode alone is not a long-term authorization policy.
5. Keep the PR in draft and separate production rollout from this staging acceptance; image digest/provenance and secret-injection design remain review items.

No secret value belongs in Git or chat. The above hardening steps are **pending**, not claimed deployed.
