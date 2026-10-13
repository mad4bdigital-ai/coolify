# Thin OAuth adapter for native Coolify MCP — evaluated OSS baseline

**Selected candidate:** [babs/mcp-auth-proxy](https://github.com/babs/mcp-auth-proxy), upstream stable release **v2.1.0** (published 2026-10-06). Apache-2.0 project; verify image provenance and digest before any deployment. No code from the upstream project has been copied into this fork.

## Why this one

The existing Go proxy already implements OAuth 2.1 + PKCE, OAuth discovery, dynamic registration, protected-resource challenges, OIDC federation, and transparent forwarding of MCP traffic. Critically, its documented `UPSTREAM_AUTHORIZATION_HEADER` option sends a **fixed Bearer header to the upstream MCP** while authenticating ChatGPT separately. This is the exact missing feature for native Coolify Sanctum MCP. We need no Laravel changes and no copy of the 45 MCP tools.

Famma AI's library is more useful if building a custom Cloudflare Worker and a pluggable login UI, which adds unnecessary application code for this case.

## Required configuration in isolated staging

- `PROXY_BASE_URL`: HTTPS URL of test adapter (separate subdomain; never alias existing `/mcp`)
- `UPSTREAM_MCP_URL=https://coolify.infra.mad4b.com/mcp`
- `UPSTREAM_AUTHORIZATION_HEADER=Bearer <read-only Coolify token>` **secret**, not in Compose, GitHub, shell history, logs or this document
- `OIDC_ISSUER_URL`: existing or newly configured OIDC issuer; the proxy does not create an identity provider
- `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`: provider registration, encrypted deployment secrets
- `TOKEN_SIGNING_SECRET`: fresh cryptographic secret, deployment-only
- `REDIS_URL`: **dedicated staging Redis or isolated logical database** (do not reuse existing Coolify data DB or change its service configuration)
- `PROD_MODE=true`; use upstream defaults for PKCE and replay checking

The upstream image can be deployed independently under Coolify as a Docker service. Pin `ghcr.io/babs/mcp-auth-proxy:2.1.0` or, preferably, a verified SHA-256 image digest after inspecting the release supply-chain attestations. No rebuild/fork of the Coolify app image is necessary.

**Important:** Never paste actual secrets into GitHub repository variables, README, UI screenshots, or conversation. Configure Coolify environment secrets through its secret controls.

## Operator acceptance path (after isolated deployment)

1. GET `/.well-known/oauth-authorization-server` on proxy base → valid OAuth JSON metadata.
2. GET `/.well-known/oauth-protected-resource/mcp` and anonymous `POST /mcp` → protected-resource challenge; no backend data.
3. Complete OAuth login via ChatGPT → obtain scoped adapter token.
4. Through the **ChatGPT connector**, `initialize` and `tools/list` → native Coolify tool catalog.
5. Through connector, call `get_current_team` and `get_infrastructure_overview` using the **read-only** upstream token; verify scope.
6. Verify direct Coolify `https://coolify.infra.mad4b.com/mcp` with Sanctum token still works unchanged.
7. Any failure → disable/remove **adapter service only**, not Coolify, Docker daemon, Traefik, Firewall V2, or backup jobs.

## Readiness and blockers

- Native Coolify MCP: proven HTTP 200 initialize/tools/list, 45 tools.
- OSS proxy selection: researched; code and version identified, **not yet audited or deployed**.
- OIDC provider client credentials: **not configured/verified**.
- Staging endpoint/Redis: **not deployed**.
- ChatGPT OAuth connection: **not yet tested**.

Do not merge or deploy simply because documentation and smoke scripts exist.
