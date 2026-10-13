# Google OIDC staging setup for Coolify MCP OAuth bridge

**Status:** GitHub-ready template only. No Google OAuth client, Redis service, proxy, DNS or ChatGPT connector has been provisioned.

## Selection

Use **Google OpenID Connect** rather than maintaining Keycloak / Authentik. Google's discovery URL is `https://accounts.google.com/.well-known/openid-configuration`; issuer is `https://accounts.google.com`. The [babs/mcp-auth-proxy v2.1.0](https://github.com/babs/mcp-auth-proxy/releases/tag/v2.1.0) handles the *outward-facing* ChatGPT OAuth 2.1 + PKCE and delegates interactive sign-in to Google OIDC.

This is a temporary **testing** solution. Google's OAuth consent-screen **Testing** state restricts access to manually added test users, but some non-basic OAuth grants in Testing mode expire after seven days. Confirm exact Google rules and user access before relying on repeated sign-ins. The proxy version selected does **not** provide a built-in email allowlist in its documented config; do not change the Google consent screen to unrestricted Production without introducing a strong IdP-side authorization policy or choosing a proxy that enforces identities.

## Google Cloud Console setup — no credentials in GitHub

1. In Google Cloud Console → Google Auth Platform, create/select a test-only project and configure OAuth branding/consent. Choose audience **External**, publishing state **Testing** and add only authorized Google accounts as **test users**. Do not make the application public.
2. Create an OAuth client with application type **Web application**, display name `mad4b-coolify-mcp-staging`.
3. Under **Authorized redirect URIs**, register exactly:
   `https://YOUR-STAGING-ADAPTER-HOST/callback`.
   This is the upstream proxy's OIDC callback, **not ChatGPT's redirect URL**. Underlying OAuth from ChatGPT uses the adapter's own registration and discovery endpoints.
4. Set `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` privately in the *new staging resource's* Coolify environment. Do not paste the secret in chats, GitHub PRs, workflows, or Google Drive.
5. Use the exact `OIDC_ISSUER_URL=https://accounts.google.com`; keep Google test-user allowlist restricted during staging.

## Minimal Coolify test resource

Use `compose.yaml` in a **new** Docker Compose resource, not the platform's internal Coolify Compose files. It includes `oauth-redis` as an internal-only Redis 7 sidecar for OAuth replay state; no external port and no persistent data volume (all sessions invalidate on rebuild, acceptable for this staging evaluation). **Do not reuse the Coolify application Redis**. The proxy is exposed to the Coolify-managed reverse proxy by its internal port 8080 and a dedicated HTTPS staging domain.

Example non-secret variables:
```text
PROXY_BASE_URL=https://YOUR-STAGING-ADAPTER-HOST
OIDC_ISSUER_URL=https://accounts.google.com
UPSTREAM_MCP_URL=https://coolify.infra.mad4b.com/mcp
```

Required deployment-only secrets:
- `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`: Google test OAuth web client
- `UPSTREAM_AUTHORIZATION_HEADER`: literal `Bearer <read-only-Coolify-Sanctum-token>`
- `TOKEN_SIGNING_SECRET`: strong random 32+ byte signing secret

IMPORTANT: Docker Compose interpolation of `UPSTREAM_AUTHORIZATION_HEADER` happens on resource configuration. Verify that Coolify marks it **secret** and will not show the fully interpolated Compose definition in logs/UI exports. Do not deploy if it will leak. Preferred eventual hardening is file-backed secret binding with a compatible proxy configuration.

## Preflight/acceptance

1. Verify the exact upstream proxy image digest and provenance before deploying. Image tag alone is not content pinning.
2. Verify Google OIDC discovery and that the OAuth client's callback URL matches the externally served proxy callback.
3. Verify DNS/TLS and adapter OAuth authorization-server metadata.
4. Verify anonymous `POST /mcp` cannot reach native Coolify tools.
5. Complete Google login from ChatGPT connector, then use ChatGPT to call `initialize`, `tools/list`, `get_current_team` with **the existing read-only Coolify token**. Native Coolify `/mcp` should stay unchanged.
6. Clean rollback is deleting/disabling this test resource alone.

## Critical constraints

- Do not deploy this template to existing production VPS while in documentation/preflight phase.
- OAuth proof requires a real interactive user sign-in; mock tests only prove implementation mechanics.
- Docker Compose `expose` and internal Redis network are not substitutes for separate staging acceptance of public routing and auth.
- No new control plane, no modifications to 45 native tools, no restart to production Docker, Firewall V2, SSH or backup jobs.
