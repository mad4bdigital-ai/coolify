# Official Hostinger OAuth MCP worker — staging only

This optional isolated worker uses the official `@hostinger/mcp@3.4.0` package in **stdio** mode, not HTTP. It is not started by the running Registry Compose stack and does not expose a network port. Hostinger explicitly says local OAuth is **not available with `--http`**, and that `HOSTINGER_API_TOKEN` bypasses OAuth.

## Authentication boundary

1. Manually create an isolated state directory on the VPS (ownership 10001:10001, mode 0700).
2. Build with `docker compose -f compose.oauth.yaml --profile manual-oauth build`.
3. Complete OAuth interactively using `docker compose -f compose.oauth.yaml --profile manual-oauth run --rm hostinger-cloud-startup-oauth --login` and a **secure browser callback route**, which must be validated before attempting authentication from a remote headless VPS. Never share the browser authorization URL publicly or expose the ephemeral callback listener. The CLI may require a locally running browser or a secure SSH port forward.
4. The `HOME/.config/hostinger-mcp/credentials.json` file holds OAuth secrets. Keep it out of Git, logs and command responses. Never copy the existing ChatGPT Secondary tokens into it.
5. After operator sign-in, a separate allowlisted, read-only stdio client bridge is needed before Registry can call tools. **Not implemented in this stage.** Do not use Hostinger's `execute` for arbitrary operations.
6. Exclude Hostinger Email completely from the migration workflow.

## Safety

No write calls, DNS changes, database export, or live account registration is performed by adding this worker. The operator must validate callback mechanics before deployment and explicitly approve any addition to Registry execution tools. OAuth account selection must be verified to be Cloud Startup.
