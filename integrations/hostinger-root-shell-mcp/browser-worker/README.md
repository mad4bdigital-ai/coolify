# hPanel Browser Worker — read-only prototype

This is an optional worker behind the existing registry-infra-mad4b MCP, not a new MCP connector.

The worker uses a separate persistent Chromium profile, not the Webtop profile or Hostinger OAuth token. It is published only on VPS loopback port 13871. The profile must be enrolled through a controlled browser login before authenticated browsing can work.

The session tool checks navigation status. Website extraction fails closed with SELECTOR_NOT_CERTIFIED until real hPanel DOM selectors are verified. It must not claim a list of sites based on guessed selectors.

No write tools, credential import, browser-debug ports or public browser access are enabled. Do not merge or deploy as production-ready before image, session and behavior testing.
