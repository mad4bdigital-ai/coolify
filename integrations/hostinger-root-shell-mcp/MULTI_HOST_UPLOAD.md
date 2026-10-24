# Multi-account hosting uploads — draft integration

Extends PR #3 infrastructure registry with an explicitly target-scoped, resumable
MCP transfer. Designed for uploads from ChatGPT without executing files or
installing WordPress plugins.

## MCP API

1. `hosting_upload_begin(target_id, size, sha256)`
2. `hosting_upload_chunk(target_id, transfer_id, offset, content_base64)` (maximum decoded chunk 384 KiB)
3. `hosting_upload_status(target_id, transfer_id)`
4. `hosting_upload_commit(target_id, transfer_id)`

Limits: 32 MiB per file. Transfers bind to a single registered target and are
staged in an isolated named Docker volume under `/data/hosting-uploads`. No
user-provided destination paths, SSH commands, addresses or usernames.

## Remote destination and prerequisites

- Only `enabled: true` registry entries with `kind: ssh|sftp` and an enrolled username qualify.
- The remote account needs an independently verified SSH host-key pin,
  `known_hosts_verified`, and its pre-enrolled private key; candidate pins are **not accepted**.
- The remote hosting user must pre-create `mad4b-quarantine` in its SFTP default directory
  and have write permission there. Do not auto-create or guess document roots.
- Files are stored as `mad4b-quarantine/<sha256>.bin` through SFTP with a temporary
  name and rename. No WordPress installation/publication.
- Upload visibility does not establish remote login readiness. Run
  `authenticate_registered_ssh(target_id)` before a live transfer.
- Each hosting account remains separate: no cross-target continuation or reusing
  transfer IDs across accounts.

## Authentication boundary

The Shell MCP server runs behind its existing OAuth gateway. Access to a
connected Shell MCP is sufficient to call these upload tools, but it does not
grant access to other remote accounts: the registry and enrolled pinned SSH
identity must also authorize the requested target.

Native Coolify token support belongs to the Coolify MCP integration (PR #1),
not this Shell MCP gateway; do not forward a Coolify bearer as a hosting password.

## Deployment

**Not deployed by this PR.** Create a test deployment from this branch and
enroll the desired accounts independently. Validate each host key with trusted
out-of-band evidence and pre-provision the remote quarantine directory.
Reusing the existing Root Shell service without an acceptance window may
restart production connections.

## Tests

`PYTHONPATH=. python -m unittest discover -s tests -v`

Includes tests for registered-target enforcement, no cross-host transfer,
offset/chunk bounds, digest rejection before network calls, and a mocked SFTP
commit. Real multi-host upload is pending verified binding and explicit
per-target operational acceptance.
