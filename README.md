# Playground — the sandbox-MCP provider

`playground` provisions isolated, stateful shells and exposes them over the
[Model Context Protocol](https://modelcontextprotocol.io/). It is the exec
transport an MCP client (e.g. an agent runtime) calls to run shell commands in
an isolated sandbox. This crate is only the provider.

## The MCP surface

Because a shell is **stateful** (cwd, env, running processes), the surface is a
small session model, exposed as eight tools:

- `open_session` — provision a sandbox bound to a pile (append-only) and a
  tenant, and return a session id.
- `exec` — run a short shell command and wait for its result.
- `read` — read up to 3 MiB from a sandbox file without byte loss; textual
  files are returned as text, images as MCP image content, and other binary
  media as MIME-labelled embedded resources.
- `write` — replace a sandbox file with one complete text or standard-base64
  payload of up to 3 MiB. The write directly truncates and overwrites its
  target; it is not transactional, so a command failure may leave a partial
  file.
- `job_exec` — start a long-running command and return a job id immediately.
- `job_poll` — read retry-safe pages of incremental stdout/stderr and terminal
  state.
- `job_cancel` — idempotently request cancellation of one job.
- `close_session` — release this handle; the persistent sandbox remains.

Permanent sandbox destruction is deliberately operator-only (`user destroy`),
not an MCP tool: several agents may share one tenant, and one connection must
not be able to invalidate every other connection's workspace.

The HTTP server's request-body ceiling remains 1 MiB by default, including the
JSON-RPC envelope and base64 expansion. Consequently, public HTTP writes are
smaller than the tool's 3 MiB byte ceiling unless the operator raises
`--max-body-bytes`; stdio calls can use the full tool limit.

`exec` and `job_exec` retain the sandbox's login profile and session defaults.
File tools deliberately run through a non-login shell with absolute utility
paths so profile output or stdin reads cannot corrupt their protocol payloads;
an omitted file-tool `cwd` resolves relative paths from `/` on both backends.

Synchronous and background commands use one bounded execution kernel. Jobs are
kept in memory for reconnecting clients and expire after one hour; a daemon
restart loses their handles. Provider shutdown cancels and reaps live jobs
before detaching sandboxes. HTTP transport sessions are deliberately separate
from persistent sandbox and job lifetimes.

On the root-local FreeBSD path, losing the kernel descendant-reaping proof is
a process-fatal invariant violation: the provider exits nonzero and stays down
for explicit operator recovery. Ordinary command, SSH, and backend errors are
per-job results and create no sticky tenant state.

`job_poll` returns `next_cursor`, `has_more`, and (if a slow consumer fell
behind the bounded ring) `gap` plus `dropped_bytes`. Advance to `next_cursor`
and keep polling until the job is terminal **and** `has_more` is false. Reusing
the old cursor is safe and replays the same retained chunks.

## Backends

- **Lima** (`--backend lima`, default): a local Lima VM per session on a macOS
  host. The pile is mounted append-only into the session.
- **Jail** (`--backend jail`): a FreeBSD jail per tenant on a remote host over
  SSH (or locally with `--jail-local`). Host-owned per-tenant piles (a seeded
  `self.pile` + a shared `shared.pile`) are mounted in append-only (Model B) —
  see the pile-provisioning section in `src/sandbox/jail.rs`. Background jobs
  are enabled only for the root, jail-local FreeBSD deployment, where
  cancellation has a descendant-reaping proof; remote SSH and Lima retain
  synchronous `exec` and reject `job_exec`.

## Serving

Serve over stdio (JSON-RPC 2.0), operator-local and unauthenticated:

```bash
cargo run --manifest-path playground/Cargo.toml -- mcp
cargo run --manifest-path playground/Cargo.toml -- mcp --backend jail --jail-local
```

Serve over Streamable-HTTP with per-sandbox bearer-token auth (feature
`mcp-http`, on by default) — the multi-tenant, internet-facing transport:

```bash
cargo run --manifest-path playground/Cargo.toml -- mcp-http --tokens ./tokens.json
```

Bind is loopback by default; internet exposure is expected to go behind a
TLS-terminating reverse proxy (this server speaks plain HTTP only). See
`src/mcp_http.rs` for the protocol and auth model.

## Users & tokens (for `mcp-http`)

A **user** is a tenant: its persistent sandbox plus the bearer token that
authorizes it. `user create` provisions the tenant's sandbox (jail backend) and
mints its token into a JSON store bound to that tenant + backend. The token is
printed once, then only lives in the store:

```bash
cargo run --manifest-path playground/Cargo.toml -- \
  user create alice --backend jail --tokens ./tokens.json
```

The first jail provision also creates one stable person in the shared pile's
relations graph, labelled `<tenant> assistant`, and exports that same label as
`PERSONA` in every login shell. Its explicit person id is derived from the
unsanitised tenant label, so retries after a partial provision and later
destroy/recreate cycles converge on the same identity rather than minting a
new one. Reconnects and daemon restarts reuse the persisted profile and pile;
they do not perform identity setup again. Because relations labels use a
32-byte ShortString, jail tenant labels in this scheme must be at most 22 bytes
and have no leading or trailing whitespace.

Other `user` verbs: `user list` (tenants in the store, annotated live/down),
`user destroy <name>` (tear the sandbox down + drop its tokens), `user token
show <name>`, `user token reset <name>` (revoke + re-mint). Pass
`--oauth-state <path>` to `destroy` or `token reset` to revoke that tenant's
OAuth invites, pending authorization codes, access tokens, and refresh tokens
at the same time; the running daemon observes the change without a restart.
`PLAYGROUND_MCP_OAUTH_STATE` supplies the same path by environment.
`PLAYGROUND_MCP_TOKENS` sets the default static-token store path for the `user`
verbs and `mcp-http`.

## Deployment

`deploy/freebsd/` holds the FreeBSD server profile: an rc.d service that runs
`mcp-http --backend jail --jail-local` with `--no-default-features
--features mcp-http` (no Burn/wgpu stack). See `deploy/freebsd/README.md`.

## Build profiles

```bash
cargo build                       # default: mcp + mcp-http + user
cargo build --no-default-features # stdio mcp only (no tokio/axum)
cargo test
```
