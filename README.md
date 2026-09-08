# Playground — the sandbox-MCP provider

`playground` provisions isolated, stateful shells and exposes them over the
[Model Context Protocol](https://modelcontextprotocol.io/). It is the exec
transport an MCP client (e.g. an agent runtime) calls to run shell commands in
an isolated sandbox. This crate is only the provider.

## The MCP surface

Because a shell is **stateful** (cwd, env, running processes), the surface is a
small session model, exposed as eight tools:

- `open_session` — open or reattach an already-provisioned tenant sandbox and
  return a session id. Storage placement is never selected over MCP.
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

One tenant may run eight jobs concurrently, within a global active limit of
32. Retention remains bounded to eight handles per tenant and 64 globally.
Capacity eviction only removes a terminal job after a poll returned its final
page; starting a new command cannot evict another command's unread tail. If
every retained handle is still running or unread, submission is refused.
The one-hour terminal expiry still applies even to unread outcomes.

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
  `self.pile` + an operator-preinitialized shared `shared.pile`) are mounted in
  append-only (Model B) — see the pile-provisioning section in
  `src/sandbox/jail.rs`. Tenant creation refuses to proceed if the shared pile
  is absent and never creates or replaces that org-wide policy state.
  Background jobs are enabled only for the root, jail-local FreeBSD deployment,
  where cancellation has a descendant-reaping proof; remote SSH and Lima retain
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

### Native Faculties gateway (opt-in)

`mcp-http --faculties-workers /etc/playground/workers.json` serves the native
Faculties catalogue through the same authenticated origin-root endpoint. The
default remains the eight sandbox tools; this option **selects** the worker
catalogue, not a union of the two. It does not create a `/faculties` route or
another OAuth database. Keep the existing `--public-url`, OAuth state, and
account `--backend jail`/`lima` identity when testing a catalogue switch.

The operator-owned manifest names already-running workers:

```json
{
  "workers": [
    { "tenant": "alice", "address": "127.0.0.1:8401", "token_file": "alice-worker.key" },
    { "tenant": "bob", "address": "127.0.0.1:8402", "token_file": "bob-worker.key" }
  ]
}
```

Tenant labels match authenticated accounts exactly. Each address must be a
distinct literal loopback address with a nonzero port; token paths resolve
relative to the manifest. Token files contain 32–1024 ASCII bearer characters,
with an optional final newline. Protect them and the manifest as operator
configuration. Mappings and internal tokens are read once; rotation requires
restarting the gateway. Public token/OAuth revocation still takes effect live
on subsequent requests, including requests in an existing MCP session.

Start each **native HTTP-capable** Faculties process separately in its tenant's
fixed filesystem and environment, with its own pile, signer, credentials, and
internal token. For example, *inside Alice's existing jail*:

```sh
faculties mcp --pile /pile/self.pile --key /pile/self.key \
  --http-listen 127.0.0.1:8401 --http-token-file /etc/faculties/worker.key
```

The gateway reads the same internal token through its operator-controlled copy
or mount. No account bearer, cookie, caller-selected pile/key, or environment
is forwarded. The worker's own configured persona/collection capabilities are
provisioning facts. A mounted shared pile is **not** automatically included in
the native catalogue's configured pile; shared-pile tools/access remain an
explicit design/provisioning choice. In particular, never use an operator's
personal pile or shared operator signer for all coworkers.

Gateway mode skips all sandbox construction, build, reattach, and shutdown
operations. It does not supervise workers. A missing tenant mapping returns
503; it never falls back to the sandbox catalogue or another account. Jails
that inherit networking share loopback, so loopback alone is not an account
boundary: keep the internal bearer mandatory and tokens private to their
respective worker contexts. Other network layouts need an explicit secure
internal transport; this initial mode intentionally accepts only loopback.

The JSON request/response bodies pass through byte-for-byte, retaining native
image, audio, and embedded-resource content and their order. The gateway
substitutes the internal bearer and wraps each upstream MCP session in a
tenant-owned public session ID. Explicit DELETE closes both. An upstream 404
discards the public wrapper; the client must initialize again. Both sides'
session bounds/idle expiry apply. At a gateway per-tenant cap, initialization
is refused rather than evicting a still-live worker session. Abandoned upstream
sessions expire at the worker, including after a gateway restart or an
initialize whose response was lost.

Internal HTTP makes one direct socket request: no DNS, environment proxy,
redirect, or retry. A failed/timed-out response after sending has an **unknown
execution outcome**; it does not mean a side-effecting tool was cancelled or
is safe to repeat. Worker 401/403/redirects become a gateway configuration error,
not a second login flow. This mode supports the native JSON/202 transport, not
SSE or resumable streams. Clients must still send the MCP media/protocol headers
required by the native worker.

The gateway admits at most 16 exchanges, retaining admission while buffered
response bytes are still held for delivery. Request size uses
`--max-body-bytes` (1 MiB default); response size is capped at 8 MiB. Body reads
have 30 seconds, connecting has 5 seconds, and a worker exchange has 10 minutes.
These are gateway bounds, not limits on native model allocations or promises
to cancel accepted work. A slow output reader may delay graceful shutdown;
workers remain externally supervised and are not stopped by this gateway.

This is a source-level integration option, **not a public deployment receipt**.
Automatic jail worker installation/supervision and a deliberate public
catalogue choice still precede a hosted rollout. The existing FreeBSD service
can pass the option through `playground_mcp_args`; its current deployment
defaults are unchanged.

## Users & tokens (for `mcp-http`)

A **user** is a tenant: its persistent sandbox plus the bearer token that
authorizes it. `user create` provisions the tenant's sandbox and mints its
token into a JSON store bound to that tenant + backend. Jail allocates faculty
storage itself; Lima requires the operator to name an existing durable
`self.pile` explicitly, with an existing `self.key` beside that lexical path.
Lima resolves both real files independently, hardlinks only those two inodes
into private per-tenant mount views, and exposes them as
`PILE=/pile/self.pile` and `TRIBLESPACE_KEY=/identity/self.key`, and exports the
tenant label itself as `PERSONA`. The token is printed once, then only lives in
the store:

```bash
cargo run --manifest-path playground/Cargo.toml -- \
  user create alice --backend jail --tokens ./tokens.json

cargo run --manifest-path playground/Cargo.toml -- \
  user create alice --backend lima --faculty-pile /srv/alice/self.pile \
  --tokens ./tokens.json
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

The native-worker integration smoke requires a separately built Faculties
binary with HTTP support. It runs both real executables on ephemeral loopback
ports and verifies discovery without creating tenant storage:

```sh
FACULTIES_HTTP_BINARY=/absolute/path/to/faculties \
  cargo test --test cli_gateway -- --ignored --nocapture
```
