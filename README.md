# Playground — the sandbox-MCP provider

`playground` provisions isolated, stateful shells and exposes them over the
[Model Context Protocol](https://modelcontextprotocol.io/). It is the **sandbox
layer** (layer 3 of 4: Substrate / Verbs / **Sandbox** / Drive) — the exec
transport a driver (the `drive` crate, a realtime cognition loop, or
any MCP client) calls to run shell commands in a sandbox.

The cognition machinery — the model loop, context assembly, memory — lives in
the `drive` crate now. This crate is only the provider.

## The MCP surface

Because a shell is **stateful** (cwd, env, running processes), the surface is a
session model, exposed as three tools:

- `open_session` — provision a sandbox bound to a pile (append-only) and a
  tenant, and return a session id.
- `exec` — run a shell command inside an open session (cwd/env persist across
  calls).
- `close_session` — tear the sandbox down.

Every session a connection opens is torn down when the connection ends (client
EOF/disconnect) or the process is signalled (SIGINT/SIGTERM), so a crashed or
disconnected client can never leak a VM or jail.

## Backends

- **Lima** (`--backend lima`, default): a local Lima VM per session on a macOS
  host. The pile is mounted append-only into the session.
- **Jail** (`--backend jail`): a FreeBSD jail per session on a remote host over
  SSH (or locally with `--jail-local`). Pile-less v1 — see the trust boundary
  in `src/sandbox/jail.rs`.

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

## Tokens (for `mcp-http`)

Bearer tokens are minted into a JSON store and bound to a tenant + backend. The
token is printed once, then only lives in the store:

```bash
cargo run --manifest-path playground/Cargo.toml -- \
  token mint --tenant alice --backend lima --tokens ./tokens.json
```

`PLAYGROUND_MCP_TOKENS` sets the default store path for both `token mint` and
`mcp-http`.

## Deployment

`deploy/freebsd/` holds the FreeBSD server profile: an rc.d service that runs
`mcp-http --backend jail --jail-local` with `--no-default-features
--features mcp-http` (no Burn/wgpu stack). See `deploy/freebsd/README.md`.

## Build profiles

```bash
cargo build                       # default: mcp + mcp-http + token
cargo build --no-default-features # stdio mcp only (no tokio/axum)
cargo test
```
