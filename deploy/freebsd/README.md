# playground sandbox-MCP on FreeBSD (server-side hosting)

Runs the sandbox provider *on* the jail host (`ai.bultmann.eu`, FreeBSD
15.1): `playground mcp-http --backend jail --jail-local` bound to
loopback, with per-tenant bearer tokens. The jail backend executes
`sudo -n zfs/jail/jexec ...` directly ([`LocalRunner`], no ssh hop);
sessions are ZFS clones of `aitemp/playground/template@base`, jails are
`playground-*`, both strictly namespaced.

Two hosting modes exist and stay interchangeable:

| mode | where the binary runs | transport to the jail host |
|---|---|---|
| Mac-driven (default) | operator's machine | `SshRunner` (`ssh` + `sudo -n`) |
| server-side (this doc) | the jail host itself | `LocalRunner` (direct spawn) |

## TRUST BOUNDARY (do not relitigate casually)

- **No pile ever goes to this server.** It is a shared machine; jail
  sessions are pile-less by design (`src/sandbox/jail.rs` module docs).
  The `pile_host_path` tool argument is logged and ignored.
- The server only ever touches `playground-*` jails and datasets under
  `aitemp/playground`. The `repo-*`/`trible*` jails and datasets on the
  same box are out of bounds.
- The HTTP server binds `127.0.0.1` and speaks plain HTTP. Anything
  beyond loopback is a deferred decision (see the end of this doc).

## Build (on the server)

The crate has path dependencies on sibling repos, so the build tree is
the standard sibling-repo layout. The server profile skips the GUI/faculties
stack entirely:

```sh
# one-time toolchain: rust 1.96 as of 2026-07; rsync for the source sync
sudo pkg install -y rust rsync

# sync the source closure from the operator machine — NOTE the
# --exclude='*.pile': NO pile file may land on this server, ever.
# (Manifests of optional path deps must exist for cargo resolution even
# though they are not built: GORBIE, mary, cubecl-fork, gorbie_commonmark.)
rsync -a --delete \
  --exclude 'target/' --exclude '.git/' --exclude '.claude/' \
  --exclude '*.pile' --exclude 'models/' --exclude 'weights/' \
  --exclude '__pycache__/' \
  playground faculties triblespace-rs GORBIE mary cubecl-fork gorbie_commonmark \
  ai.bultmann.eu:playground-build/

# verify the pile rail held before anything else:
ssh ai.bultmann.eu "find playground-build -name '*.pile'"   # must print nothing

cd ~/playground-build/playground
cargo build --release --locked --no-default-features --features mcp-http
```

`--no-default-features --features mcp-http` builds the MCP provider +
HTTP transport only: no eframe/wgpu (diagnostics), no faculties→mary/Burn.
Measured on the box (32 cores, cold build incl. crates.io downloads,
2026-07-11): 1m21s wall / ~9.8 min CPU; the source rsync itself was ~9 s
for 51 MB. Warm rebuilds: seconds. Binary: 9.1 MB dynamic ELF.

## Install

```sh
cd ~/playground-build/playground
sudo install -o root -g wheel -m 0755 target/release/playground /usr/local/bin/playground
sudo install -o root -g wheel -m 0555 deploy/freebsd/playground_mcp /usr/local/etc/rc.d/playground_mcp

# token store: root-only directory, 0600 file (mint writes it 0600 itself)
sudo mkdir -p -m 0700 /usr/local/etc/playground
# `user create` provisions the tenant's persistent jail AND mints its token.
# --jail-local runs zfs/jail directly on this host (no ssh hop).
sudo playground user create <label> --backend jail --jail-local \
  --tokens /usr/local/etc/playground/tokens.json
# the token is printed exactly once — hand it to the tenant out of band

sudo sysrc playground_mcp_enable=YES
sudo service playground_mcp start
```

The service runs as root (jail(8)/zfs(8) need it; `sudo -n` is a
pass-through for root). It binds `127.0.0.1:8377` and logs to
`/var/log/playground_mcp.log`. Restart-on-crash via `daemon -R 5`.

Note the trade-off this mode makes on a shared machine: the token store
now lives on the server (root-readable only, but root includes anyone
with root there). Tolerable precisely because sessions are pile-less —
a stolen token buys an empty jail, not memory.

## Verify (loopback round-trip)

```sh
TOK=<token>
H='Content-Type: application/json'
A="Authorization: Bearer $TOK"

# initialize — note the mcp-session-id response header
SID=$(curl -si -H "$A" -H "$H" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  http://127.0.0.1:8377/mcp | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:"{print $2}')

# open a jail session (pile path is ignored on this backend — pile-less)
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_session","arguments":{"pile_host_path":"/nonexistent/pile-less"}}}' http://127.0.0.1:8377/mcp

# run something in the jail (session id = playground-<tenant>)
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"session":"playground-<label>","command":"uname -a; id; pwd"}}}' http://127.0.0.1:8377/mcp

# tear it down
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"close_session","arguments":{"session":"playground-<label>"}}}' http://127.0.0.1:8377/mcp

# leftovers must be zero:
jls name | grep '^playground-' || echo "no playground jails"
zfs list -r aitemp/playground   # only the parent + template must remain
```

Interim remote use without any exposure decision: an SSH port-forward
(`ssh -L 8377:127.0.0.1:8377 ai.bultmann.eu`) gives an operator with an
ssh account the full service on their own loopback.

## DEFERRED — decisions that need JP (do not improvise these)

1. **Internet exposure.** Today: loopback only, nothing else installed.
   The options, in increasing exposure order:
   a. keep loopback + per-operator ssh forwards (works today, zero new
      surface);
   b. bind the ZeroTier address (`sysrc playground_mcp_bind=<zt-ip>:8377`)
      — reachable by ZeroTier members only; still plain HTTP, so tokens
      transit the overlay unencrypted-at-the-HTTP-layer;
   c. public: needs a TLS-terminating reverse proxy (nginx/caddy via
      pkg), a DNS name, a cert story, and a firewall pass — none of
      which exist on the box today. `--allow-origin` values must be set
      if any browser client appears.
2. **Real tenants.** Only `test-tenant` exists. Colleague tenant names,
   who mints, and how tokens are delivered (and rotated/revoked) are
   open. Token revocation currently = edit the store + restart.
3. **Template package set.** The template is stock FreeBSD 15.1 base
   (empty /usr/local). What colleagues' jails should ship (git,
   compilers, python?) is a product decision; rebuild additively (new
   snapshot), never destroy `@base` while clones may exist.
4. **Jail resource limits.** Sessions currently have no rctl/zfs-quota
   caps.
5. **Piles.** Permanently out of scope for this server until the
   encrypted-replica or shared.pile-only design is decided
   (`src/sandbox/jail.rs` trust-boundary docs). Nothing in this
   deployment may move a pile toward the machine.
