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

## TRUST BOUNDARY (Model B — host-owned per-tenant piles)

- **The caller-supplied pile never goes to this server.** The
  `pile_host_path` tool argument is logged and ignored. Instead each tenant
  jail gets its OWN host-owned, server-born piles, provisioned on this box
  under `--jail-pile-root` (default `/aitemp/playground/piles`): a per-tenant
  `self.pile` (seeded from a generic `bootstrap.pile` — no operator memory)
  single-file-mounted at guest `/pile/self.pile`, plus one org-wide
  `shared.pile` single-file-mounted at guest `/shared/shared.pile`. Both are
  `chflags sappnd` append-only and decoupled from the jail lifecycle
  (`destroy_session` never deletes them). A stolen tenant token thus reaches
  only that tenant's own seeded pile and the shared org pile — never the
  caller-supplied pile, and never any other pile on the host.
- **Only the pile FILES are mounted — never a host directory (2026-07-24).**
  Each pile is a single-FILE nullfs mount (the host pile file onto a pre-created
  empty target file inside the jail's own ZFS clone), so the jail's `/pile` and
  `/shared` are the jail's OWN clone dirs, not writable host directories. A
  tenant (root in its jail) therefore cannot create sibling entries in a host
  dir — closing the symlink confused-deputy class where a pre-placed
  `shared.pile.<jail>.tmp` symlink tricked the privileged provision `cp` into
  overwriting a chosen host file. The bootstrap `cp` also stages only into a
  host-PRIVATE `0700` dir (`--jail-pile-root`'s sibling `…/staging`, never
  mounted into a jail) and publishes with a no-follow / create-only hardlink,
  so the privileged copy can never follow a tenant-planted symlink. FreeBSD
  nullfs single-file mounts and concurrent multi-writer append were verified on
  the deploy host's 15.1 kernel.
- **Append-only is enforced by the host, not trusted to the guest.** `chflags
  sappnd` lets a jailed process `O_APPEND` but not `O_TRUNC`/unlink/rename, so a
  buggy or stale tool cannot truncate a pile (the 2026-07-03 truncation class).
  At the current `kern.securelevel=-1` this blocks ACCIDENTAL truncation only; a
  deliberate jail-root truncation still needs `securelevel>=1` (then the same
  flag is malicious-proof with no code change — the deploy-hardening step).
- The server only ever touches `<prefix>-*` jails and datasets under its
  configured `--jail-dataset-parent` (default `aitemp/playground`). The
  `repo-*`/`trible*` jails and datasets on the same box are out of bounds.
- The HTTP server binds `127.0.0.1` and speaks plain HTTP. Anything beyond
  loopback is a deferred decision (see the end of this doc).

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
with root there). Under Model B a stolen tenant token reaches that
tenant's own server-born `self.pile` (seeded, append-only) and the shared
`shared.pile` — its own data and the org-shared pile, never the caller's
pile or any other pile on the host. Append-only (`chflags sappnd`,
malicious-proof once `securelevel>=1`) bounds the damage to appends, not
truncation.

## Verify (loopback round-trip)

```sh
TOK=<token>
H='Content-Type: application/json'
A="Authorization: Bearer $TOK"

# initialize — note the mcp-session-id response header
SID=$(curl -si -H "$A" -H "$H" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  http://127.0.0.1:8377/mcp | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:"{print $2}')

# open a jail session (the caller pile_host_path is logged + ignored; the jail
# uses its own server-born self.pile at guest /pile, seeded on `user create`)
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_session","arguments":{"pile_host_path":"/ignored/by/jail-backend"}}}' http://127.0.0.1:8377/mcp

# run something in the jail (session id = playground-<tenant>); also prove the
# pile mounts are live and append-only (append lands, truncate is refused)
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"session":"playground-<label>","command":"uname -a; id; ls -la /pile /shared; echo APPEND-OK >> /pile/self.pile && echo appended; (: > /pile/self.pile) 2>/dev/null || echo truncate-blocked"}}}' http://127.0.0.1:8377/mcp

# tear it down
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"close_session","arguments":{"session":"playground-<label>"}}}' http://127.0.0.1:8377/mcp

# leftovers must be zero (jail + clone), but host piles SURVIVE (Model B):
jls name | grep '^playground-' || echo "no playground jails"
zfs list -r aitemp/playground   # only the parent + template must remain
ls /aitemp/playground/piles     # per-tenant self.pile dirs + shared/ persist
```

Interim remote use without any exposure decision: an SSH port-forward
(`ssh -L 8377:127.0.0.1:8377 ai.bultmann.eu`) gives an operator with an
ssh account the full service on their own loopback.

## Resource limits (repair #4 — bound every tenant-controllable resource)

The server enforces these bounds itself (no host reconfig needed). Tunable via
`mcp-http`/`user create` flags; sane defaults shown.

- **Output cap.** Each `exec`'s stdout and stderr are capped at **16 MiB** per
  stream and the jail process (and its tree) is **killed** the instant either
  crosses it — the tenant sees `output truncated at N bytes … process killed`.
  A runaway producer (`cat /dev/zero`) cannot make the daemon accumulate
  unbounded memory upstream of any proxy response cap.
- **Timeout ceiling.** A caller may request a smaller `timeout_ms`, never a
  larger one: the effective timeout is `min(requested, 30 min)`. On expiry the
  server-side `timeout(1)` reaps the jail process tree (exit 124); on a
  local-side kill or an output-cap kill the backend additionally
  `jexec <jail> kill -TERM/-KILL -1` to reap any background/orphan processes
  inside the jail.
- **Admission control.** Per-tenant (`--max-concurrent-execs-per-tenant`,
  default **4**) and global (`--max-concurrent-execs`, default **32**)
  concurrency caps around `exec`, with a bounded wait queue
  (`--max-queued-execs`, default **64**) — past the queue, admission is refused
  with `sandbox busy`. No single tenant can occupy every blocking worker; the
  global cap protects the daemon.
- **Storage quotas (ZFS).** Each per-tenant clone gets a
  `refquota` (`--jail-clone-refquota`, default **10G**) so a tenant cannot fill
  the host pool via its own dataset; the pile-root dataset gets a global `quota`
  (`--jail-pile-quota`, default **50G**) so pile writes cannot fill the pool
  either. `0`/empty disables. Set at provision, before the jail starts. NOTE:
  the pile-root quota is applied only when `--jail-pile-root` is an actual ZFS
  dataset mountpoint (a plain directory is skipped with a log line — create a
  dataset at the pile root for the bound to bite). Per-tenant pile isolation
  (a dataset per tenant pile dir) is a noted follow-up; the global pile quota
  already stops the fill-the-pool attack.
- **Request body limit.** The HTTP body is explicitly capped
  (`--max-body-bytes`, default **1 MiB**) — a stated policy, not axum's silent
  2 MiB default. Oversized bodies get `413` before buffering.

### RACCT/RCTL — MUST be enabled before public exposure

RACCT/RCTL is OFF unless a host explicitly enables it (FreeBSD's default), so
verify it per host before exposure — kernel per-jail resource accounting is not
something to assume. The server does **not** assume it: the ZFS quotas, output
cap, timeout ceiling, and admission caps above hold regardless. But CPU, RAM,
process-count, and FD pressure *inside* a jail reach host-global resources until
RACCT is on. Before any public / mutually-untrusted exposure, enable it and the
per-jail rules:

```sh
# 1. Turn on kernel resource accounting (needs a reboot to take effect).
sudo sysrc -f /boot/loader.conf kern.racct.enable=1
sudo shutdown -r now   # RACCT is a loader tunable; a live sysctl set is not enough

# 2. After reboot, confirm it is on:
sysctl kern.racct.enable    # must print: kern.racct.enable: 1
```

Once RACCT is on, the server applies these per-jail `rctl(8)` rules at each
provision automatically (guarded behind the runtime `kern.racct.enable` probe —
a no-op while it is off, live with no code change once on):

```
jail:<name>:maxproc:deny=512      # fork-bomb bound
jail:<name>:nthr:deny=2048        # thread bound
jail:<name>:openfiles:deny=8192   # FD-exhaustion bound
jail:<name>:memoryuse:deny=2G     # resident RAM bound
jail:<name>:swapuse:deny=1G       # swap bound
jail:<name>:pcpu:deny=90          # CPU-percent bound (signals the process)
```

To verify after a provision (RACCT on): `sudo rctl -h jail:<name>` lists the
live rules. `destroy_session` removes them (`rctl -r jail:<name>`). To apply
rules to already-running jails without reprovisioning, add them by hand with the
lines above.

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
4. **Jail resource limits.** The server now enforces output/timeout/
   admission/ZFS-quota bounds itself (see "Resource limits" above). The
   remaining operator action is enabling **RACCT/RCTL** on the host
   (`kern.racct.enable=1` + reboot) so the per-jail CPU/RAM/maxproc/FD
   `rctl` rules bite — required before any public exposure. Exact steps and
   rules are in the "RACCT/RCTL" subsection above.
5. **Bootstrap seed contents.** Model B seeds each tenant `self.pile` and
   the `shared.pile` from `--jail-bootstrap-pile`. That seed MUST be a
   generic bootstrap with no operator memory — the shipped
   `faculties/bootstrap.pile` is the colony onboarding tour and is NOT
   generic (it still carries persona references), so it needs scrubbing
   before it can be the seed here. Who curates the seed, and how the
   `shared.pile` is synced to/from the org, are open.
