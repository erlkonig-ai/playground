# playground sandbox-MCP on FreeBSD (server-side hosting)

Runs the sandbox provider *inside* the dedicated `playground` parent jail
(FreeBSD 15.1). Operator-side copy/install examples use `$JAIL_HOST`, but the
running provider has no host transport: `playground mcp-http --backend jail
--jail-local` binds to loopback and executes
`zfs/jail/jexec ...` directly ([`LocalRunner`], no ssh hop; when the daemon is
root it strips the operator-facing `sudo -n` prefix before spawning);
sessions are ZFS clones of
`airoot/jails/playground/jails/template@base`, jails are `playground-*`, and
the parent jail is delegated only that ZFS subtree.

The trusted parent must set `enforce_statfs = 0`. FreeBSD otherwise allows it
to create the nested single-file nullfs mounts but redacts those mounts (and
their FSIDs) from the parent afterward, which prevents exact verification and
safe unmount. This setting applies only to the operator-controlled parent;
tenant child jails retain their restricted/default view.

**Deployment status (2026-07-28): not live.** This directory now contains the
minimal candidate service, Caddy, rotation, configuration, and smoke-test
artifacts. They have not been applied to a host. The public
`mcp.bultmann.eu` AAAA record exists but ports 80/443 currently refuse;
`mcp.bultmann.eu` has no public A record and the local resolver does not return
the public record. `ai.bultmann.eu` points at a different host, has no working
TLS service, and has no playground UI to deploy, so this profile deliberately
does not claim that origin.

Two hosting modes exist and stay interchangeable:

| mode | where the binary runs | transport to the jail host |
|---|---|---|
| Mac-driven (default) | operator's machine | `SshRunner` (`ssh` + `sudo -n`) |
| server-side (this doc) | the jail host itself | `LocalRunner` (direct spawn) |

## TRUST BOUNDARY (Model B — host-owned per-tenant piles)

- **The caller-supplied pile never goes to this server.** The
  `pile_host_path` tool argument is ignored. Instead each tenant
  jail gets its OWN host-owned, server-born piles, provisioned on this box
  under `--jail-pile-root` (`/var/db/playground/piles` in this profile): a
  per-tenant `self.pile` (seeded from a generic `bootstrap.pile` — no operator memory)
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
  host-PRIVATE `0700` dir (`<jail-pile-root>/.staging`, inside the same quota
  dataset but never mounted into a jail) and publishes with a no-follow /
  create-only hardlink,
  so the privileged copy can never follow a tenant-planted symlink. FreeBSD
  nullfs single-file mounts and concurrent multi-writer append were verified on
  the deploy host's 15.1 kernel.
- **Append-only is enforced by the host, not trusted to the guest.** `chflags
  sappnd` lets a jailed process `O_APPEND` but not `O_TRUNC`/unlink/rename, so a
  buggy or stale tool cannot truncate a pile (the 2026-07-03 truncation class).
  A deliberate jail-root truncation requires host `securelevel>=1`; verify that
  value on the target host before exposure.
- The server only ever touches `<prefix>-*` jails and datasets under its
  configured `--jail-dataset-parent`
  (`airoot/jails/playground/jails` in this profile). The
  `repo-*`/`trible*` jails and datasets on the same box are out of bounds.
- The provider binds `127.0.0.1` and speaks plain HTTP. Caddy is the sole public
  listener and sole TLS terminator; the provider port is never exposed.

## Build (on the server)

The provider crate has no sibling-repository path dependencies. Build and
install it on its own; faculties belong in the child-jail template and are a
separate artifact.

```sh
# one-time toolchain: rust 1.96 as of 2026-07; rsync for the source sync
sudo pkg install -y rust rsync

# From the local playground checkout, sync only this repository. NOTE the
# --exclude='*.pile': no operator pile may land on this server, ever.
rsync -a --delete \
  --exclude 'target/' --exclude '.git/' --exclude '.claude/' \
  --exclude '*.pile' --exclude 'models/' --exclude 'weights/' \
  --exclude '__pycache__/' \
  ./ $JAIL_HOST:playground-build/playground/

# verify the pile rail held before anything else:
ssh $JAIL_HOST "find playground-build -name '*.pile'"   # must print nothing

cd ~/playground-build/playground
cargo build --release --locked --no-default-features --features mcp-http
```

`--no-default-features --features mcp-http` builds the MCP provider + HTTP
transport only.
Measured on the box (32 cores, cold build incl. crates.io downloads,
2026-07-11): 1m21s wall / ~9.8 min CPU; the source rsync itself was ~9 s
for 51 MB. Warm rebuilds: seconds. Binary: 9.1 MB dynamic ELF.

## Install

```sh
cd ~/playground-build/playground
sudo install -o root -g wheel -m 0755 target/release/playground /usr/local/bin/playground
sudo install -o root -g wheel -m 0555 deploy/freebsd/playground_mcp /usr/local/etc/rc.d/playground_mcp
sudo pkg install -y caddy curl jq
sudo install -d -o root -g wheel -m 0755 /usr/local/etc/caddy
sudo install -o root -g wheel -m 0644 deploy/freebsd/Caddyfile /usr/local/etc/caddy/Caddyfile
sudo install -d -o root -g wheel -m 0700 /var/log/caddy
sudo install -o root -g wheel -m 0644 deploy/freebsd/playground_mcp.newsyslog.conf \
  /usr/local/etc/newsyslog.conf.d/playground_mcp.conf
sudo install -o root -g wheel -m 0555 deploy/freebsd/smoke.sh \
  /usr/local/libexec/playground_mcp-smoke

# Mutable auth state: root-only directory, 0600 files (writes are atomic).
sudo install -d -o root -g wheel -m 0700 /var/db/playground

# The pile quota only means anything when this path is its own dataset. Before
# running this on an existing host, STOP if /var/db/playground/piles is nonempty
# and migrate it deliberately; never mount a dataset over existing pile data.
sudo zfs create -o mountpoint=/var/db/playground/piles -o quota=50G \
  airoot/jails/playground/jails/piles
sudo zfs list -H -o name,mountpoint,quota airoot/jails/playground/jails/piles

# Install the separately-reviewed, generic bootstrap seed here. Do not use an
# operator/persona self.pile. The child template must also contain the faculty
# binaries intended for tenants before provisioning the first real tenant.
sudo install -o root -g wheel -m 0444 <generic-bootstrap.pile> \
  /var/db/playground/bootstrap.pile

# STOP: before this command, complete the per-tenant RACCT/RCTL procedure below
# from the PHYSICAL host and prove all six name-keyed rules are loaded. Jailed
# root cannot add them after the child exists. `user create` then provisions
# the persistent jail and mints its token; --jail-local uses no ssh hop.
test "$(sysctl -n security.jail.enforce_statfs)" = 0
sudo playground user create <label> --backend jail --jail-local \
  --jail-external-rctl \
  --jail-template-snapshot airoot/jails/playground/jails/template@base \
  --jail-dataset-parent airoot/jails/playground/jails \
  --jail-pile-root /var/db/playground/piles \
  --jail-bootstrap-pile /var/db/playground/bootstrap.pile \
  --tokens /var/db/playground/tokens.json
# the token is printed exactly once — hand it to the tenant out of band

# Browser connectors use OAuth instead. Mint a single-use human-gate code and
# hand that code to the same tenant out of band:
sudo playground invite --tenant <label> \
  --oauth-state /var/db/playground/oauth.json

# Any later administrative reset/destroy must include this same OAuth path, or
# PLAYGROUND_MCP_OAUTH_STATE, so every credential family is revoked together:
#   playground user token reset <label> ... --oauth-state /var/db/playground/oauth.json
#   playground user destroy <label> ... --oauth-state /var/db/playground/oauth.json

# Review deploy/freebsd/rc.conf.example, then install those exact assignments
# (the long flags value pins this parent jail's delegated dataset topology).
sudo sysrc playground_mcp_bind='127.0.0.1:8377'
sudo sysrc playground_mcp_tokens='/var/db/playground/tokens.json'
sudo sysrc playground_mcp_args='--jail-external-rctl --jail-template-snapshot airoot/jails/playground/jails/template@base --jail-dataset-parent airoot/jails/playground/jails --jail-pile-root /var/db/playground/piles --jail-bootstrap-pile /var/db/playground/bootstrap.pile --jail-clone-refquota 10G --jail-pile-quota 50G --public-url https://mcp.bultmann.eu --oauth-state /var/db/playground/oauth.json'
sudo sysrc caddy_config='/usr/local/etc/caddy/Caddyfile'
# Validate both services before enabling either public listener.
sudo service caddy configtest
sudo sysrc playground_mcp_enable=YES caddy_enable=YES
sudo service playground_mcp start
sudo service caddy start
```

The service runs as root (jail(8)/zfs(8) need it; `LocalRunner` removes the
operator-facing `sudo -n` prefix for root). It binds `127.0.0.1:8377` and logs to
`/var/log/playground_mcp.log`. It deliberately does **not** auto-restart after
an unexplained daemon exit. A loss of command-tree control deliberately exits
nonzero and leaves the affected jail untouched for operator inspection; an
operator must recover it before explicitly starting the provider again.
`daemon -H` lets newsyslog reopen the file without restarting the provider or
cancelling jobs. Caddy is the only public listener and terminates TLS for the
single canonical origin `https://mcp.bultmann.eu`.

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

# open a jail session; HTTP auth supplies the tenant and the jail backend uses
# its server-born self.pile, so the public tool exposes no host path argument
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_session","arguments":{}}}' http://127.0.0.1:8377/mcp

# Copy the exact opaque session id returned above. It includes a hash of the
# tenant identity; deriving it from a display label is deliberately unsupported.
BOX='<session-id-returned-by-open_session>'

# Run something in the jail; also prove the pile mounts are live and append-only
# (append lands, truncate is refused).
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"session\":\"$BOX\",\"command\":\"uname -a; id; ls -la /pile /shared; echo APPEND-OK >> /pile/self.pile && echo appended; (: > /pile/self.pile) 2>/dev/null || echo truncate-blocked\"}}}" http://127.0.0.1:8377/mcp

# detach this client handle; the persistent jail deliberately remains
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"close_session\",\"arguments\":{\"session\":\"$BOX\"}}}" http://127.0.0.1:8377/mcp

# permanent removal is explicit (open again first if the prior close detached
# the provider registry), and removes the jail + clone but NOT host piles:
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"open_session","arguments":{}}}' http://127.0.0.1:8377/mcp
curl -s -H "$A" -H "$H" -H "Mcp-Session-Id: $SID" -d "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"destroy_session\",\"arguments\":{\"session\":\"$BOX\"}}}" http://127.0.0.1:8377/mcp

jls name | grep '^playground-' || echo "no live playground jails"
zfs list -r airoot/jails/playground/jails   # removed tenant clone is absent
ls /var/db/playground/piles                # tenant + shared piles persist
```

Interim remote use without any exposure decision: an SSH port-forward
(`ssh -L 8377:127.0.0.1:8377 $JAIL_HOST`) gives an operator with an
ssh account the full service on their own loopback.

## Resource limits (repair #4 — bound every tenant-controllable resource)

The provider enforces the fixed execution bounds below; the parent-jail/ZFS
topology supplies the storage and kernel bounds. They are policy, not a public
scheduler-tuning surface.

- **Output retention.** A synchronous `exec` retains at most **16 MiB per
  stream**. On the local FreeBSD path it keeps draining and discards bytes past
  that prefix, leaving the descendant reaper alive; excess output is an
  ordinary truncated result, not a daemon fault. A retained `job_exec` instead
  has one **4 MiB combined** stdout/stderr ring and each poll returns at most
  **256 KiB**. Filling the ring evicts old chunks and reports `gap` +
  `dropped_bytes`; it does not kill the command. At most 64 job handles are
  retained globally (8 per tenant), bounding retained payload at 256 MiB; each
  ring is also capped at 1024 chunks so tiny writes cannot escape through
  allocation metadata.
- **Timeout ceiling.** A caller may request a smaller `timeout_ms`, never a
  larger one: the effective timeout is `min(requested, 30 min)`. On expiry the
  server-side `timeout(1)` reaps the jail process tree (exit 124). A local,
  root, FreeBSD jail deployment also uses `timeout(1)` as a descendant reaper
  for exact job-scoped cancellation; it waits for every descendant, including
  processes that double-fork or create a new session. If that kernel-backed
  proof itself fails, the provider exits nonzero immediately—there is no
  automatic jail reset, quarantine ledger, or restart
  loop to compound an already-untrustworthy host state. Remote SSH and Lima
  keep synchronous `exec` but deliberately reject `job_exec` rather than
  overclaim cancellation.
- **Admission control.** One foreground command per tenant and 32 globally,
  with no waiter queue: excess work is refused immediately as `sandbox busy`.
  This preserves legible mutation order, prevents one public user from taking
  every daemon worker, and removes a second scheduler.
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

### RACCT/RCTL — the physical host predeclares each tenant

RACCT/RCTL is OFF unless the physical host explicitly enables it (FreeBSD's
default), so verify it before exposure. CPU, RAM, process-count, and FD pressure
inside the nested jails otherwise reach host-global resources.

The provider deliberately remains inside the `playground` parent jail. Stock
FreeBSD lets jailed root create and remove child jails, but does **not** grant it
the `PRIV_RCTL_ADD_RULE` / `PRIV_RCTL_REMOVE_RULE` privileges, and there is no
`allow.rctl` jail parameter. Therefore this profile does not pretend it can
manage per-child RCTL rules: `--jail-external-rctl` disables that impossible path,
and the physical host predeclares the six fixed rules for each deterministic
child name. This needs no privileged helper and no runtime network hop because
tenant creation is already an operator action.

On the **physical host**, first enable RACCT and its boot-time rule loader:

```sh
# 1. Turn on kernel resource accounting and its boot-time rule loader.
# `sysrc` variable names cannot contain dots, so add this exact loader line
# with sudoedit (do not spell it as kern_racct_enable):
#     kern.racct.enable="1"
sudoedit /boot/loader.conf
sudo sysrc rctl_enable=YES

# Confirm the parent's GLOBAL name as seen by the physical host.
jls name
```

Before creating a tenant, derive its exact global child name with the same Rust
function the backend uses. This command is read-only and can run through the
parent jail from the physical host:

```sh
TENANT='<label>'
PARENT_JAIL='playground'  # replace if physical-host `jls name` says otherwise
GLOBAL_CHILD=$(jexec "$PARENT_JAIL" /usr/local/bin/playground \
  user jail-name "$TENANT" --jail-prefix playground \
  --parent-jail-name "$PARENT_JAIL")
printf '%s\n' "$GLOBAL_CHILD"
```

Add these six concrete lines to `/etc/rctl.conf`, replacing
`<global-child-name>` with that output:

```text
jail:<global-child-name>:maxproc:deny=512/jail
jail:<global-child-name>:nthr:deny=2048/jail
jail:<global-child-name>:openfiles:deny=8192/jail
jail:<global-child-name>:memoryuse:deny=2G/jail
jail:<global-child-name>:swapuse:deny=1G/jail
jail:<global-child-name>:pcpu:deny=90/jail
```

For the first tenant, reboot after enabling RACCT; the loader tunable cannot be
enabled live and `/etc/rc.d/rctl` will load the predeclared name:

```sh
sudo shutdown -r now
```

On an already-enabled host, or for each later tenant, apply newly added rules
immediately instead of waiting for another reboot:

```sh
for tail in \
  maxproc:deny=512/jail nthr:deny=2048/jail \
  openfiles:deny=8192/jail memoryuse:deny=2G/jail \
  swapuse:deny=1G/jail pcpu:deny=90/jail
do
  sudo rctl -a "jail:${GLOBAL_CHILD}:${tail}"
done
sudo rctl "jail:${GLOBAL_CHILD}"      # must print all six rules
```

Only after that proof should `user create ... --jail-external-rctl` create the
empty persistent jail and mint its credential. FreeBSD permits a name-keyed
RCTL record before the jail exists; when the jail appears it attaches to that
record. `/etc/rc.d/rctl` is host-only (`KEYWORD: nojail`) and reloads the rules
at boot. Destroy leaves these small name-keyed rules in place so deterministic
reprovisioning remains bounded; remove them manually only when permanently
retiring the tenant.

The provider's rc prestart independently refuses to run unless
`kern.racct.enable=1`, but it cannot inspect host-owned RCTL rules from inside
its jail. The physical-host `rctl "jail:${GLOBAL_CHILD}"` check is a real
provisioning gate, not optional paperwork.

## Go-live checklist

The code path is now small: one Caddy site, one loopback provider, one local
jail backend, and one bounded execution state machine. Public deployment still
waits on evidence from the actual host; documentation is not that evidence.

Required before opening ports 80/443:

1. **Recover the real administration path and re-audit the target.** The host
   reached through the current Ansible alias no longer exposes the previously
   observed `playground` parent jail, while direct SSH to the public IPv6
   address currently refuses. Confirm the intended physical host and parent
   jail before copying anything.
2. **Prove the parent boundary.** Version or inspect the real parent-jail and
   physical-host PF configuration: the service must be root only inside that
   parent, delegated only `airoot/jails/playground/jails`, with child networking
   denied unless deliberately enabled. The rc script refuses host-root,
   `securelevel < 1`, and RACCT-off starts.
3. **Turn on and prove RACCT/RCTL.** Reboot after enabling it, predeclare the
   exact global child name before each tenant creation, and inspect all six
   host-owned rules from the physical host. Also prove the 10G clone
   `refquota` and the 50G pile-dataset `quota`; a plain pile directory is not a
   substitute.
4. **Build the useful child image.** The observed template was stock FreeBSD.
   Install the intended faculties/tools, freeze a new immutable snapshot, and
   install a reviewed generic bootstrap pile containing no operator memory.
   Decide explicitly whether tenants need outbound networking; the current
   child topology has none.
5. **Bring up the private service first.** Install the binary and rc profile,
   provision one pilot token, run the loopback MCP round-trip, then run the
   opt-in FreeBSD job cancellation smoke. It must kill the escaped job
   descendant while preserving the unrelated process in the same jail.
6. **Bring up Caddy and resolve DNS deliberately.** Validate the Caddy config,
   obtain the real certificate, and verify the physical firewall exposes only
   80/443. Decide whether the public service may remain IPv6-only or needs an A
   record/proxy, and repair local split-horizon resolution before relying on
   local browser tests.
7. **Exercise real clients.** Complete authorization-code + PKCE flows from both
   Claude and ChatGPT, then use `open_session`, synchronous `exec`, and the
   `job_exec` / `job_poll` / `job_cancel` path through the public hostname.
   Poll a job until `state == terminal && has_more == false`.

`ai.bultmann.eu` is intentionally absent from this list: there is currently no
UI or other product to serve there. Adding a second OAuth/CORS origin before a
real consumer exists would add authority and ambiguity, not capability.

The first pilot does not need VNET, a second privileged helper, a pile-backed
job ledger, or multiple execution strategies. Those are later responses to
observed needs, not prerequisites for safe usefulness.
