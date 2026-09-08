# Native Faculties workers in persistent FreeBSD child jails

This is a **source-only operator recipe, not a deployment receipt**. It does
not enable the public native catalogue or alter the existing sandbox default.
Build/test the native HTTP Faculties artifact separately, then validate this
profile on the target FreeBSD 15.1 host before any public switch.

Each colleague has one already-provisioned persistent jail and one native
Faculties process. The process uses that jail's existing `/pile/self.pile`
and `/pile/self.key`, and the canonical persona returned by
`playground user attach`. It does not create a user, mint an account token,
read OAuth state, or import an operator's environment. The existing shared
pile mount does **not** confer blanket shared-collection authority; this first
worker profile configures only the colleague's own pile and signer.

The gateway, child jail, and worker have separate lifetimes:

- The existing OAuth edge authorizes each request and chooses a tenant's
  fixed entry in `workers.json`. It does not start or stop workers.
- `user attach` reuses a running jail or reattaches its existing ZFS clone,
  durable pile/key mounts, and configured limits. Unknown tenants fail; no
  clone, bootstrap reseeding, or token creation occurs. Legacy stopped jails
  may acquire their missing durable signer through existing reattach logic.
- A per-worker rc service **in the trusted parent jail** starts base-system
  `daemon`, which directly supervises `jexec ... faculties mcp`. Child jails
  are persistent `jail -c` contexts without an `/etc/rc` startup command, so a
  service installed only inside a child would not run on reattach.

## Prerequisites

Use the [existing parent-jail security and provisioning profile](README.md),
including root-owned configuration paths, delegated ZFS subtree,
`enforce_statfs=0` in the trusted parent, host securelevel at least 1, RACCT,
and physical-host RCTL rules for each globally qualified child jail name.
The parent cannot install or verify those physical-host rules;
`--jail-external-rctl` is an operator assertion, not proof of limits.

Install a Playground artifact with `user attach` at
`/usr/local/bin/playground`, and `jq` in the parent. Each selected child must
already contain a compatible FreeBSD native Faculties binary at
`/opt/faculties/faculties`, including `mcp --http-listen` and
`--http-token-file`. This recipe does not build, upgrade, provision, or destroy
child filesystems. A running legacy jail missing `/pile/self.key` needs the
documented deliberate signer backfill/reattach first; a running-jail reuse
does not repair its mounts or synthesize the key.

Prepare the [gateway manifest](../../README.md#native-faculties-gateway-opt-in)
in a private parent directory. For example, the *non-secret* structure is:

```json
{
  "workers": [
    {
      "tenant": "pilot",
      "address": "127.0.0.1:8401",
      "token_file": "worker-keys/pilot.token"
    }
  ]
}
```

The manifest and each internal token must be root-owned regular non-symlink
files with mode `0600` or `0400`; their directory tree must be controlled by
root. Relative `token_file` paths resolve against the manifest directory,
exactly as at the gateway. Generate a distinct cryptographically random
bearer for every worker and keep it out of terminal output and command
arguments (for example, write `openssl rand -hex 32` directly into an
operator-created private file). This is a private internal credential, **not**
an OAuth/access token or the pile signing key.

The rc profile accepts only canonical `127.0.0.1:PORT` or `[::1]:PORT`, with
ports 1–65535. The gateway's general manifest parser accepts additional
literal loopback spellings; this conservative service profile does not.
Labels and addresses must be distinct, and the selected label must match
exactly. Invalid or oversized manifests, missing entries, unsafe file modes,
bad tokens, unknown tenants, or missing guest assets refuse startup.

Before exposure, verify the **actual parent and child socket addresses** and
that every worker port is unreachable from outside the host on the intended
jail topology. A loopback spelling alone is not proof: FreeBSD can map IPv4
loopback bind/connect operations to a restricted jail's primary address.
This follows the primary
[FreeBSD IPv4 jail code](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/netinet/in_jail.c);
it is a deployment check, not evidence that the existing host is exposed or
authorization to change its networking.

## Install one instance

Run this only in the trusted parent jail after choosing an existing tenant.
The service suffix is an operator identifier, not a tenant-label encoding;
use only lowercase letters, digits and underscores. Install one instance
per tenant/address, not multiple supervisors for the same worker.

```sh
# Example instance. Review these source files before installing them.
sudo install -d -o root -g wheel -m 0700 /usr/local/etc/playground-workers
sudo install -o root -g wheel -m 0600 \
  deploy/freebsd/playground_faculties.conf.example \
  /usr/local/etc/playground-workers/playground_faculties_pilot.conf
# Edit this private file: exact tenant, manifest, dataset parent, pile root,
# and jail prefix. Address and token path are NOT duplicated there.
sudoedit /usr/local/etc/playground-workers/playground_faculties_pilot.conf

sudo install -o root -g wheel -m 0555 deploy/freebsd/playground_faculties \
  /usr/local/etc/rc.d/playground_faculties_pilot
# rcorder reads literal comment conditions, not shell expansions. Give each
# installed instance its own PROVIDE condition; don't leave the template name.
sudo sed -i '' 's/^# PROVIDE: playground_faculties$/# PROVIDE: playground_faculties_pilot/' \
  /usr/local/etc/rc.d/playground_faculties_pilot
sudo sysrc playground_faculties_pilot_enable=YES
sudo service playground_faculties_pilot start
sudo service playground_faculties_pilot status
```

The script derives its instance name from FreeBSD's `rc_service`, including
when boot sources it from `/etc/rc`. Its private file is loaded only during
start: a subsequently broken manifest cannot prevent `stop`. There are no
extra-arguments or environment passthrough settings. Each actual start checks
the parent-jail safeguards, even with `forcestart` (prefer ordinary `start`
or `onestart`; `force` also changes rc's error-reporting semantics).
See the primary [rc.subr source](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/libexec/rc/rc.subr)
and [rcorder manual](https://man.freebsd.org/cgi/man.cgi?query=rcorder&sektion=8&format=html)
for the service-name and literal dependency conventions.

Only the selected bearer bytes travel through stdin into the already-attached
jail, where a private temporary file is atomically renamed to
`/var/run/faculties-mcp/token` with mode `0400`. No host directory is mounted.
The worker gets explicit own-pile/key flags and a clean environment, including
its canonical `PERSONA`. It does not source the guest's login profile or
inherit Drive endpoints, collection overrides, or operator credentials;
[`jexec -l`](https://man.freebsd.org/cgi/man.cgi?query=jexec&sektion=8&format=html)
is followed by `env -i` to make the final environment explicit.

## Check readiness privately

`service ... status` proves **supervisor liveness, not HTTP readiness**. A
failed binary, bind conflict, or killed jail can leave `daemon` retrying every
10 seconds. Inspect `/var/log/playground_faculties_pilot.log` and run an
authenticated MCP initialize/discovery exchange against the manifest address
before exposing anything. The installed
[`smoke.sh`](smoke.sh) exercises the sandbox catalogue and is **not** a native
worker readiness check.

For a non-mutating native check, initialize, send
`notifications/initialized`, list tools, and delete the session. Do not call
a faculty merely to test readiness. This example runs in a root shell in the
trusted parent; the bearer and session remain in a private temporary file,
not process arguments. Resolve the address and key path from the selected
manifest entry before running it:

```sh
(
  set -eu
  umask 077
  check_url=http://127.0.0.1:8401/
  key_file=/var/db/playground/worker-keys/pilot.token
  check_dir=$(mktemp -d /var/tmp/faculties-check.XXXXXXXX)
  trap 'rm -f "$check_dir/request" "$check_dir/headers" "$check_dir/body"; rmdir "$check_dir"' EXIT
  {
    printf 'Authorization: Bearer '
    tr -d '\r\n' < "$key_file"
    printf '\nContent-Type: application/json\nAccept: application/json, text/event-stream\n'
  } > "$check_dir/request"
  check_request() {
    check_status=$(curl --fail-with-body --silent --show-error --max-time 30 \
      --noproxy '*' --proto '=http' --header "@$check_dir/request" \
      --dump-header "$check_dir/headers" --output "$check_dir/body" \
      --write-out '%{http_code}' --request "$1" --data "${2-}" "$check_url")
  }
  check_request POST '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"operator-check","version":"1"}}}'
  [ "$check_status" = 200 ]
  jq -e '.id == 1 and .result.capabilities.tools != null' "$check_dir/body" >/dev/null
  check_version=$(jq -er '.result.protocolVersion | select(test("^[0-9-]+$"))' "$check_dir/body")
  check_session=$(awk 'tolower($1) == "mcp-session-id:" { sub("\r$", "", $2); print $2 }' "$check_dir/headers")
  case "$check_session" in ''|*[!A-Za-z0-9_-]*) exit 1 ;; esac
  printf 'Mcp-Session-Id: %s\nMCP-Protocol-Version: %s\n' \
    "$check_session" "$check_version" >> "$check_dir/request"
  check_request POST '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  [ "$check_status" = 202 ]
  check_request POST '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  [ "$check_status" = 200 ]
  jq -e '.id == 2 and (.result.tools | type == "array" and length > 0)' \
    "$check_dir/body" >/dev/null
  jq '.result.tools | length' "$check_dir/body"
  check_request DELETE
  [ "$check_status" = 204 ]
)
```

This prints only the discovered tool count. An early failure may leave an
initialized server session until its idle expiry; no tool operation was
submitted. A public connector still needs its own OAuth/discovery check.

## Restart, rotation, shutdown, and reboot

The supervisor's PID is `/var/run/playground_faculties_pilot.pid` (`daemon
-P`, not the child's `-p`). `service ... stop` signals this supervisor, which
forwards termination to its direct child and suppresses automatic restart.
It leaves the persistent jail, mounts, piles, and signing key intact. Never
kill only the worker and expect it to stay stopped. Stop and disable the
service **before** deliberately detaching/destroying its jail, or the
supervisor will continue trying to enter it. An unresponsive child requires
explicit operator inspection; this service does not escalate to destructive
jail teardown. These semantics follow the primary
[`daemon` manual](https://man.freebsd.org/cgi/man.cgi?query=daemon&sektion=8&format=html).

Logs are scoped per instance and mode `0600`. To rotate with newsyslog, use
the same service-specific log and supervisor PID (send SIGHUP, not a worker
restart), following [`playground_mcp.newsyslog.conf`](playground_mcp.newsyslog.conf).
For example, the pilot entry is:

```text
/var/log/playground_faculties_pilot.log root:wheel 600 7 10M * ZCE /var/run/playground_faculties_pilot.pid SIGHUP
```

Both gateway routing/bearers and native worker bearers are startup snapshots.
For token rotation, stop the selected worker, atomically replace its private
parent token, start the worker (which copies the new token into the child),
then restart the gateway using the same manifest. For address/tenant changes,
stop the old instance before editing the mapping and adjust private instance
configuration deliberately. Expect a short unavailable interval and lost MCP
sessions; clients must initialize again. Never replay a possibly executed
mutation automatically after a disconnect/restart. Public OAuth revocation
still uses the existing authorization store and is unrelated to rotating
this private hop credential.

On cold boot, the physical host must load its RACCT/RCTL policy and start the
trusted parent with delegated datasets available. Parent rc orders each
enabled worker after filesystems/ZFS/network setup and before
`playground_mcp`; each worker explicitly attaches only its own tenant. The
gateway can still start if a worker failed and returns unavailable for that
tenant. The rc dependency is an **ordering**, not a readiness guarantee or a
requirement that the other service be enabled. A native-gateway start alone
does not reattach jails. A source-reviewed recipe and historical sandbox
cold-boot receipts do not establish native-worker reboot success: verify the
actual ordering, mounts, host limits, clean environment, private discovery,
per-tenant isolation, restart, and stop on the intended FreeBSD host first.

## Local source checks

`sh -n deploy/freebsd/playground_faculties` checks shell syntax. On Linux with
`jq`, `sh deploy/freebsd/tests/worker-service.sh` checks the launch/refusal
contract using an isolated transformed script and fake absolute commands.
It covers exact mapping, private file modes, malformed credentials, bounded
address forms, repeated/fast starts, byte-preserving bearer staging, fixed
argv/environment, and config-independent stop. It starts no real worker or
jail and does not validate FreeBSD rc ordering, signal behavior, mount
semantics, or socket reachability.

The optional test below extracts the documented discovery exchange verbatim,
substitutes an isolated URL/token file, and runs it against an already-built
native binary. It binds a kernel-selected loopback port, checks the
200/202/200/204 exchange, and verifies that the deliberately absent pile and
signing key remain absent. It compiles nothing and calls no faculty:

```sh
FACULTIES_HTTP_BINARY=/absolute/path/to/faculties \
  sh deploy/freebsd/tests/native-discovery.sh
```

On Linux, both the fake-command suite and this real-native exchange passed
against Faculties `43d575967` (218 tools). This is evidence for the recipe and
native protocol, not for an installed FreeBSD service or the reconciled
Faculties release cohort.
