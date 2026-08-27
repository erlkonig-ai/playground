# Linux sandbox backend — measured ground truth (deferred lane)

A third `SandboxBackend` for the aarch64 DGX Sparks, so a small local model can
do autonomous work with faculties and piles mounted and **no network egress from
the sandbox**. JP's framing, verbatim: *"Isolate the sandbox, not the process the
model runs in."*

Status **2026-08-27: deferred, not cancelled.** Deployment moved to `drive` on
the Sparks and `playground` on the MacBook, so the jail and Lima backends cover
the near term. The reason for wanting this has not gone away: a sandbox local to
the box where the model runs is a stronger boundary than one brokered from
another machine.

What landed instead was the prerequisite refactor (`src/sandbox/runner.rs`,
`src/sandbox/policy.rs`) — see those modules' docs.

---

## What was MEASURED on `spark` (zgx-0d6e), 2026-08-27

Every line below was observed on the box, not inferred. Where a number or a
verdict has a scope, the scope is stated with it.

### The box

| | |
|---|---|
| OS | Ubuntu 24.04.4 LTS, kernel `6.17.0-1029-nvidia`, aarch64 |
| the provider's unprivileged user | uid 1001; in `sudo`, **not** in `docker` |
| `sudo -n` | works (passwordless) |
| root fs | `/dev/nvme0n1p2` **ext4**, 3.6T, 1.4T free, everything (`/home`, `/var/lib`, `/tmp`, `/raid`) is on it |
| cgroups | v2 (`cgroup2fs`); host controllers `cpuset cpu io memory hugetlb pids rdma misc dmem` |
| cgroup delegation to the user slice | **`cpu memory pids` only — no `io`** |

### Container runtimes — the recommended shape does not exist here yet

- **`podman` is ABSENT.** Not installed. Available in the archive as
  `4.9.3+ds1-1ubuntu0.2+esm3`.
- **`newuidmap`/`uidmap` is ABSENT** (available as `1:4.13+dfsg1-4ubuntu3.2`).
  Rootless podman needs it.
- `docker` **29.2.1** is present and is the box's real runtime: cgroup v2 with
  the systemd driver, `overlay2`, `runc`, security options
  `apparmor + seccomp(builtin) + cgroupns`. Rootful; reachable only via `sudo`
  because the provider's user is not in the `docker` group.
- `crun` absent, `runc` present. `nerdctl` absent.
- `/etc/subuid` and `/etc/subgid` **do** carry a `165536:65536` range for that
  user, so the id
  ranges rootless podman would need already exist.

### The AppArmor userns gate IS in the way

```
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.unprivileged_userns_clone = 1
user.max_user_namespaces = 511843
```

and empirically, as that unprivileged user:

```
$ unshare -U -r true
unshare: write failed /proc/self/uid_map: Operation not permitted   (rc=1)
```

So **rootless podman would not work on this box as it stands.** It needs either
the AppArmor profile the Ubuntu `podman` package ships (`/etc/apparmor.d/podman`,
which grants the userns transition) or `kernel.apparmor_restrict_unprivileged_userns=0`.
Standing this up is therefore a real change to a shared measurement box — two
package installs plus an AppArmor decision — not something to do unilaterally
mid-lane. **Ask JP first.**

### Inode flags work, and enforce exactly what the pile needs

The pile filesystem is ext4 and **`chattr +a` is real here** — this is the
opposite of the Lima/virtiofs precedent (2026-07-11: `chattr +a` fails
`Operation not supported`, is kept with `|| true`, and a session then truncated
its own pile to 0 bytes).

Measured on the host, on an ext4 file under that user's home:

| as | action | result |
|---|---|---|
| unprivileged user | `chattr +a` | **fails** — needs `CAP_LINUX_IMMUTABLE` |
| root | `chattr +a` | succeeds, `lsattr` → `-----a--------e-------` |
| unprivileged **owner** | `chattr -a` | **fails** |
| unprivileged owner | `: > pile` | **fails**, `Operation not permitted` |
| unprivileged owner | `>> pile` | **succeeds** |
| unprivileged owner | `rm pile` | **fails** |

So the flag must be set **host-side, as root, BEFORE the mount**, and a failure
to set it must `bail!` — never `|| true`.

### The claim about Docker being default-unsafe is WRONG as stated — and right in substance

The brief said: *rootful container root holds `CAP_LINUX_IMMUTABLE` in the
initial userns, so `chattr -a` works and append-only is defeated.* Measured, that
is **not true of Docker's default capability set**, and it **is** true of two
opt-in flags.

Bind-mounting one append-only host file into `vllm/vllm-openai:v0.26.0` with
`--network none`:

| container config | `CapEff` | `chattr -a` | `: > pile` | `>> pile` |
|---|---|---|---|---|
| `-u 0:0` (Docker default caps) | `a80425fb` | **fails** | **fails** | succeeds |
| `-u 0:0 --cap-add=LINUX_IMMUTABLE` | `a80427fb` | **SUCCEEDS** | **SUCCEEDS** | succeeds |
| `--privileged` | `1ffffffffff` | **SUCCEEDS** | **SUCCEEDS** | succeeds |
| `-u 1001 --cap-drop=ALL --security-opt no-new-privileges` | `0` | **fails** | **fails** | succeeds |

`CAP_LINUX_IMMUTABLE` is bit 9 (`0x200`). `0xa80425fb` does not have it;
`0xa80427fb` does. Docker's default bounding set genuinely excludes it.

**The practical conclusion is unchanged and is the reason the negative test
exists:** append-only survives a rootful Docker container only as long as nobody
adds `--cap-add=LINUX_IMMUTABLE` or `--privileged`, and on an NVIDIA box
`--privileged` (or `--gpus all` habits near it) is one copy-paste away. Do not
rely on the runtime's defaults being what you last read; **prove it per
provision.**

Host state after all four runs: the pile still carried its seed line and the
appends, at its grown size, still flagged `-----a-`. **Nothing truncated it.**

### `--network none` blocks egress

In every configuration above, `--network none` produced no default route and
`cat < /dev/tcp/1.1.1.1/53` failed. **But see the next section before trusting
that sentence.**

---

## The trap that nearly got written into the test

`ip` **is not installed in that image.** My first negative test read
`ip -o link` into an empty string and reported "no interfaces" — a *pass* — for
a reason that had nothing to do with isolation. An absent probe binary and a
correctly-isolated sandbox produce byte-identical output.

That is the same failure shape as Lima's `chattr +a ... || true`: a check that
silently degrades into no check. So the provision-time test must:

1. **Assert the probe binary exists first**, and fail closed if it does not.
2. **Capture exit codes without a pipe.** `cmd 2>&1 | sed ...; rc=$?` captures
   `sed`'s status, not `cmd`'s. My first pass reported `trunc rc=0` while the
   truncation had actually failed.

## The commit that makes it real, when this resumes

Not the container verbs — the **provision-time negative test**, run on EVERY
provision, failing closed on any of:

- as the sandbox uid, `chattr -a <pile>` MUST fail;
- `: > <pile>` MUST fail;
- `>> <pile>` MUST succeed;
- `ip -o link` shows only `lo`, and `ip route show default` is empty;
- and, per the trap above, every tool the test uses is present.

## Design notes carried forward

- Single-**FILE** bind mounts, never directories. That is the 2026-07-24
  confused-deputy fix and it transfers unchanged: Docker/podman bind a plain
  file onto a plain file, and mountinfo confirms it
  (`... <host>/self.pile /pile/self.pile rw,relatime - ext4 ...`).
- On Linux the mount table to verify against is `/proc/self/mountinfo`, and the
  field that identifies a bind is the **root** field (4), not the post-`-`
  device name — the device is identical for every bind on the same filesystem
  and therefore identifies nothing. `super::policy` already has the comparison
  rules; it needs a `parse_linux_mountinfo` alongside `parse_bsd_mount`.
- The backend should take the runtime as a flag (`podman` | `docker`) rather
  than hardcoding one. Their CLIs are near-identical for what we need, only one
  of them exists on the box today, and — given the table above — the security
  property is established by the negative test, not by which binary's name is on
  the command line.
- cgroup caps available rootless here are `cpu memory pids`. No `io`.
- Rootless containers need `loginctl enable-linger <user>`; `Linger=no` today, so
  user services die at logout.

## What this isolation would NOT protect against

Stated plainly, so nobody has to rediscover it:

- **Not a defence against the model reading anything the pile contains.** The
  sandbox bounds egress and truncation, not what the model learns.
- **Append-only is not immutability.** A sandbox can still append garbage to its
  own pile forever, up to whatever quota exists. It cannot rewrite history; it
  can pollute it.
- **A crash-torn tail is still possible** and is repaired host-side
  (unflag → amputate → re-flag), exactly as on the jail backend.
- **`--network none` is not a firewall.** It removes the interfaces. Anything
  the provider itself hands into the sandbox — a mounted socket, a file, an
  exec'd command's output — is still a channel, and any future decision to give
  the sandbox an address moves the whole egress question to a host firewall rule
  that this backend would not express.
- **It does not protect the host from a `--privileged` regression.** The
  negative test catches it at provision; nothing catches someone running the
  container by hand.
