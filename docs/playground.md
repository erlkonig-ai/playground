# Playground

## Design notes

- Event model and migration plan:
  - `playground_event_model.md`
- Memory architecture (context construction, lenses, archive reification):
  - `playground_memory_architecture.md`

## Config in the pile

Playground stores its runtime configuration in the pile. Inspect or update it with:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config show
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set tavily-api-key @/path/to/tavily_key.txt
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set exa-api-key @/path/to/exa_key.txt
./playground/faculties/headspace.rs --pile /path/to/self.pile show
./playground/faculties/headspace.rs --pile /path/to/self.pile set base-url https://api.mistral.ai/v1
./playground/faculties/headspace.rs --pile /path/to/self.pile set reasoning-summary detailed
```

For string config fields you can pass `@/path/to/file` to load the value from a file.

Set a persona id (used by `orient` to read local messages by stable identity):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set persona-id <hex-id>
```

Pin branch ids used by faculties (recommended so `orient` and diagnostics resolve branches by stable ids):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set compass-branch-id <hex-id>
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set local-messages-branch-id <hex-id>
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set relations-branch-id <hex-id>
```

Set the reasoning effort (optional, model/provider-dependent):

```bash
./playground/faculties/headspace.rs --pile /path/to/self.pile set reasoning-effort xhigh
```

Playground uses the chat-completions wire format for runtime and memory
compaction requests.

Configure memory lenses (all configured lenses are computed on failed turns):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set memory-lens-technical-prompt @/path/to/technical_lens.txt
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config set memory-lens-factual-max-output-tokens 256
```

Reset a lens to defaults:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile config unset memory-lens-technical-prompt
```

Flush the current moment into memory (sets the moment boundary to the latest
finished turn):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile memory consolidate
```

Set an explicit boundary turn:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile memory consolidate --turn-id <turn-hex-id>
```

## Relations (people)

Seed explicit person ids for messaging and affinity metadata:

```bash
./playground/faculties/relations.rs add <label> --id <hex-id>
./playground/faculties/relations.rs list
```

Local messaging resolves participants via the `relations` branch, so make sure
the persona id set in config also exists as a person entry.
For older piles, run this one-time migration to backfill normalized lookup keys:

```bash
./playground/migrations/relations_backfill_norm.rs --pile /path/to/self.pile
```

## Running

Core + LLM + Lima exec:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile run
```

`playground run` is the entrypoint for the VM-backed exec worker. The
old `run_lima.sh` wrapper is removed.

Core loop only (no LLM/exec workers):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile core
```

Core + LLM + exec in a Lima VM (macOS):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile \
  run
```

Run exec worker (VM):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile exec
```

When the exec worker launches a command, it exports these environment variables:
- `PILE`: active pile path (same value passed via `--pile`)
- `CONFIG_BRANCH_ID`: fixed config branch id (`6069A136254E1B87E4C0D2E0295DB382`)
- `WORKER_ID`: exec worker id (hex)
- `TURN_ID`: current exec request id (hex)

Reason notes (useful when the model/provider does not expose reasoning tokens):

```bash
./faculties/reason.rs "Why this action makes sense"
./faculties/reason.rs "Why this command now" -- git status
```

`reason.rs` logs a structured rationale event into the active exec/cognition branch
and (when a command is provided) then runs it.

## Pile separation (severance model)

If you want strict separation between internal cognition and external comms,
use two piles and only allow **one-way** flow from the external-comms pile into
the internal pile. For example:

- Internal pile (Playground): full cognition + private memory.
- External pile (Bulti or other comms persona): Teams/email/etc. access only.

Periodically sync the external pile into the internal pile and merge branches
so the internal loop can absorb new work context. Do not sync in the other
direction and do not give internal credentials to the external pile.

Operationally, the sync is intentionally simple for now. If/when `trible pile`
gains a first-class merge command, use that. Until then, treat this as a manual
maintenance step: copy/rsync the pile file, merge branches with available
tooling, then verify the combined branches are visible before starting
Playground.

## Workspace snapshots

Capture a workspace snapshot into the pile (branch `workspace` by default):

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile capture \
  playground/faculties /workspace/faculties \
  --label "seed:faculties"
```

Playground defaults now point faculty commands at `/workspace/faculties/*` so the
persona can inspect and edit local copies. Keep `/opt/playground/faculties` as
an immutable source tree and seed `/workspace/faculties` via workspace
snapshots.

List snapshots:

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile list
```

The `state=` field is a deterministic `SimpleArchive` handle for workspace
content (root path + entries), so identical snapshots share the same state
handle even when snapshot IDs differ.

Diff two snapshots (added/removed/modified paths):

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile diff <left-id> <right-id>
```

Merge two snapshots with a base (3-way file merge):

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile merge <base-id> <ours-id> <theirs-id>
```

By default merge conflicts fail. To force a side for conflicting paths:

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile merge <base> <ours> <theirs> --conflicts ours
```

Restore the latest snapshot into a target directory:

```bash
./playground/faculties/workspace.rs --pile /path/to/self.pile restore /tmp/workspace
```

The exec worker bootstraps the workspace on startup by merging the latest snapshot
lineage into `/workspace`:
- missing paths are created,
- unchanged existing paths are kept,
- conflicting existing paths are preserved and reported.
