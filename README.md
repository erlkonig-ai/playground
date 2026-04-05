# Playground

## Diagnostics

Run the diagnostics dashboard to observe a pile:

```bash
cargo run --manifest-path playground/Cargo.toml -- diagnostics
```

The dashboard defaults to `./personas/<instance>/pile/self.pile` (instance defaults to `playground`)
and branch `cognition`; change the path or branch in the UI if
your VM writes elsewhere.

Prefill the dashboard with a pile path:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/self.pile diagnostics
```

## Notebooks

Run the conceptual compaction notebook to explore carry merges as new messages are added:

```bash
cargo run --manifest-path playground/Cargo.toml --example compaction_lsm
```

## Running Playground

Run core + LLM + Lima exec. Defaults to `./personas/<instance>/pile/self.pile`:

```bash
cargo run --manifest-path playground/Cargo.toml -- run
```

Point at a specific pile path:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile run
```

Run core + LLM and start the exec worker inside a Lima VM (macOS):

```bash
cargo run --manifest-path playground/Cargo.toml --bin playground -- \
  --pile /path/to/pile/self.pile run
```

Run the core loop only (no LLM/exec workers):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile core
```

Run the LLM worker only (split-host setups or local testing):

```bash
cargo run --manifest-path playground/Cargo.toml --bin playground -- --pile /path/to/pile/self.pile llm
```

Run the exec worker only (VM/split-host setups):

```bash
cargo run --manifest-path playground/Cargo.toml --bin playground -- --pile /path/to/pile/self.pile exec
```

## Memory backfill (independent of requests)

Estimate pending compaction work (archive by default):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile memory estimate
```

Include pending exec leaves in the estimate:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile memory estimate --include-exec
```

Optionally provide pricing to get a rough USD estimate:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile \
  memory estimate \
  --input-cost-per-1m-tokens 2.0 \
  --output-cost-per-1m-tokens 6.0 \
  --cost-currency EUR
```

Backfill context memory chunks without creating LLM requests:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile memory build
```

Cap archive ingestion per run (useful for staged backfills):

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile \
  memory build --max-archive-leaves 500
```

## Config in the pile

Playground stores its configuration inside the pile. Use the `config` subcommand to inspect or update it:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config show
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set poll-ms 100
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set memory-compaction-arity 8
```

Prompts can also be loaded from files:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set system-prompt @./system_prompt.txt
./faculties/headspace.rs --pile /path/to/pile/self.pile lens set factual prompt @./memory_lens_factual.txt
./faculties/headspace.rs --pile /path/to/pile/self.pile lens set factual compaction-prompt @./memory_lens_factual_compaction.txt
./faculties/headspace.rs --pile /path/to/pile/self.pile lens add reflective --prompt @./memory_lens_reflective.txt --compaction-prompt @./memory_lens_reflective_compaction.txt --max-output-tokens 160
./faculties/headspace.rs --pile /path/to/pile/self.pile lens list
```

Use `@-` to read a value from stdin (for both `playground config set` and `headspace` value fields).

Prompt files in `playground/prompts/*.md` are generated from templates in
`playground/prompts/templates/*.tmpl.md`. Re-render after editing templates or shared fragments:

```bash
python3 playground/scripts/render_prompts.py
python3 playground/scripts/render_prompts.py --check
```

You can pin branch ids in config (recommended) so faculties resolve stable branch identities:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set compass-branch-id <hex-id>
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set local-messages-branch-id <hex-id>
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile config set relations-branch-id <hex-id>
```

Clear an optional config field:

```bash
./faculties/headspace.rs --pile /path/to/pile/self.pile lens reset factual prompt
./faculties/headspace.rs --pile /path/to/pile/self.pile lens remove reflective
```

Manage LLM profiles (headspaces):

```bash
./faculties/headspace.rs --pile /path/to/pile/self.pile list
./faculties/headspace.rs --pile /path/to/pile/self.pile add "oss-120" --model gpt-oss:120b --base-url http://localhost:11434/v1/responses
./faculties/headspace.rs --pile /path/to/pile/self.pile use oss-120
./faculties/headspace.rs --pile /path/to/pile/self.pile set reasoning-effort medium
./faculties/headspace.rs --pile /path/to/pile/self.pile set api-key sk-...
```

LLM/headspace settings (model/base-url/reasoning/api-key, compaction profile, and memory lenses)
are managed by the `headspace` faculty. Compaction merge arity is runtime config.

## Running With a VM (exec worker in VM)

On macOS, use Lima to run the exec worker in a VM while the core loop + LLM worker run on the host:

```bash
cargo run --manifest-path playground/Cargo.toml -- --pile /path/to/pile/self.pile run
```

This command:
- Creates/starts a Lima instance (default name `playground`).
- Runs the core loop + LLM worker on the host.
- Runs the exec worker inside the VM, pointed at the same pile.

Commands executed by the exec worker receive:
- `PILE` (active pile path),
- `CONFIG_BRANCH_ID` (`6069A136254E1B87E4C0D2E0295DB382`),
- `WORKER_ID` (exec worker id),
- `TURN_ID` (current exec request id).

Reason notes (useful when a model/provider does not expose reasoning output):

```bash
./faculties/reason.rs "Why this action makes sense"
./faculties/reason.rs "Why this command now" -- git status
```

`reason` logs a structured rationale event into the active exec/cognition branch
and (when a command is provided) then runs it.

Pass a pile path as the first argument if you want a non-default location. The Lima VM is
recreated on every run to ensure the exec environment matches the host.
