# Playground Design

## Purpose

Playground is a minimal, deterministic loop that turns LLM output into execution
requests and feeds results back into the cognition graph. The core stays
small: **LLM result → exec request → exec result → new prompt**. Any external
messaging (Teams, email, etc.) is treated as a separate faculty and not part of
the core.

## Core Loop

1) Ensure there is a pending `openai_responses::request` (seeded or derived
   from the latest exec result).
2) Wait for the LLM worker to write an `openai_responses::result`.
3) Translate `output_text` into a `playground_exec::command_request`.
4) Wait for the executor worker to write a `playground_exec::command_result`.
5) Create a new `playground_cog::thought` prompt from the command output and enqueue
   the next `openai_responses::request`.

This means Playground does not call an LLM provider directly and does not execute
commands directly. The LLM worker handles provider requests; the executor worker
runs commands and writes results. Playground only reads and writes TribleSpace.

## Data Model

Playground’s core stores cognition prompts (`playground_cog`) and provider request/response
artifacts (`openai_responses`) alongside execution events (`playground_exec`). There
is no generic comms layer; external channels remain separate faculties.

## Schema Map (Proposed)

Keep three domains, each queryable and linked, without forcing a single
least-common-denominator model:

### Channel Schemas (external chat)

- Namespace: channel-specific (e.g., `teams::*`)
- Purpose: user-facing conversation graph for a single channel.
- Dashboard view: channel-native messages, authors, threads, requests.

Provider-specific artifacts should **not** live here. Keep LLM/provider payloads
and execution metadata in the execution schema and link back to messages via
explicit edges. Each channel gets its own schema and faculty; any unified view
should be a projection, not a canonical store.

### Archive Projection (unified message graph)

- Namespace: `archive::*`
- Purpose: a unified message/author/attachment graph derived from raw exports
  (ChatGPT backups, Codex logs, Teams, etc.) so tooling can query history without
  caring about source formats.
- This is a projection, not a channel schema. Keep raw source artifacts
  separately (e.g. lossless JSON trees, HTML) and link them to `archive::*`
  entities via explicit provenance edges.

### Execution (Provider / Endpoint)

- Namespace: provider- and endpoint-specific (e.g., `openai::responses::*`)
- Purpose: command runs and provider/job lifecycle.
- Example kinds (OpenAI Responses):
  - `openai::responses::kind_request`
  - `openai::responses::kind_status`
  - `openai::responses::kind_response`
  - `openai::responses::kind_result`
- Example attributes:
  - `model`, `response_raw`, `response_json_root`
  - `started_at`, `finished_at`, `sandbox_id`
- Example kinds (Command execution):
  - `playground_exec::command_request`
  - `playground_exec::in_progress`
  - `playground_exec::command_result`
- Example attributes:
  - `command_text`, `exit_code`, `stdout`, `stderr`
- Link edges:
  - `about_message` (links a run to a channel message)
  - `about_thought` (links a run to a cognition object)
  - `about_request` (links a run to a request)

Execution should not be generic. Different endpoints get different schemas and
workers (e.g., `openai::responses::request` vs `openai::images::request`). A
cognition object can spawn a provider-specific request; the worker only
processes `request → in_progress → result` and returns raw outputs for the
cognition layer to interpret. Command execution is treated the same way: it has
its own request/status/result schema and worker.

Example flow:

```
playground_cog::thought
  -> openai::responses::request
  -> openai::responses::result
  -> playground_cog::insight
```

## Executor Worker (Default)

To keep actions fully introspectable, command execution is handled by a
dedicated executor worker that only reads/writes TribleSpace. Playground expresses
intent by writing execution requests and waits for results.

Benefits:
- Every command and result is stored in the graph (queryable + auditable).
- Playground stays sandboxed to TribleSpace (no direct OS access).
- Execution can be scaled or moved to separate hosts without changing cognition.

The executor should remain “dumb”: it executes requests and records results.
Interpretation happens in the cognition layer.

For split-host setups, run the executor as a subcommand (`playground exec`) on the
remote host and keep the core loop + LLM worker on the host. Use `playground run ssh`
to orchestrate the core loop and LLM worker while starting the executor over SSH.

### Schema Sketch (playground_exec)

Minimal lifecycle:

```
playground_exec::command_request
  -> playground_exec::in_progress
  -> playground_exec::command_result
```

Type conventions (draft):

- `text` = `Handle<Blake3, LongString>` (UTF-8 text in a blob)
- `bytes` = `Handle<Blake3, FileBytes>` (file-backed bytes)
- `u64` = `U256BE` (store as u64 inside a 256-bit value)
- `timestamp` = `NsTAIInterval` (TAI nanoseconds; use the interval width to
  represent uncertainty; for exact instants set lower=upper)
- `id` = `GenId`

Kinds and attributes (draft, with schema intent):

- `playground_exec::kind_command_request`
  - `command_text` (text)
  - `cwd` (text, optional)
  - `stdin` (bytes, optional)
  - `stdin_text` (text, optional convenience)
  - `timeout_ms` (u64, optional)
  - `sandbox_profile` (id, optional; link to profile entity with `metadata::name`)
  - `requested_at` (timestamp)
  - `about_message` / `about_thought` / `about_request` (id links)
- `playground_exec::kind_in_progress`
  - `about_request` (id)
  - `started_at` (timestamp)
  - `worker_id` (id; link to worker entity)
  - `attempt` (u64)
- `playground_exec::kind_command_result`
  - `about_request` (id)
  - `finished_at` (timestamp)
  - `attempt` (u64)
  - `exit_code` (u64, optional on infra failure)
  - `stdout` / `stderr` (bytes)
  - `stdout_text` / `stderr_text` (text, optional convenience)
  - `duration_ms` (u64, optional)
  - `error` (text, optional for infra failures)

Large payloads should be stored as blob handles rather than inline strings.
Additional result kinds (e.g., `command_rejected`) can be introduced later if
policy gating becomes necessary.

If numeric fields become widespread, consider introducing explicit value
schemas (e.g., `playground_exec::u64`) instead of relying on generic `U256BE`.

### Executor Worker Interface (Draft)

The worker is a simple state machine over `playground_exec::command_request`.

1) Poll for `command_request` entities that have no `command_result` for their
   highest attempt.
2) Claim a request by appending an `in_progress` event with `worker_id` and
   `attempt = 1 + max(attempt)` (or `1` if none).
3) Re-check: only execute if the newly written `in_progress` is the latest
   attempt and no result exists for that attempt.
4) Execute using the requested sandbox profile (or a default).
5) Append `command_result` (with `attempt`) plus exit code and captured output
   (or `error` if the command failed to spawn/run).
6) Do not mutate or delete earlier events; Playground derives current state from
   the latest events.

Notes:
- If a request is claimed but no result appears after a timeout, another worker
  can append a new `in_progress` with a higher `attempt`.
- The worker should not interpret or post-process output beyond capture. Any
  semantic interpretation belongs to cognition.
- Avoid writing new attributes directly on the request entity. Treat request,
  progress, and result as separate event entities linked by `about_request`.
  This keeps ownership localized to the worker's own event IDs.
- In-sandbox executor: run the worker inside the sandbox so it shares the same
  workspace filesystem and pile. This removes SSH/network split-brain and
  yields a single ordered command stream per workspace. For stronger isolation,
  execute in ephemeral workspaces and explicitly export artifacts (patches,
  blobs) back into the pile.

### VM-Based Sandbox Layout (macOS)

On macOS, prefer a Linux VM with the executor running inside the VM. This keeps
the “real” filesystem and process state inside a Linux sandbox while allowing
the host Playground process to remain minimal.

Suggested layout:

- Host (macOS):
  - Runs Playground core (TribleSpace read/write, cognition, planning).
  - Shares only the pile directory into the VM (optional: also mount a workspace
    directory via virtiofs for faster iteration).
- Guest (Linux VM):
  - Runs the executor worker (single-writer per workspace).
  - Bootstraps `/workspace` by merging the latest snapshot lineage (missing
    paths are created; conflicting existing paths are preserved).
  - Executes `playground_exec::command_request` against the restored workspace.
  - Writes `playground_exec::command_result` back into the shared pile.

Shared paths (example):

- Host: `./personas/<instance>/workspace`
- Host: `./personas/<instance>/pile/self.pile`
- VM: `/workspace`
- VM: `/pile`

The executor only needs access to the pile plus `/workspace` inside the VM.
Anything else (network, system binaries, secrets) can be mediated by the VM
config or a dedicated sandbox profile.

Operationally, use `playground run` to start the core loop + LLM worker on the
host and the executor inside the Lima VM. The Lima configuration is defined in
`playground/scripts/lima.yaml.tmpl`; edit it and re-run `playground run` to
apply changes (set `PLAYGROUND_LIMA_RECREATE=1` to recreate the VM when you
change the config). The template provisions Rust via rustup so the executor can
compile on first boot; if you already created the VM before adding provisioning,
recreate it once with `PLAYGROUND_LIMA_RECREATE=1`.

### Pile Safety on macOS

To protect the pile from accidental truncation or deletion on macOS, set the
file flag to append-only (`uappnd`) and run the executor as a non-admin user.
This preserves append-only semantics without introducing a separate pile
writer service.

### Cognition (insight/memory/valence)

- Namespace: `playground_cog::*` (or similar)
- Purpose: introspection, memories, goals, valence, hypotheses.
- Example kinds:
  - `playground_cog::kind_thought`
  - `playground_cog::kind_insight`
  - `playground_cog::kind_memory`
  - `playground_cog::kind_goal`
- Example attributes:
  - `summary`, `valence`, `confidence`, `salience`, `tags`
  - `about_message`, `about_command`, `derived_from`

These domains can live in the same pile while remaining distinct and
queryable. Relationships between domains should be explicit links, not implicit
schema conflation.

## Migration Notes

- Prefer additive migrations: introduce new schemas and link from old data.
- Keep identifiers stable: renaming modules does not require new IDs.
- If labels change, append `metadata::name` entries on the same IDs.
- Legacy playground data can remain as a historical projection, but new work
  should target the dedicated schemas (`archive::*`, `teams::*`,
  `openai_responses::*`, `playground_exec::*`) instead of the old playground protocol.

## Faculties and External Messaging

External messaging (Teams, Telegram, email, etc.) is intentionally **not** part
of Playground's core. It should live in separate faculties that expose a structured
interface (e.g., `poll` and `send`) instead of raw tribles.

All data can live in the same pile, but **no automatic correspondence** should
be created between Teams and provider messages. Any relationship is mediated by
Playground's decisions and shell commands, not by direct schema links.

## Status and Responses

Playground does not emit `openai_responses::kind_result` events. Those belong to the
LLM worker that fulfills the request. Playground only acts on completed outputs.

## Design Principles

- Keep the core loop small and deterministic.
- Prefer explicit schemas over derived or ad-hoc identifiers.
- Treat external messaging as optional faculties, not core functionality.
