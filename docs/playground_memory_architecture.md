# Memory Architecture

This document describes the memory system as currently implemented. The system
provides manually curated, hierarchical summaries of past interactions that the
model uses as long-term context.

## Three-Branch Model

The playground maintains three independent branches on the pile:

| Branch | Purpose | Written by |
|--------|---------|------------|
| **memory** | User-created summary chunks | Memory faculty (`memory create`) |
| **cognition** | Active execution state (thoughts, model requests/results, commands) | Model worker loop |
| **archive** | Imported historical messages (prior sessions, external sources) | Import tools |

Memory chunks can reference cognition results via `about_exec_result` and
archive messages via `about_archive_message` for provenance tracking. The
three branches are independent — memory consolidation happens at the user's
discretion, not automatically.

## Chunk Data Model

A chunk is an entity tagged with `kind_chunk` carrying these attributes:

| Attribute | Schema | Description |
|-----------|--------|-------------|
| `summary` | `Handle<Blake3, LongString>` | Text summary stored as a blob |
| `created_at` | `NsTAIInterval` | When the chunk was created |
| `start_at` | `NsTAIInterval` | Temporal scope start (inclusive) |
| `end_at` | `NsTAIInterval` | Temporal scope end (inclusive) |
| `child` | `GenId` (repeated) | Arbitrary n-ary tree children |
| `about_exec_result` | `GenId` (optional) | Provenance link to cognition branch |
| `about_archive_message` | `GenId` (optional) | Provenance link to archive branch |

Time ranges use `NsTAIInterval` (TAI nanosecond intervals), allowing chunks
to represent non-instant events. Queries use overlap logic, not equality.

### Hierarchical Structure

Chunks form an arbitrary n-ary tree via `child` edges. A root chunk has no
parent. Splitting a root into finer-grained children is how the model adds
detail: the parent provides a coarse summary while children cover sub-ranges
at higher resolution.

The context assembly algorithm exploits this hierarchy for adaptive budget
allocation (see below).

## Memory Creation

Memory is created explicitly via the memory faculty:

```
memory create [<from>..<to>] <summary>
```

The faculty:
1. Stores the summary text as a `LongString` blob
2. Sets `start_at`/`end_at` from the range (defaults to now)
3. Parses the summary for `(memory:<range>)` or `[text](memory:<hex>)` links
   and creates `child` edges to referenced chunks
4. If no children are specified, scans the cognition and archive branches for
   events in the time range and creates `about_exec_result` /
   `about_archive_message` provenance links

All queries use `pattern!` directly on the `TribleSet` — no pre-materialization
into Rust structs. Chunk metadata is loaded on demand.

## The Breath Mechanism

The breath is a static boundary between memory and the present moment in the
model's context window. It consists of two fixed messages:

```
assistant: "breath"
user:      "present moment begins."
```

These markers serve as an anchor for Anthropic's prompt prefix caching. Because
they never change, the cache can seed the prefix (system prompt + memory cover +
breath) and only recompute the moment (recent shell interactions) on each turn.

### One-Turn Delay

When the memory cover changes (e.g., new chunks were created), the OLD cover
is used for the current turn and the NEW cover is recorded for the next turn.
This one-turn delay ensures the cache sees a stable prefix before it shifts.

## Context Assembly

The model's prompt is assembled as:

1. **System prompt** (static, from config)
2. **Memory cover** (chronologically sorted chunk summaries, budget-aware)
3. **Breath boundary** (assistant "breath" + user "present moment begins.")
4. **Moment turns** (recent shell interactions, most recent that fit budget)

### Budget Model

```
input_budget = context_window - max_output - safety_margin
body_budget  = input_budget * chars_per_token - system_prompt_chars
```

Memory cover takes priority; moment turns fill the remainder.

### Adaptive Splitting

The memory cover algorithm greedily selects chunks:

1. Start with all root chunks, sorted chronologically
2. Drop oldest roots if total summary text exceeds budget
3. Iteratively split the widest (coarsest) parent that has children, if the
   children's combined cost fits within the freed budget
4. Stop when no more splits fit or budget is exhausted
5. Track contiguous coverage — stop at the first temporal gap

This maximizes detail where the time range is broadest while respecting the
token budget. Isolated future chunks don't advance the coverage boundary,
preventing unsummarized events from being skipped.

## Provenance

Chunks can optionally link to the raw events they summarize:

- `about_exec_result` points to a cognition-branch execution result entity
  (carries `finished_at` timestamp)
- `about_archive_message` points to an archive-branch message entity
  (carries `created_at`, `author`, content)

These links allow the model to trace a summary back to the specific shell
interactions or imported messages it was derived from.
