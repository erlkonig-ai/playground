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
| `summary` | `Handle<LongString>` | Text summary stored as a blob |
| `created_at` | `NsTAIInterval` | When the chunk was created |
| `start_at` | `NsTAIInterval` | Temporal scope start (inclusive) |
| `end_at` | `NsTAIInterval` | Temporal scope end (inclusive) |
| `child` | `GenId` (repeated) | Arbitrary n-ary tree children |

Provenance to specific cognition turns or archive messages is computed
*at read-time* via temporal overlap rather than stored as a chunk-side
attribute (see Provenance below). The `about_exec_result` /
`about_archive_message` attributes remain declared in the schema for
backward compatibility with chunks written under earlier versions, but
new chunks do not set them.

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

Provenance — "which raw events does this chunk summarize?" — is recovered
by *temporal overlap* rather than stored as chunk-side references:

```
memory provenance <chunk-id>
```

returns every cognition exec result whose `finished_at` and every archive
message whose `created_at` falls within the chunk's `[start_at, end_at]`
interval, chronologically ordered.

This loose coupling means:

- **Chunks can be written before the data lands.** A reflective summary
  written today against a not-yet-imported chatgpt-data-dump becomes
  automatically associated with that data the moment it lands on the
  archive branch, because the time-range query catches it.
- **No rewrite pass on import.** New archive data joins the existing
  provenance fabric just by being timestamped.
- **Multi-source unification.** Cognition (playground exec results) and
  archive (imported message history) are queried together; the model
  doesn't need to know which branch a piece of evidence came from.

This is the [coordinate-and-cursor pattern][cc] applied to memory
provenance — facts indexed by time, relationships computed by overlap.

[cc]: # "wiki:b72c62851e4e4989138a2a45d75c813b in the pile"

### Legacy: `about_exec_result` / `about_archive_message`

Earlier chunks (written before the loose-coupling refactor in faculties
0.18) may carry `ctx::about_exec_result` and `ctx::about_archive_message`
attributes set at write-time. The schema preserves these attribute IDs so
older chunks remain queryable, and tools that read them (e.g. `triage`)
continue to work. New chunks do not set them.
