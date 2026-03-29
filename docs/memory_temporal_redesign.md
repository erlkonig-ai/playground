# Memory Design History

*This document is retained for historical context. The ideas below evolved
into the current memory architecture described in
`playground_memory_architecture.md`.*

## What Changed

The original memory system envisioned:
- Multiple **lenses** (factual, technical, emotional) producing parallel
  summary streams
- An **LSM-tree** compaction model with level-numbered chunks and automatic
  merging
- **Fork machinery** (`fork_summarize_leaf`, `fork_summarize_merge`) for
  asynchronous summarization

This was replaced by a much simpler design:
- **No lenses** — a single summary per chunk, written by the model at its
  discretion
- **No automatic compaction** — the user (or the model via faculties)
  explicitly creates chunks with `memory create`
- **Arbitrary n-ary tree** — chunks link to children via `child` edges,
  forming a tree that the context assembly algorithm splits adaptively
- **Time-range addressing** — chunks carry `start_at`/`end_at` intervals
  and are selected by temporal overlap, not by level number

## Key Insights That Survived

1. **Memory as lived experience**: summaries should read as recollections,
   not database entries.
2. **Time ranges, not levels**: addressing memory by "when" rather than
   "how compacted" is more natural and composable.
3. **Budget-adaptive detail**: the context window is finite, so memory
   must be able to present coarse summaries and split into finer detail
   on demand.
4. **Provenance links**: chunks can reference the raw events they
   summarize via `about_exec_result` and `about_archive_message`.

## What Was Dropped

- Per-lens prompt files and `MemoryLensConfig`
- `merge_arity` configuration and `insert_chunk_with_carry` cascade
- Archive reification (simulated shell turns for historical messages)
- Automatic model-driven compaction in the main loop

These may be revisited in the future, but the current system prioritises
simplicity and explicit control.
