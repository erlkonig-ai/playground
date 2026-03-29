# Event Model

## Shell-First Causality

Playground treats the shell as the model's physical reality. Every action the
model takes is a shell command; every observation is the command's output. This
grounds the model's experience in concrete, reproducible cause-and-effect
rather than abstract API calls.

The core invariant: **one side-effecting command per turn**. The model emits a
command, the shell executes it, and the output becomes the next observation.
This sequential discipline keeps the interaction log deterministic and
replayable.

## Turn Structure

Each turn in the cognition branch is recorded as a chain of entities:

1. **Thought** (`kind_thought`) — the context snapshot that prompted the model
2. **Model Request** (`kind_request`) — links thought to model + context
3. **Model Result** (`kind_result`) — output text, reasoning, response metadata
4. **Command Request** (`kind_command_request`) — the shell command extracted
5. **Command Result** (`kind_command_result`) — stdout, stderr, exit code,
   `finished_at` timestamp

Each entity links back to its predecessor via `about_thought` or
`about_exec_result`, forming a provenance chain.

## Provider Artifacts

The raw provider response is stored alongside the canonical turn structure.
This preserves provider-specific data (usage metadata, model identifiers,
reasoning traces) without polluting the canonical format.

## Memory / Moment Boundary

The context window is split into two regions separated by the **breath**
boundary (see `playground_memory_architecture.md`):

- **Memory**: curated summaries from the memory branch, stable across turns
- **Moment**: recent shell interactions from the cognition branch, changing
  each turn

The breath markers (`"breath"` / `"present moment begins."`) are static
strings that anchor the Anthropic prompt prefix cache. Everything before the
breath is cacheable; everything after is the dynamic tail.

## Context Fill

The last user message in each turn is annotated with the current context fill
percentage, giving the model awareness of how much of its context window is
in use. This allows the model to decide when to consolidate memory (freeing
moment space) or when to be more concise.
