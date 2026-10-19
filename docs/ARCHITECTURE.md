# Architecture (index)

Canonical enforced rules live in `sentinel/ARCHITECTURE.md` (dependency rule,
ports, CQRS, fitness tests).

Phase 0 baseline (current vs target, API surface, Eighth Review context):
`docs/ARCHITECTURE_BASELINE.md`.

Protect / tool runner: in-process agents use `container.tool_runner.execute`.
External agents that skip it are outside F-11 enforcement.
