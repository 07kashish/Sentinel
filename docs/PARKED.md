# Parked features

Phase 3 removes the features listed here from the current product. Their original
implementations remain recoverable from the immutable `archive/pre-cleanup` tag.
An entry is marked complete only after its routes, configuration, runtime and
feature-only tests are removed and the required checks pass.

## MCP compatibility decision

MCP reply inspection retains the deterministic ProtectGate, unsigned trust,
bounded text extraction, refusal handling, receipts and streaming. Its policy
payload preserves eventType, action, resource, agentId and metadata.prompt;
synthetic metadata.a2a is retired.

Custom policy rules matching metadata.a2a.* (or eventType agent_delegation from A2A) no longer match anything; no shipped rule used them.

This retirement applies to A2A-originated events when A2A is parked. MCP reply
events retain `eventType: agent_delegation` for compatibility. Operators with
custom rules depending on the retired A2A metadata must migrate those rules.

## Removed environment settings

The executable scan reads this catalog and also checks `_FILE` variants. A name
ending in an underscore represents a retired configuration prefix. Removal
records retain full names in exactly CHANGES.md, CLEANUP_PLAN.md and this file;
the scan checks every other tracked or unignored product file.

<!-- removed-settings:start -->
```json
[
  "SENTINEL_DETONATION_IMAGE",
  "SENTINEL_DETONATION_TRACING"
]
```
<!-- removed-settings:end -->

## Detonation and skill assessment

Purpose: isolated skill execution, syscall tracing and skill manifest/source assessment.
Removed 19 whole files (6,205 physical lines); shared-file cuts are reported in CLEANUP_PLAN.md.
Removed route: `POST /v1/skills/assess`. Removed settings: `SENTINEL_DETONATION_IMAGE`, `SENTINEL_DETONATION_TRACING` (including `_FILE` variants). No dedicated tables.
Restore signal: a contracted customer requires running untrusted third-party skills in an isolated sandbox with independently verified syscall evidence.

Recovery paths at `archive/pre-cleanup`:

- `deploy/detonation/Dockerfile`
- `sentinel/application/skill_detonation.py`
- `sentinel/composition/detonation_wiring.py`
- `sentinel/domain/detonation.py`
- `sentinel/domain/observed_binding.py`
- `sentinel/domain/skills.py`
- `sentinel/infrastructure/detonation_container.py`
- `sentinel/infrastructure/detonation_tracing.py`
- `sentinel/infrastructure/skill_scanner.py`
- `sentinel/infrastructure/strace_parse.py`

Test recovery directory: `tests_arch/` at the same archive tag. Exact retired test paths are listed in [the cleanup inventory](../CLEANUP_PLAN.md).
