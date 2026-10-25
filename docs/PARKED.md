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
[]
```
<!-- removed-settings:end -->
