## Where they are right and I was wrong

Both Claude Opus and Codex correctly identified that the pipeline is not resumable because `pipeline.process()` unconditionally starts at `advance(State.VALIDATED)` (`api/pipeline.py:108`). If a worker crashes mid-incident and the item is reclaimed, it hits an `IllegalTransition` and fails permanently, contradicting the claim that it's crash-safe without losing work.

Claude Opus correctly found that the `dlq.enqueue` call in `api/main.py:155` transposes positional arguments (`str(e)` is passed as `max_attempts` which expects an `int`), which will corrupt the database on SQLite or crash on Postgres. Since `drain` is never scheduled, it's a silent drop reproducing the v2/v3 disaster.

Claude Opus correctly found that `test_no_overclaiming.py` evaluates weak conditions: `test_absent_capabilities` skips checks if "does not" appears nearby (`tests/test_no_overclaiming.py:108-111,137-138`), and `test_readme_states_detection_numbers` pools all metrics without matching them to specific claims, allowing transposed labels to pass (`tests/test_no_overclaiming.py:214-220`).

Codex correctly found that the incident creation and queue enqueue happen in separate transactions (via `BackgroundTasks` at `api/main.py:606-617`), so a crash after returning the API response but before the background task enqueues will permanently strand the incident with `"processing": true`.

Codex correctly found that `app/storage/adapter.py:117` claims to map `INSERT OR IGNORE` to `ON CONFLICT DO NOTHING`, but actually merely strips `OR IGNORE`, translating it to `INSERT INTO`. This breaks deduplication on Postgres entirely.

Codex correctly found that the durable queue lacks fencing on `complete()` and `fail()`, meaning a slow worker can still overwrite state after its claim has timed out and another worker picked it up.

## Where they are wrong

**Claim:** "But `apply_retention` iterates a table list still containing `("incidents", "created_at")` (`db.py:696`)... Every hourly run raises `OperationalError: no such table: incidents`" (Claude Opus & Codex)
**Refutation:** This is false. In `app/storage/db.py:696-699`, the `("incidents", "created_at")` line is explicitly commented out, and the comment acknowledges "Council v4 found this". `apply_retention` no longer references the deleted table and does not raise this error.

**Claim:** "A second, file-backed metric store (`system_metrics.py`) is still written (`main.py:435-438`) despite the 'counters are derived, never stored' claim." (Claude Opus)
**Refutation:** This is false. `api/main.py:435-438` contains only a comment block explaining that the JSON counter store was deleted. The file `system_metrics.py` does not exist in the codebase.

## What all of us missed entirely

In `app/storage/db.py:691-705`, `apply_retention` deletes `reports` and `evidence` using `created_at` before it deletes `incident_state`. If an incident is older than the retention window, the artifacts it relies on will be purged. Since `get_incident()` and the dashboard can still query `incident_state` if it survives (e.g., if the incident was updated later or deletion was incomplete), the system can be left in `COMPLETED` state but the `ArtifactMissing` guard would fail if it were evaluated again, or any report queries would return null. The retention policy violates the structural integrity of the lifecycle graph because it destroys the artifacts that the state machine asserts must exist durably.

## The disagreement that actually matters for the decision

The disagreement is whether the core architecture (repository and lifecycle) genuinely solved the split-brain state, or if the "relocated" bugs at the boundaries (DLQ enqueue bug, non-atomic incident/queue handoff, lack of queue fencing) mean the product remains fundamentally broken. While the inner lifecycle transaction is sound on paper, the boundary handoffs guarantee that evidence is dropped silently under failure and duplicate execution can occur. In a SOC product built around attestation and non-repudiation, a failure to capture failures durably is a fatal flaw, not just an edge case.

## My revised position

**Unchanged: NO.** While the single-writer repository is a real structural improvement, the system fails to deliver its core value proposition. The boundary defects—specifically the non-atomic handoff to the durable queue, the `dlq.enqueue` positional argument crash, the lack of fencing in `DurableQueue.complete`, and the broken `INSERT OR IGNORE` translation on PostgreSQL—collectively ensure that data loss and split execution paths still occur in production. A security product that silently drops failure evidence and breaks its own deduplication on its primary database engine is not viable.