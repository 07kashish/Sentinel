# Sentinel — Runtime Trust and Verifiable Execution for Autonomous AI Agents

Sentinel is an **early-stage** runtime trust layer for autonomous agents. It
ingests signed agent runtime events, evaluates them against a deterministic
policy, correlates them into a causal execution graph, escalates proposed
remediations to a human, and can optionally anchor incident evidence via an
attestation gateway.

The capability it is being built around is **verifiable agent execution**: which
actor performed an action, under whose authority, through which tool or MCP
path, against which resource, under which policy, and with what evidence.

**Status: pre-production.** Not a SOC replacement. Not "production-ready".
Durable storage, fail-closed auth, execution fencing, and honest attestation
dispositions are in place. Detection is a configurable policy engine plus an
advisory statistical path that is **not** in the control plane.

## Five-minute quickstart

No Docker, no accounts, no `.env`:

```bash
pip install -r requirements.txt   # from this checkout. This project is NOT on PyPI: see the note below
PYTHONPATH=. python scripts/quickstart.py
```

> **Do not `pip install sentinel-agent-trust`.** This project has never been published to PyPI or
> any other registry. A package with that exact name exists on PyPI, uploaded in July 2026 by a
> different publisher; installing by name fetches THEIR code, not this repository. Install only
> from a checkout (`pip install -e ".[server]"`) or from a wheel you built yourself.

It starts the real ASGI app on SQLite in a temp directory, submits a staged
exfiltration -- `read_file` then `zip` then `http_post` to an external host --
and shows the incident that comes back. Measured at **2.3s** end to end on the
development machine; the script prints its own elapsed time, so the number you
see is yours rather than this README's.

Everything it exercises is the shipped code path. There are no stubs and no
fixtures, because a demo that mocks the thing being demonstrated proves
nothing. The attack is the tracked red-team case `staged_exfiltration`, not an
invented one, so a newcomer's first impression is a case the release gate
asserts on every build.

**It exits non-zero if no incident is raised.** A quickstart that congratulates
you on a broken build is worse than no quickstart, so the verdict is computed
from whether an incident actually came back -- not from having reached the end
of the script. It also cross-checks two independent reports of the same fact
(the submission response and the incident list) and fails if they disagree.

You will notice that **nothing is blocked**. That is deliberate and is
explained in [docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md):
correlation is self-reported, so blocking on it would let an attacker halt
someone else's agent by forging a chain. Sentinel detects far more than it
prevents, on purpose.

For the full stack -- PostgreSQL, Prometheus, Grafana, Keycloak, Jaeger --
`docker compose up -d`.

## What runs today

Hexagonal package `sentinel/` (domain / application / infrastructure /
composition / interface), with architecture fitness tests in `tests_arch/`.

```text
sentinel/
  domain/           # Incident lifecycle, Fence, errors, protect decisions
  application/      # Commands, queries, saga engine, ports
  infrastructure/   # SQL, detection policy, attestation HTTP, evidence
  composition/      # Container + Settings (sole wiring site)
  interface/        # FastAPI HTTP, ASGI factory, worker, CLI
tests_arch/         # Architecture, chaos, concurrency, security, mutation
evaluation/         # Honest detection metrics gate
config/             # default_policy.json
docs/               # Architecture baseline, remediation matrix, threat model
```

The legacy `api/`, `app/`, `agents/`, and `dashboard/` trees are **gone**.

## HTTP API (actual)

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/events` | Ingest. Capability `ingest_event`. No client-asserted severity. |
| POST | `/v1/protect/evaluate` | Pre-action policy gate. Capability `evaluate_protect`. |
| POST | `/v1/mcp/evaluate` | MCP tool call: server trust + tool-definition drift, then the same policy. Capability `evaluate_protect`. Enrolment is CLI-only. |
| POST | `/v1/mcp/proxy/{server_id}` | MCP wire proxy (JSON-RPC/Streamable HTTP). Forwards to ENROLLED servers only; `tools/call` evaluated against the live definition; drifted listings, duplicate tool names, changed server identity and foreign OAuth issuers all refused. Registered only when `SENTINEL_MCP_PROXY_ENABLED` is set. Capability `execute_tool`. |
| POST | `/v1/tools/execute` | Inline tool proxy. Effects register only where configured: `read_file`, `write_file`, `http_request`, plus `aws_api`, `github_api`, `kubernetes_api`, `sql_query` where platform credentials are supplied. Every platform effect carries a tier ceiling checked **after** the gate allows. |
| POST | `/v1/a2a/evaluate` | Delegation chain: privilege amplification, loops, agent-card drift, cross-agent injection, then the same policy. Capability `evaluate_protect`. |
| POST | `/v1/a2a/proxy/{agent_id}` | A2A wire proxy (JSON-RPC). Forwards to ENROLLED agents only; the delegation is refused BEFORE the message moves, the agent card is drift-checked against what the peer serves now, and the REPLY is inspected too. `message/stream` is NOT_SUPPORTED. Registered only when `SENTINEL_A2A_PROXY_ENABLED` is set. Capability `execute_tool`. |
| POST | `/v1/a2a/cards` | Enrol an agent card and pin its fingerprint. Capability `manage_policy` (admin). **In-process store**. |
| POST | `/v1/skills/assess` | Explainable skill risk + static source scan that never executes what it inspects. Capability `evaluate_protect`. |
| GET | `/v1/incidents`, `/v1/incidents/{id}`, history, report | Read capabilities |
| GET | `/v1/dashboard` | Tenant summary JSON (not an HTML UI) |
| POST | `/v1/approvals/{id}` | Approve/reject remediation |
| GET | `/health/live` | Process up. Opaque. |
| GET | `/health/ready` | DB + keys configured. Opaque. |
| GET | `/health/diagnostics` | Detail behind `read_diagnostics` |

Serve with:

```bash
python -m sentinel.interface.cli migrate
gunicorn "sentinel.interface.asgi:create_application()" --worker-class uvicorn.workers.UvicornWorker
```

## Protect mode (honest)

`POST /v1/protect/evaluate` runs the **deterministic policy** only (no LLM, no
classifier in the gate). Decisions: `allow`, `warn`, `require_approval`, `block`.

- Default: advisory. Every response has `enforced: false`.
- With `SENTINEL_PROTECT_ENFORCE=true`, stopping decisions set `enforced: true`.
  Callers are under contract to abort. Sentinel is **not** an inline network
  interceptor; without integration honouring the response, nothing is blocked
  on the wire.

## Detection (honest)

Measured performance against labeled corpora is published by the evaluation gate,
not asserted as marketing. Cross-source statistical AUC remains limited; expected
calibration error is high. The classifier is a second opinion alongside
deterministic rules — never merged into the control path.

```bash
PYTHONPATH=. py evaluation/metrics.py --json evaluation/metrics.json
```

Methodology: `evaluation/BENCHMARK.md`. Do not treat current numbers as
production SOC evidence.

## Observe vs protect

- **Observe (default ingest):** agents emit events after actions; Sentinel records,
  detects, investigates, proposes approvals. Nothing executes automatically
  without a human decision and a configured integration.
- **Protect (evaluate):** agents ask before high-risk tool calls. Enforcement is
  optional configuration + caller honouring `enforced`.

## Setup

1. Python 3.12+
2. `pip install -r requirements.txt` (dev: `requirements-dev.txt`)
3. Copy `.env.example` → `.env` and set `SENTINEL_API_KEYS=tenant:key:role`
4. `python -m sentinel.interface.cli migrate`
5. Run ASGI entry above

Optional: attestation gateway via `SENTINEL_ATTESTATION_ENDPOINT` + token (https only).
Without a gateway, incidents complete as `completed_unattested` — never as fake success.

## Tests and quality

```bash
pytest -q tests_arch/
ruff check sentinel tests_arch
```

CI also runs detection metrics, mutation suites, bandit, and container smoke tests.
See `.github/workflows/ci.yml`.

## Docs

- `docs/ARCHITECTURE.md` — current vs target, API surface, risks
- `docs/REMEDIATION_MATRIX.md` — Eighth Review F-1..F-12 status
- `sentinel/ARCHITECTURE.md` — enforced dependency rules
- `docs/THREAT_MODEL.md` — edge findings (**different** F-numbering)
- `docs/MCP_GATEWAY.md` — MCP server trust, tool pinning, description poisoning
- `docs/TOOL_GATEWAY.md` — OpenAPI ingestion, tool adapters, SIEM export

## What this README does not claim

- Production readiness
- Live HTML dashboard / MONITORING LIVE
- Inline kill-switch without integration
- Improved AUC beyond measured evaluation output
- **A2A streaming.** `message/stream` and `tasks/resubscribe` return
  `NOT_SUPPORTED`: a gate in front of an SSE stream must either buffer it — which
  is not streaming — or forward chunks nobody evaluated.
- **Interception of traffic that bypasses the proxy.** The A2A wire proxy puts
  the gate in the path for agents pointed at it; a framework that never points at
  Sentinel is still outside enforcement, exactly as F-11 records for the tool
  proxy.
- **That a clean skill scan means a skill is safe.** The scanner parses and never
  executes; name matching is defeated by runtime construction. Every `ScanResult`
  carries that limit in its own `limits` field.
- **S3, Kafka, or `kubectl exec`.** Each is absent by decision rather than
  half-implemented, and each says so where an operator will hit it.

## Licence

Proprietary — all rights reserved. See [LICENSE](LICENSE). Reading the source
is not a licence to use it; production use requires a written agreement.

## Status documentation

- Branch protection status: [docs/BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md) — **currently unenforced**, and the document explains why
- Pre-production readiness: [docs/PRODUCTION_READINESS_REPORT.md](docs/PRODUCTION_READINESS_REPORT.md)
- Eighth Review F-1..F-12: [docs/REMEDIATION_MATRIX.md](docs/REMEDIATION_MATRIX.md)
- Historical artifacts (**not current truth**): [docs/history/](docs/history)
