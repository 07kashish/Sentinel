# Sentinel

Sentinel provides independent, cross-vendor oversight of the AI agents a company runs.

It records activity sent through its integrations, evaluates deterministic policy,
requires approval where policy demands it, executes configured tools through
bound authorizations, and preserves evidence of the result. It does not discover
every agent in a company or observe activity that never reaches an integration.

## Observe → Decide → Act → Prove

- **Observe:** accept tenant-scoped events, record agent activity, maintain observed
  inventory and execution graphs, and inspect calls through enrolled MCP servers.
  The operator console shows the records Sentinel actually received.
- **Decide:** deterministic rules and tenant policy evaluate actions. Identity,
  capability grants, containment and execution controls constrain the result.
  Human approval is required when policy calls for it. Optional model advice is
  recorded as advisory text and cannot authorize an action or set its priority.
- **Act:** configured tools run through the approval and execution-binding path.
  Retained adapters include AWS, GitHub, Kubernetes, a constrained PostgreSQL
  target, scoped file/HTTP tools and registered business applications. Remediation
  webhooks remain available through the guarded executor. Unconfigured adapters
  are absent; a decision alone is not evidence that an action ran.
- **Prove:** operation records, execution receipts, evidence commitments,
  transparency proofs and Execution Passports support later verification.
  Declared identity and intent remain distinguishable from verified identity and
  observed effects. Unknown outcomes remain unknown until reconciled.

Protection defaults to advisory mode. Execution binding defaults on, but those
are separate controls: advisory decisions do not promise enforcement. Explicit
configuration, valid credentials and the applicable approval are still required
for consequential execution.

## Local quickstart

Use Python 3.12 or later and a clean checkout of this branch. These commands were
run in a fresh Linux/WSL clone with a new virtual environment and SQLite database
during Phase 4. The token is generated locally; do not reuse local development
configuration as a production deployment.

From the repository directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ".[server]"
export SENTINEL_ENV=development
export SENTINEL_DB_PATH="$PWD/data/sentinel.db"
export SENTINEL_API_KEYS="local:$(python -c 'import secrets; print(secrets.token_urlsafe(32))'):admin"
python -m sentinel.interface.cli migrate
python -m uvicorn sentinel.interface.asgi:create_application --factory --host 127.0.0.1 --port 8000
```

Keep the server running and use another terminal:

```sh
curl --fail http://127.0.0.1:8000/health/live
curl --fail http://127.0.0.1:8000/health/ready
```

The verified responses were `{"status":"ok"}` and `{"ready":true}`. Stop the
server with Ctrl+C. Migration is an explicit deployment step; startup verifies
the schema version and does not migrate automatically.

The console is at <http://127.0.0.1:8000/console>. It loads a public static shell;
its data requests require a bearer token. Use the token portion of the configured
API-key entry for local operator access. Event submission uses a separate ingest
role: an admin token cannot fabricate telemetry.

**Docker: UNVERIFIED (not installed in WSL).** Neither the image nor the Compose
path was tested in Phase 4. Checkpoint 2 remains blocked on Docker verification.
The native quickstart above is the verified path.

## Configuration and interfaces

The minimum local inputs are an API-key binding and a writable database path.
The defaults select development mode and SQLite. Production requires PostgreSQL,
strong credentials and explicit security choices; it is not obtained by exposing
the local server to a network.

See the [full configuration reference](docs/CONFIGURATION.md) for every retained
field, default, environment input and operational control. The
[example environment](.env.example) contains examples, including optional groups
that must be fully configured or left unset.

The Python SDK has no third-party runtime dependencies. MCP calls can use the
opt-in HTTP proxy or the stdio bridge. The proxy evaluates enrolled server trust,
tool-definition drift and deterministic policy, then inspects replies. Real
platform execution is available only where the corresponding adapter is
configured. See [integrations](docs/INTEGRATIONS.md) and
[architecture](docs/ARCHITECTURE.md) for those boundaries.

API routes require an authenticated principal and a capability. The explicit
public exceptions are liveness, readiness and the three static console resources.
Prometheus metrics require a separate scrape token. The optional OpenAPI schema
requires diagnostics permission and is unavailable in production; interactive
Swagger/ReDoc UIs are not shipped as routes.

## Parked and planned

Detonation, endpoint collection, vendor inventory discovery, estate analysis,
SOAR notifications/playbooks, orgs/SCIM, A2A and legacy partitioning are parked.
[The parked-feature record](docs/PARKED.md) explains what was removed, where to
recover it and what customer evidence would justify reconsidering it.

**Phase 5 is planned, not built, and has not started.** The recorded next work
includes agent-registry and audit-log connector work (5.1/5.2), using the archived
GitHub/Slack/identity helpers only as references. It must restore verified answers
about actor, authenticated identity, delegator and granted permissions through the
registry and retained identity/authorization paths; the planned
`oversight_demo.py` (5.6) must demonstrate those answers. The current execution
trust demo explicitly leaves questions 1–4 unanswered, along with 14 and 18.

See [CLEANUP_PLAN.md](CLEANUP_PLAN.md) and [CHANGES.md](CHANGES.md) for measured
cleanup results, verification limits and decisions. See
[testing](docs/TESTING.md), [operations](docs/OPERATIONS.md) and
[security](docs/SECURITY.md) for their respective procedures and constraints.

## License

See [LICENSE](LICENSE).
