# Deployment

## Runtime entry

```bash
python -m sentinel.interface.cli migrate   # deployment step, not boot
python -m sentinel.interface.cli verify    # O(1) schema version check
gunicorn "sentinel.interface.asgi:create_application()" \
  --worker-class uvicorn.workers.UvicornWorker
```

Importing modules starts nothing. Workers attach in ASGI lifespan.

## Required configuration

| Variable | Purpose |
|---|---|
| `SENTINEL_ENV` | development / staging / production |
| `SENTINEL_API_KEYS` | `tenant:key:role` (min length enforced in production) |
| DB | `SENTINEL_DB_PATH` (SQLite) or Postgres DSN settings |
| `SENTINEL_PROTECT_ENFORCE` | `true` only when callers honour protect / tool_runner |
| `SENTINEL_PROTECT_KILL_SWITCH` | `true` refuses all tool side effects (fail closed) |
| `SENTINEL_TOOL_BUDGET_PER_MINUTE` | per-agent tool execution budget (0 = off) |
| `SENTINEL_OIDC_ISSUER` / `AUDIENCE` / `JWKS_JSON` | optional JWT path (all-or-nothing) |
| `SENTINEL_METRICS_TOKEN` or `_FILE` | required for `/metrics/prometheus` scrape |
| `SENTINEL_OTLP_ENDPOINT` | optional; enables in-process OTel-shaped hooks |
| `SENTINEL_ATTESTATION_ENDPOINT` + token | optional; https only |
| `SENTINEL_REDIS_URL` | required whenever more than one process serves traffic — see below |
| `SENTINEL_RATE_LIMIT_FAIL_OPEN` | required explicit in production |
| `SENTINEL_SINGLE_PROCESS_ATTESTED` | only consulted when the topology cannot be observed |
| `SENTINEL_REQUIRE_EXECUTION_BINDING` | required explicit in production — see below |

### Binding every execution to an authorization

`SENTINEL_REQUIRE_EXECUTION_BINDING` decides whether the **unbound** tool path
still works.

`ProtectedToolRunner.execute` takes a description of the intended action and,
separately, an opaque zero-argument closure. Policy is evaluated over the
description; the closure then runs and can do anything. So an agent approved to
write one bucket can write another, and the passport, its signature and the
transparency proof all still verify — because each is a true statement about
the *decision*, and the decision was never about what ran.

`execute_bound` closes that: it takes an `ExecutionAuthorization` committing to
a parameter digest, re-checks the digest immediately before the side effect, and
passes the **verified** parameters into the tool.

| Value | Effect |
|---|---|
| `false` | both paths work. The deployment is only as bound as its call sites happen to be |
| `true` | the unbound path refuses. Every side effect needs an authorization |

**Production refuses to start unless you state one.** There is no safe default:
`false` leaves unbound executions possible, `true` stops any call site not yet
migrated, and a security control that takes the service down on upgrade gets
reverted rather than adopted. Same reasoning as
`SENTINEL_RATE_LIMIT_FAIL_OPEN`.

Migrate call sites to `execute_bound`, then set this to `true`. Until it is
`true`, do not describe the deployment as binding authorization to execution —
see [`ARCHITECTURE.md`](ARCHITECTURE.md#execution_trust_architecture) for the
residual that remains even when it is.

### The process count is observed, not declared

A per-process rate limiter is only the whole limiter if there is one process.
`SENTINEL_WORKER_SHARD_COUNT` used to be the only signal, and it is a
declaration — so

```bash
uvicorn sentinel.interface.asgi:app --workers 4
```

with that variable unset left the declared count at 1, passed every check, and
gave you four independent limiters each permitting the full configured rate.

Startup now reads the process table instead: the worker flag on the launch
command, and sibling processes sharing the same parent and executable. If more
than one process is serving and `SENTINEL_REDIS_URL` is unset, **the service
refuses to start** and says how many processes it saw. Correcting
`SENTINEL_WORKER_SHARD_COUNT` will not clear that refusal, because it is not
what was read.

**On Windows there is no `/proc`, so the count is `UNOBSERVABLE`** — which is
deliberately not treated as "one process". In production that also refuses,
unless you set `SENTINEL_SINGLE_PROCESS_ATTESTED=true` to state on the record
that this deployment runs a single process. An attestation cannot override a
contradicting observation; if the process table says four, four is the answer.

Outside production the unobservable case passes, because a developer machine
that cannot be inspected is also not serving traffic.

`sentinel preflight` cannot check any of this and says so in its own output.
Running the observation from a CLI would report on the CLI — one process, every
time, whatever the deployment looks like.

## Kubernetes / Helm

- Manifests: `deploy/k8s/sentinel.yaml`, `deploy/helm/sentinel/`
- CI validates: `helm lint`, `kubeconform`, probe paths against live router
- Probes must hit `/health/live` and `/health/ready` (not a generic `/health`)
- Chart includes NetworkPolicy, PDB, HPA templates

## Local kind / k3d validation (operator)

```bash
# kind example
kind create cluster --name sentinel
helm lint deploy/helm/sentinel --strict
helm template sentinel deploy/helm/sentinel > /tmp/sentinel-rendered.yaml
kubeconform -strict -summary /tmp/sentinel-rendered.yaml
# After secrets exist for postgres/auth/metrics/signer:
# helm upgrade --install sentinel deploy/helm/sentinel -n sentinel --create-namespace
# kubectl -n sentinel rollout status deploy/sentinel
# kubectl -n sentinel get --raw /api/v1/namespaces/sentinel/services/http:sentinel:8000/proxy/health/ready
```

## Cluster drills

**UNVERIFIED in this environment** — no live cluster was exercised for this report.
Operators must: apply manifests in a staging cluster, confirm probes, rolling
restart, and multi-replica rate-limit behaviour with Redis.

### Why it is still UNVERIFIED (checked 2026-08-12)

Not an inference — each precondition was probed and failed:

```console
$ docker --version ; kind --version ; helm version ; kubectl version
docker  : NOT INSTALLED
kind    : NOT INSTALLED
helm    : NOT INSTALLED
kubectl : NOT INSTALLED

$ wsl.exe -l -v
Windows Subsystem for Linux has no installed distributions.

$ powershell -c "[Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')"
IsAdmin: False
```

Installing Docker Desktop or `wsl --install <Distro>` both require elevation,
and this workspace has no administrator rights. That is the blocking precondition
— not a missing step someone forgot to run.

**CI run status is also unreadable from here**, so "the workflow file exists" is
the only thing established about `kind-helm-smoke`; whether it has ever gone
green is unknown:

```console
$ gh run list --limit 5
To get started with GitHub CLI, please run:  gh auth login

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    "https://api.github.com/repos/Loksjain/Sentinel/actions/runs?per_page=5"
HTTP 404
```
