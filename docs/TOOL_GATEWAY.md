# Tool gateway: OpenAPI ingestion, real adapters, action semantics, SIEM

## Action semantics: what a platform operation MEANS

The policy engine matches text. Text matching knows `.env` is sensitive; it does
not know that `iam:AttachUserPolicy` is privilege escalation while
`iam:ListUsers` is inventory, that `kubectl exec` is code execution while
`kubectl logs` is reading, or that `PUT /repos/o/r/branches/main/protection`
rewrites who may ship code. `sentinel/domain/action_semantics.py` encodes those
grammars for the Tier-1 platforms — AWS, Kubernetes, GitHub, SQL — as pure
classification: platform, operation, category (read / write / destructive /
privilege / credential / execution / export) and tier (low → critical), with
the reasons.

**It never decides ALLOW or BLOCK.** `enrich_payload` writes the result into
`metadata.semantics`, and `config/default_policy.json` carries ordinary rules
matching `metadata.semantics.tier`. So the deterministic policy engine stays
the single decision-maker, the classification arrives in the verdict as a
matched rule an analyst can read, and a deployment that disagrees edits policy
rather than code — the same projection pattern the MCP gateway uses.

Caller-supplied `metadata.semantics` is **always discarded** before enrichment.
The field is an input to policy, so a caller allowed to assert it would be a
caller allowed to pre-classify its own actions.

Classification is by recognised form only. An action in none of the grammars
gets **no label at all** rather than a default tier — a wrong "low" would be an
attacker's favourite label. Renaming and encoding evade this exactly as they
evade any static analysis: it raises the floor for the common honest shapes and
is not a model of intent.


Companion to [MCP_GATEWAY.md](MCP_GATEWAY.md), which documents the trust engine
these share.

## OpenAPI: ingestion, not a second gateway

An agent handed an OpenAPI document gets what an MCP server gives it — named
operations, each with prose the model reads as instructions and a schema saying
what it may send. The three questions are identical, so a spec is **converted**
into the tool definitions `McpGateway` already pins rather than getting a second
trust engine beside it. Two engines would be two places for the answers to
disagree.

```bash
python -m sentinel.interface.cli openapi-enrol acme reports-api openapi.json https://api.example.com
```

**The fingerprint covers method, path, merged path-item parameters, requestBody
and `security`** — not just the parameter list. This is what catches the case a
name-based allowlist cannot see:

| Change | `operationId` | Result |
|---|---|---|
| Nothing | `getReport` | allowed |
| `summary` gains injected prose | `getReport` | refused, `definition_changed` |
| `/v1/reports/{id}` → `/v1/admin/{id}` | `getReport` (**unchanged**) | refused, `definition_changed` |

Executed, not asserted in prose — see the table above reproduced by
`test_moving_an_operations_path_changes_its_fingerprint_although_the_id_is_identical`
and `test_dropping_a_security_requirement_changes_the_fingerprint`.

Path-item `parameters` are merged into every operation beneath them, because a
parameter added one level up applies to all of them and reading only the
operation's own list would leave the fingerprint still while the capability
moved (`test_path_item_parameters_are_merged_into_every_operation_under_it`).

Both `summary` and `description` are carried, because generators put
instruction-shaped text in either and a scanner reading one is evaded by using
the other.

### Bounds, and one honest limit

A spec is untrusted input parsed *before* anyone has decided to trust it, so it
is bounded on every axis a hostile author controls: operation count
(`MAX_OPERATIONS`), schema depth (`MAX_SCHEMA_DEPTH`), prose length. Long
descriptions are **truncated** rather than refused — a wordy vendor is far more
common than an attack, and refusing a whole spec over one field pushes operators
to skip enrolment entirely.

**`$ref` is not resolved.** Following pointers inside an unreviewed document,
possibly across files or in a cycle, is not something to do before the trust
decision. The consequence is real and stated rather than hidden: if a `$ref`
target changes, the referring schema is unchanged and the pin does not move.

## Real tool adapters

The inline proxy shipped with only `echo` and `noop` registered, which meant the
enforcement path around it had never governed an effect that could cause harm.
`read_file`, `write_file` and `http_request` now exist.

**The gate decides policy; the adapter enforces containment.** `ProtectGate`
reasons about the request as *described*. The adapter reasons about what it
*resolves to* — and no policy engine can know that `notes.txt` is a symlink to
`/etc/shadow`, because that fact does not exist until something follows the
link. So every adapter re-checks its invariants **after** the gate has said
ALLOW, and every containment test runs the adapter directly with no gate in
front of it (`test_containment_holds_even_when_the_gate_allows_the_call`).

Filesystem containment resolves **first**, then checks:

- checking the string first misses `a/../../etc/passwd`;
- comparing a resolved path against an *unresolved* root refuses every
  legitimate path wherever the root itself contains a symlink (`/tmp` is
  `/private/tmp` on macOS), and a check that refuses everything gets switched
  off by whoever is on call
  (`test_a_root_containing_a_symlink_still_accepts_its_own_files`);
- containment uses `is_relative_to`, not a string prefix, so `/srv/sandbox-evil`
  is not inside `/srv/sandbox`
  (`test_a_sibling_directory_with_the_same_prefix_is_not_inside`).

`http_request` reuses the existing `HardenedHttpClient` — post-resolution address
validation, connection pinned to the validated address so DNS rebinding has
nothing to rebind, redirects refused, response bounded. Writing a second client
would mean the path an *attacker* reaches is the one that never got those
defences. Caller-supplied headers are **not** forwarded: an agent that can set
headers can set `Authorization`.

### Fail closed by absence

| Variable | Unset (default) |
|---|---|
| `SENTINEL_TOOL_FILE_ROOT` | `read_file` / `write_file` are **not registered** |
| `SENTINEL_TOOL_HTTP_ALLOWED_HOSTS` | `http_request` is **not registered** |

An unconfigured adapter is *absent*, not present-and-disabled — the proxy already
refuses unregistered tools, so the safe state is enforced by code that exists
rather than by a flag one boolean away from being on.

The two symlink tests skip on Windows, where creating symlinks needs privileges;
they run on `ubuntu-latest` in CI. The skip is reported, never silent.

## Tier-1 platform adapters: AWS, GitHub, Kubernetes, PostgreSQL

`action_semantics` above knows what `iam:AttachUserPolicy` means. Until these
adapters existed it was classifying events that had **already happened somewhere
else** - Sentinel could name the consequence and could not stand in front of it,
because the only effects the enforcement path governed were reading a file,
writing a file and fetching a URL.

`sentinel/infrastructure/platforms/` registers four more into the **same**
`InlineToolProxy` effects mapping, so they reach an agent only through the kill
switch, the capability grant, `ProtectGate`, the budget and the circuit breaker.
There is no second execution path for the higher-privilege effects.

### The confused deputy, and the rule that defeats it

This process holds credentials the agent must never aim. An adapter that takes a
caller-supplied path *and* a caller-supplied label is a confused deputy by
construction: the agent declares `action="iam:ListUsers"` - classified low,
allowed by policy - and supplies `path="/?Action=CreateAccessKey"`, and Sentinel
signs it with the deployment's own key. Policy saw one operation; AWS performed
another.

> **The classified label and the transmitted request are built from one input.**

Nothing accepts a raw URL, a raw host, or a label sitting alongside a request
that could contradict it.

| Adapter | The single input | Derived from it |
|---|---|---|
| `aws_api` | `iam:CreateAccessKey` | classification, service, endpoint host, wire protocol, the `Action` AWS performs |
| `github_api` | `(method, path)` | classification and the request line |
| `kubernetes_api` | `(verb, kind, namespace, name)` | classification and the API path |
| `sql_query` | the statement | classification and what the database runs |

The AWS parameter validator refuses a caller-supplied `Action` or `Version`
outright (`test_aws_parameters_may_not_carry_their_own_action`), the GitHub path
may not carry a host or a query string
(`test_github_path_may_not_carry_a_host`,
`test_github_query_cannot_smuggle_a_second_path`), and the destination host is
never caller-supplied - it is operator configuration, or it is derived from the
service in the classified action.

### The tier ceiling is containment, not policy

Each adapter carries a **ceiling**: the highest semantic tier it will perform,
checked *after* `ProtectGate` has already said ALLOW. Same distinction
`FileSandbox` draws. The gate judges the request **as described**; the ceiling
judges what it **resolved to**, and it survives a policy misconfiguration, an
injection that talks the gate into an ALLOW, and a rule someone deleted
(`test_aws_ceiling_refuses_privilege_escalation_the_gate_allowed`).

The default is `low` - read-only - for a platform configured without one
(`test_the_ceiling_by_omission_is_read_only`).

**Unclassifiable is refused.** The ceiling is the only containment these adapters
have, and an action nobody could classify cannot be checked against it
(`test_aws_refuses_an_action_it_cannot_classify`,
`test_sql_refuses_a_statement_it_cannot_classify`).

### What is deliberately absent

- **S3.** Its REST protocol needs per-operation path and payload signing that
  does not generalise from the POST-to-`/` shape the signer implements. A
  half-working S3 adapter would be a capability claim the module could not
  honour (`test_aws_refuses_a_service_it_cannot_address`).
- **`kubectl exec` / `attach` / `port-forward`.** Not blocked - *absent*. No
  entry in the verb table, so no code path builds one, at any ceiling
  (`test_kubernetes_exec_is_unreachable`).
- **GitHub `PATCH`.** `HardenedHttpClient` permits GET/HEAD/POST/PUT/DELETE, and
  widening that allowlist for one adapter's convenience would weaken every other
  caller in the process.

### No new dependencies

No `boto3`, no `kubernetes`, no `PyGithub`. Each brings its own HTTP stack,
which would route the **highest-privilege egress in the product** around
`HardenedHttpClient`: no post-resolution address validation, no connection
pinning, redirects followed by default. SigV4 is an HMAC ladder over stdlib,
pinned to the published `aws4_testsuite` vector rather than to its own output
(`test_sigv4_matches_the_published_aws_test_vector`). PostgreSQL uses `psycopg`,
already a dependency because Sentinel's own store is PostgreSQL.

### Three containments on SQL, because text matching loses

1. the tier ceiling, from `action_semantics`;
2. one statement per call, so a classified `SELECT` cannot carry a `DROP`
   (`test_sql_multi_statement_is_refused`);
3. a `READ ONLY` transaction with a statement timeout, enforced by **PostgreSQL**
   - the only one of the three that does not depend on Sentinel being right
   about SQL (`test_sql_select_runs_read_only_with_a_timeout`).

Parameters are bound by the driver, never interpolated
(`test_sql_parameters_are_bound_not_interpolated`).

The DSN may not name **Sentinel's own store**. No adapter can enforce that for
itself - `platforms/postgres.py` has never heard of `Settings.engine` - so the
composition root does, and the comparison ignores credentials, driver suffix and
query string because each of those reaches the same rows while looking like a
different setting
(`test_the_store_check_survives_a_driver_suffix_and_a_different_user`).

### Fail closed by absence, again

A platform with **no** settings has no adapter built. A platform with **some** of
its required settings is a start-up `ConfigurationError`, not a silent absence:
an operator who half-configures AWS has said what they wanted, and quietly
building nothing would leave them believing the adapter is live until the first
refusal, which is during an incident
(`test_a_half_configured_platform_is_a_start_up_error`).

There is deliberately no enable flag. There are credentials, or there is no
adapter.

## SIEM delivery (real, via the outbox)

Set `SENTINEL_SIEM_WEBHOOK_URL` (and optionally `SENTINEL_SIEM_WEBHOOK_TOKEN`)
and each incident commits an **export intent in the same transaction as the
incident itself**. There is no window in which the incident exists and the
intent to export it does not — which is what makes "a security event is never
silently discarded" a property rather than an aspiration.

Delivery is then the transactional outbox's job, with the retry, backoff, lease
recovery and dead-lettering it already has. `SiemWebhookDeliverer` owns exactly
the wire: render as ECS (the JSON shape Splunk HEC, Elastic and Datadog ingest
without a custom parser), attach the bearer token and the idempotency key, and
**refuse to treat a non-2xx as success**
(`test_a_rejected_delivery_fails_rather_than_reporting_success`). One attempt,
no retry inside it: a second retry loop nested in the first would multiply a
budget nobody configured.

A 4xx fails like a 5xx, deliberately. A bad URL or an expired token is
permanent from the webhook's point of view, but marking it
delivered-with-a-shrug would discard the event; failing keeps the row on the
retry budget and, on exhaustion, in the dead-letter state where an operator can
see and replay it. An outbox row of kind `siem` claimed with **no** deliverer
configured is refused **by name** rather than passed over
(`test_an_unconfigured_deliverer_refuses_a_siem_row_by_name`).

The idempotency key rides `X-Sentinel-Idempotency-Key`, so the at-least-once
redelivery the outbox lease permits is identifiable by a deduplicating
collector as the same event rather than a second one.

Empty URL means **no export intent is enqueued at all** — not that exports are
enqueued and dropped. The flag that enqueues and the deliverer that sends are
derived from the same condition, so the two cannot disagree.

## SIEM export (file/stdout)

Still available, and the right choice where a collector agent already runs:

```bash
python -m sentinel.interface.cli siem-export acme cef | logger -t sentinel
python -m sentinel.interface.cli siem-export acme ecs > audit.ndjson
```

**The security property here is escaping, not delivery.** Several exported fields
are attacker-influenced: a tool description, a prompt, a resource path an agent
chose. CEF separates fields with `|`, keys with `=`, and *events* with newlines.
A resource id containing

```
evil\nCEF:0|Sentinel|SentinelSOC|1.0|login|Successful login|0|
```

is not a strange log line — it is a second event, forged, in the analyst's
console with Sentinel's name on it. That is worth more to an attacker than
evading detection, because it misleads the investigation that follows.

Verified end to end: two audit rows, one carrying that payload, produce exactly
two lines; the forged header never begins a line; and a detail value of
`outcome=success` is emitted as `outcome\=success`, so it cannot declare a key
and the real `outcome=denied` stands.

Details that matter:

- **Backslash is escaped before the delimiters** — the ordering bug in every
  escaping routine ever written (`test_backslash_is_escaped_before_the_delimiters`).
- U+2028, U+2029, NUL, VT and FF are stripped alongside `\r\n`: a surprising
  number of parsers treat them as event boundaries.
- Pipes are **not** escaped in the extension. Per the CEF spec they delimit only
  the header, and escaping them there would corrupt legitimate values.
- Detail *keys* are normalised to alphanumerics rather than escaped — a key is an
  identifier, not free text.
- A denial is **not** low severity. A refusal is the record of something being
  attempted; filed at severity 2 it sits below most SOC thresholds and nobody
  looks (`test_a_denial_is_not_exported_as_low_severity`).

## SIEM transports: OTLP and syslog

The webhook posts ECS JSON to one HTTPS collector, which Splunk HEC, Elastic and
Datadog accept. Two large classes of deployment cannot use it, so
`sentinel/infrastructure/siem_transports.py` adds two more wires - neither of
which adds a dependency.

| Transport | Wire | For |
|---|---|---|
| `otlp` | OTLP/HTTP logs, JSON encoding | an OpenTelemetry collector, the standard aggregation point |
| `syslog` | RFC 5424 over TLS, RFC 5425 octet framing | QRadar and most on-premises SIEMs |

**Octet-counted framing, not newline framing.** The message body is JSON and
contains no newlines only by convention; a receiver using newline framing would
split one record wherever a detail value happened to contain one. The count is
in **bytes** - the MSG is UTF-8 and carries a BOM, so `len(str)` is the wrong
number and would misalign every subsequent record on the connection
(`test_syslog_octet_count_is_bytes_not_characters`).

**Structured data is escaped.** RFC 5424 structured data ends at the first
unescaped `]`, so a value carrying one would split a record in two and the second
half would parse as a different event - the syslog form of the CEF injection
above (`test_syslog_structured_data_escapes_a_closing_bracket`).

**TLS is not optional and the certificate is verified.** A syslog stream is the
audit trail in transit: in the clear it is readable by anyone on the path, and
unverified it is writable by them (`test_syslog_verifies_tls_by_default`).

**No invented timestamps.** A missing `occurred_at` becomes RFC 5424 NILVALUE,
not "now". Substituting the current time would fabricate the one field an
investigator most needs to trust
(`test_syslog_does_not_invent_a_timestamp_it_was_not_given`).

### Fan-out: duplicate over loss

Configuring a transport alongside the webhook fans out to both. If any sink
fails, the deliverer **raises**, so the record stays on the outbox retry budget -
which means sinks that already succeeded see the event again. That is a
deliberate choice, and it is why every transport carries the idempotency key: a
redelivery is identifiable as the same event rather than as a second one. The
receipt names each sink, so an operator reading a dead-lettered record can see
which collector is the problem.

One failing sink does not stop the others on the same attempt
(`test_one_failing_sink_does_not_stop_the_others_on_this_attempt`) - otherwise a
single broken collector means nothing ships anywhere until someone notices.

### Kafka is NOT_SUPPORTED, by name

A Kafka producer is a broker-protocol client with its own pooling, partitioner
and retry semantics; there is no honest way to add one without a dependency, and
a "Kafka transport" that quietly posted to a REST proxy would not be Kafka.
Setting `SENTINEL_SIEM_KAFKA_*` is a **start-up error naming the reason**, not a
silent no-op (`test_kafka_is_refused_by_name_at_start_up`) - an operator must
learn at boot, not discover during an audit that a year of events went somewhere
else.

### No network delivery from the CLI exporter, deliberately

A built-in pusher needs credentials, retry policy and a delivery guarantee, and
getting those wrong means silently dropping security events — the failure this
product exists to prevent. Every SIEM already ingests a line stream, so piping to
a collector that solves delivery properly is the smaller claim and the safer one.

The event count goes to **stderr**, never stdout, because a summary line mixed
into the stream is a malformed event.

## Production preflight

```bash
SENTINEL_ENV=production python -m sentinel.interface.cli preflight
```

`Settings.from_environment` raises on the **first** problem, so bringing up
production is a sequence of one-at-a-time discoveries, each a failed rollout.
This reports all of them at once (measured: six problems in one pass, exit 78).

It is **not** the enforcement path — `from_environment` is unchanged and still
does the refusing. A preflight that said OK on a configuration startup rejects
would be worse than none, so two tests hold them together: an equivalence corpus
asserting `report.ok` matches whether startup raises *in both directions*, and a
structural ratchet counting `production`-gated branches in `settings.py` against
declared requirements. The ratchet is verified by mutation — injecting a new
production check into `settings.py` makes it fail.

A non-production environment reports `checked_production=False` and says so in
words, because an empty finding list would otherwise read as a clean bill of
health for a production rollout.
