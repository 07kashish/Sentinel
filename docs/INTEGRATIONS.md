# Integrations

<a id="connector_matrix"></a>
<a id="connector_matrix--connector-matrix"></a>
## Connector matrix

The specification names roughly thirty discovery connectors. **Three are
implemented; five more are implemented but have never
authenticated against a real tenant.** This document lists all of them with
their real status, because "which connectors does Sentinel have" should be
answered by a page that names the gaps rather than by a slide that lists logos.

Five statuses, used strictly:

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Code exists, is wired, and has tests that exercise it against a canned API |
| **UNVALIDATED** | All of the above, and it has never spoken to a real tenant — request shapes and scopes come from the vendor's published contract |
| **BUILDABLE** | Needs no new dependency or credential type — the client and signer already exist here |
| **NEEDS SDK** | Requires an SDK, a credential type or an API surface this repository has no access to |
| **NOT PLANNED** | Out of scope for the architecture as it stands, with the reason |

**UNVALIDATED is a separate status on purpose.** A published API contract is
not a successful call, and collapsing the two would let "we wrote the
connector" be read as "the connector works". Each one reports this itself
through `external_validation`, and `describe_discovery` names the unvalidated
ones inside the discovery report rather than in this document — a caveat is
worthless in a file nobody opens while reading a count.

No connector is listed as implemented because it could be. A connector that
returned an empty inventory because nobody could exercise it is **worse than an
absent one**: it reports "nothing found" where the honest answer is "not
implemented", and those need opposite responses.

---

<a id="connector_matrix--implemented"></a>
### Implemented

| Connector | Assets discovered | Coverage reporting | Tests |
|---|---|---|---|
| **Kubernetes** | `AGENT_RUNTIME` (pods), `SERVICE_ACCOUNT` | namespaces scanned, unreachable namespaces with reason, truncated listings, permissions used | `test_connectors.py` |
| **AWS IAM** | `SERVICE_ACCOUNT` (users), `CLOUD_ROLE` (roles) | path prefix scanned, truncation, permissions used | `test_connectors.py` |
| **GitHub Actions** | `SKILL` (agentic workflows), `REPOSITORY` | repositories scanned, unreadable repositories with status, truncated listings, per-workflow `content_examined`, permissions used | `test_github_discovery.py` (25) |

<a id="connector_matrix--what-the-three-connectors-deliberately-do-not-do"></a>
#### What the three connectors deliberately do not do

**GitHub requires explicit repositories.** Same reason as Kubernetes'
namespaces: listing every repository an organisation owns needs an org-wide
read a deployment may not have been granted, and falling back to whatever the
token happens to see produces a confident report about a subset with no
indication that it is one.

**Its agentic-workflow detection is a heuristic and says so.** `AI_MARKERS` is
exported so a reader can see exactly what was searched for. It will miss a
workflow that shells out to a vendored binary, and it will flag one that
mentions a model in a comment. `coverage.examined` is the denominator, because
"three agentic workflows" means something different out of four than out of
four hundred.

**A workflow whose content could not be read is recorded, not dropped.** It is
still reported, with `content_examined: false`, so a reader comparing two rows
can tell that one was judged on its content and the other on its filename.
Dropping it would report a clean repository. An undecodable file is likewise a
named hole rather than an empty string -- an empty string matches no markers,
so treating a decode failure as empty content would quietly turn an agentic
workflow into a clean one.

**Nothing it finds is ever `attested`.** Nothing binds a digest to what
actually ran in a workflow, so `observed` is the strongest honest provenance
and the AI-BOM's census reflects that.

**Kubernetes requires explicit namespaces.** Listing every namespace needs a
cluster-wide read a deployment may not have been granted, and falling back to
`default` produces a confident report about one namespace out of forty.

**Pods become `AGENT_RUNTIME`, not `AGENT`.** A pod is *where* an agent runs.
Calling it the agent conflates workload with identity, and two pods running one
agent would read as two agents.

**IAM identities are never `AGENT`.** IAM does not know what an agent is.
Labelling a user an agent because it sits under `/agents/` infers identity from a
naming convention, and a convention is not an authority.

---

<a id="connector_matrix--implemented-never-validated-against-a-real-tenant"></a>
### Implemented, never validated against a real tenant

These five talk to the control planes where agents are *declared*, so what they
return is an agent because the platform says so rather than because a name
matched a pattern.

| Connector | Assets discovered | Kind, and why | Tests |
|---|---|---|---|
| **AWS Bedrock Agents / AgentCore** | `AGENT` | Bedrock agents are agents in the platform's own vocabulary | `test_ai_connectors.py` |
| **Microsoft Entra** | `SERVICE_ACCOUNT` | Graph has no concept of an agent; an app registration named `prod-agent-sync` is an app registration | `test_ai_connectors.py` |
| **Google Vertex AI** | `AGENT` (reasoning engines) | a deployed reasoning engine is a deployed agent | `test_ai_connectors.py` |
| **OpenAI** | `AGENT` (assistants) | an assistant is an agent | `test_ai_connectors.py` |
| **Generic MCP** | `MCP_SERVER`, `MCP_TOOL` | enumerated by the server's own `tools/list` | `test_ai_connectors.py` |

Two deliberate omissions in what they store. **MCP tool descriptions and
OpenAI function descriptions are not recorded.** Both are text written by
whoever runs that server or created that assistant, which is why
`test_mcp_attacks.py` exists — and an inventory is read by analysts and
summarised by models. The tool *name* is what discovery needs.

Every connector above is built on `HardenedHttpClient` and the SigV4 signer
that already exist, so they inherit post-resolution address validation,
connection pinning against DNS rebinding, redirect refusal and bounded
responses. The signer gained a `path` parameter for Bedrock's `POST /agents/`,
restricted by `_signable_path` to a literal of unreserved characters so the
signed path and the transmitted one cannot drift — a mismatch there surfaces as
an opaque 403 that reads like a permissions problem.

<a id="connector_matrix--running-them"></a>
### Running them

```
python scripts/run_discovery.py --explain   # what each connector needs
python scripts/run_discovery.py             # run everything configured
```

Exit codes matter here: **1** means nothing was configured, which is an
unperformed scan rather than a clean estate, and **2** means a connector failed
or its coverage was partial. Only **0** means every configured connector
completed fully. A truncated listing that exited 0 in CI would be a subset
recorded as a total.

---

<a id="connector_matrix--the-property-that-matters-more-than-the-count"></a>
### The property that matters more than the count

`AssetInventory` **cannot be constructed without `DiscoveryCoverage`** — it is a
required constructor argument and the type is checked. A connector cannot return
assets without also saying what it looked at, what it could not reach, which
permissions it used, and whether pagination completed.

That is enforced structurally rather than by this document, because
documentation saying "connectors should report coverage" produces connectors
that do not (`test_an_inventory_cannot_be_built_without_coverage`).

The consequence for a reader: **a count is never a census.** `merge()` surfaces
`partial_sources` above any total, and every inventory carries its own limits
string saying that absence is not evidence of absence.

---

<a id="connector_matrix--adding-a-connector"></a>
### Adding a connector

1. Implement the `Connector` protocol: a `name` and `discover() -> AssetInventory`.
2. Map native types onto `AssetKind`, keeping the native type in `native_type` —
   the normalised kind answers cross-connector questions, the native type is how
   somebody finds the thing again in the console it came from.
3. Report coverage honestly. Every unreachable target needs a **reason**;
   "coverage was partial" is a shrug wearing a data structure.
4. Register it in `build_connectors` behind its credential, so an unconfigured
   connector is **absent** rather than present-and-returning-empty.
5. Add it to this table with its real status.


<a id="mcp_gateway"></a>
<a id="mcp_gateway--mcp-security-gateway"></a>
## MCP security gateway

**Status:** Two paths, both implemented and executed end to end.

1. **Evaluation** (`POST /v1/mcp/evaluate`) decides about calls that are
   *described* to it. Sentinel makes no network call on this path.
2. **The wire proxy** (`POST /v1/mcp/proxy/{server_id}`, off by default) speaks
   JSON-RPC over the MCP Streamable HTTP transport and sits BETWEEN an MCP
   client and an enrolled server, so the call passes through the gate on its
   way rather than being reported after the fact.

What the proxy is **not**: transparent interception. A client must be pointed
at the proxy URL; nothing rewrites traffic that does not arrive here. Protocol
support is one versioned revision and an allowlist of methods — everything else
is refused as `NOT_SUPPORTED` rather than forwarded unevaluated. Both limits are
stated in the module docstrings and repeated below, so no reader infers more
reach than exists.

<a id="mcp_gateway--the-three-questions-a-generic-tool-gate-cannot-answer"></a>
### The three questions a generic tool gate cannot answer

`ProtectGate` already decides `ALLOW` / `WARN` / `REQUIRE_APPROVAL` / `BLOCK`
from a tool call's content, and the MCP gateway **reuses** it rather than
forking a second decision path. One rule set governs both, so there is no second
place for them to disagree. What MCP adds is context a bare tool call has no
room for:

| # | Question | Failure if unasked |
|---|---|---|
| 1 | Is this server one we enrolled? | An agent is pointed at a server nobody reviewed, and every call to it looks like an ordinary tool call |
| 2 | Is this tool what it was when it was approved? | A server ships a benign `search_docs` on Monday and a data-exfiltrating `search_docs` on Friday. The **name is identical**, so an allowlist sees nothing |
| 3 | Is the tool's *description* itself the attack? | A description is prose the model reads as instructions, supplied by the server. Inspecting the **arguments** never finds it |

Checks run in that order, and the order is load-bearing: an `UNKNOWN` or
`BLOCKED` server is refused **before any of its text is read**, so a hostile
server cannot reach the parser or spend the detector's time. Asserted by
`test_an_unknown_server_is_refused_before_its_content_is_read`, which requires
`evaluation.protect` to be `None` rather than merely requiring a refusal.

<a id="mcp_gateway--trust-is-a-stored-fact-never-a-request-field"></a>
### Trust is a stored fact, never a request field

`McpCallPayload` has **no** field for MCP server trust. `UNKNOWN` is the only
thing standing between an attacker-introduced server and the rest of the
pipeline, so a caller able to declare its own server `enrolled` would step over
the whole gateway in one request.

`trustLevel` *is* accepted and is a different axis — it is the calling **agent's**
`TrustLevel`, exactly as on `ProtectPayload`, and says how sure we are of who is
calling rather than whether the server they reached is one we know.

Enforced from both sides:

- `test_a_caller_cannot_declare_its_own_server_enrolled` posts `trust`,
  `serverTrust` and `server_trust` in the request body and requires the server
  to stay `unknown`.
- `test_a_caller_cannot_promote_its_own_server_by_claiming_trust` asserts the
  **signature** of `McpGateway.evaluate_request` — no parameter is annotated
  `McpServerTrust`. It resolves annotations with `typing.get_type_hints`; the
  first version compared `inspect.signature(...).annotation` against the class
  under `from __future__ import annotations`, where every annotation is a
  *string*, so the sweep scanned an empty set and passed while checking nothing.

<a id="mcp_gateway--enrolment-is-cli-only"></a>
### Enrolment is CLI-only

Enrolling a server decides which servers an agent may reach and what their tools
are allowed to be. That is a trust-anchor change, and
`sentinel/domain/authorization.py` records the standing decision that
trust-anchor changes are guarded by shell access to the host rather than by a
bearer token — a credential that could enrol its own MCP server could enrol a
hostile one.

```bash
python -m sentinel.interface.cli mcp-enrol acme docs-mcp tools.json https://mcp.example/docs
```

`tools.json` accepts either a bare list or the `{"tools": [...]}` shape an MCP
client prints, because hand-reshaping the artifact being security-reviewed is
where mistakes come from. It is a **file and not a live fetch** on purpose:
enrolment is the moment an operator says "these are the tools I reviewed", and
fetching at enrolment time would mean approving whatever the server happened to
serve, unread.

`mcp-block` refuses every call to a server, and `mcp-enrol` will **not** launder a
blocked server back to enrolled — `test_a_blocked_server_cannot_be_enrolled_back_without_unblocking`.

Because this is the only path out of `UNKNOWN`, a broken `mcp-enrol` would not
fail loudly; it would refuse every MCP call forever while looking like a strict
security posture. `test_enrolment_turns_a_refused_call_into_an_allowed_one`
executes the loop and asserts the **before** state as well as the after, so it
cannot pass on a build that allows everything.

<a id="mcp_gateway--storage"></a>
### Storage

`mcp_servers` and `mcp_tool_pins` are both in `PROTECTED_TABLES`, so the RLS
migration and the catalogue check in `test_tenant_isolation_rls.py` cover them
without being told about them — that test iterates `PROTECTED_TABLES` and asks
PostgreSQL's own catalogue whether `relrowsecurity` **and**
`relforcerowsecurity` are set with a policy attached.

Every query is scoped twice: `conn.set_tenant(...)` **and** an explicit
`tenant_id =` predicate. The predicate is not redundant — **SQLite has no
row-level security**, so on SQLite it is the only tenant boundary there is.
Verified by mutation: removing `AND server_id=` / the tenant predicate from
`SqlMcpRegistry.lookup` makes
`test_one_tenants_enrolment_does_not_admit_another_tenants_call` fail, and
restoring it makes the module pass again.

Pinning **replaces** a server's tool set in one transaction rather than merging.
Merging would leave a tool pinned that the operator has since removed; splitting
the delete and insert across transactions would open a window with no pins at
all, which under `require_pin` turns a re-approval into an outage.

<a id="mcp_gateway--sentinel_mcp_require_pin"></a>
### `SENTINEL_MCP_REQUIRE_PIN`

Defaults to `true`. Setting it `false` is the OBSERVE-mode escape for a rollout
where an operator is still discovering which servers exist. It relaxes **check 2
only** — server trust and description scanning are unaffected, and an unknown
server is still refused either way
(`test_an_unpinned_server_is_refused_by_default_and_allowed_in_observe_mode`
asserts the policy still ran in the permissive case).

<a id="mcp_gateway--a-defect-this-found-in-itself"></a>
### A defect this found in itself

Running the CLI drill end to end showed `evaluate` diffing the **one** tool being
called against the **whole** pinned set, so every tool that simply was not the
subject of the call was reported as `TOOL_REMOVED`. With twenty pinned tools,
every call would have written nineteen false "a pinned tool is no longer
offered" entries into its audit record.

A single call is not an observation of the server's tool listing. Per-call drift
is now scoped to the called tool; `diff_tools`, which is given a real listing,
still reports removals. Both halves are pinned by
`test_one_call_does_not_report_every_other_pinned_tool_as_removed` and
`test_a_full_listing_still_reports_a_removed_tool`.

This is the same correction the detector needed after F-10, where 51.7% of
ordinary tool actions were being flagged: narrow the input to what the check can
actually speak to.

<a id="mcp_gateway--the-wire-proxy"></a>
### The wire proxy

`POST /v1/mcp/proxy/{server_id}` (capability `execute_tool`) is an MCP
Streamable HTTP endpoint an MCP client points at **instead of** the real
server. It exists only when `SENTINEL_MCP_PROXY_ENABLED` is set — when off,
the route is not registered and a scanner sees the same 404 as no feature.
Implementation: `sentinel/infrastructure/mcp_wire.py` (JSON-RPC over
`HardenedHttpClient`, so redirect refusal, post-resolution address validation
and bounded responses are inherited, not re-implemented) fronted by
`sentinel/interface/mcp_proxy_routes.py`.

Properties the evaluation API cannot provide, each pinned by
`tests_arch/test_mcp_wire_proxy.py`:

- **Default-deny egress.** The endpoint comes from the enrolment record; the
  request has no field to name one. A server that is not `ENROLLED` is refused
  before any network activity — the tests assert the upstream call log is
  EMPTY, not merely that the caller was told no
  (`test_an_unknown_server_is_refused_and_nothing_is_dialled`). `OBSERVED` is
  refused here even though `evaluate` accepts it: this route is the thing
  *making* the call, and dialling a server an operator merely saw would turn
  observation into authorisation.
- **The rug pull is caught against the LIVE definition.** `tools/call` first
  fetches the server's current `tools/list` and evaluates the called tool's
  live definition against the pin, so a definition changed after enrolment
  refuses the call without forwarding it
  (`test_a_rug_pulled_tool_is_refused_before_the_call_is_forwarded`). Cost:
  one extra upstream round trip per call, stated here rather than hidden.
- **A drifted listing is refused, not filtered.** Descriptions in `tools/list`
  are prose the model reads as instructions. A listing with an added or
  changed tool is refused whole; filtering it would hand the client upstream
  state Sentinel partly authored. Removal-only drift passes with an audit
  record — a server that dropped a tool narrowed, not widened.
- **Delegated identity rides every record.** `X-Sentinel-Agent-Id` (required),
  `X-Sentinel-Principal` and `X-Sentinel-Session-Id` carry human → agent →
  session attribution into the audit trail; refusals carry it too, which is
  when it matters (`test_the_delegation_chain_is_recorded_on_the_refusal`).
  `X-Sentinel-Upstream-Authorization` forwards the client's own OAuth
  credential for the upstream verbatim; it is never logged, stored or minted.

Protocol support is versioned and allowlisted: revision `2025-06-18`
(`MCP_PROTOCOL_VERSION`), methods `initialize`, `ping`, `tools/list`,
`tools/call` and the client lifecycle notifications. Everything else answers
JSON-RPC `-32601` with an explicit `NOT_SUPPORTED` marker and is **not**
forwarded — a pass-through nobody evaluated would be an unevaluated side
channel. Policy refusals travel in-band as JSON-RPC error `-32050` with the
full evaluation under `error.data.sentinel`, because the caller is an MCP
client mid-session and an in-band error is the shape it can handle.

<a id="mcp_gateway--oauth-through-the-proxy"></a>
#### OAuth through the proxy

An upstream `401`/`403` is **relayed** with its `WWW-Authenticate` header
(`test_an_upstream_401_is_relayed_with_its_challenge`) — that header carries
the RFC 9728 protected-resource-metadata pointer the client's
authorization-server discovery starts from, so relaying it is what makes the
MCP authorization flow work *through* the proxy. Sentinel never mints, stores
or logs upstream credentials; it carries the client's own.

It is **not relayed unread**. That pointer is supplied by the resource whose
trustworthiness is the open question: a compromised server answering
`resource_metadata="https://attacker.example/…"` aims the client's entire OAuth
flow at an authorization server the attacker runs. Sentinel is the one party in
the exchange that knows which endpoint an operator actually enrolled, so it is
the only party positioned to notice. A pointer that is not same-origin with the
enrolled endpoint is **stripped**, and the refusal is recorded as
`oauth_issuer_confusion`
(`test_a_challenge_naming_a_foreign_issuer_is_not_relayed`). The client still
learns it is unauthorized — from a challenge naming nobody, which fails closed
rather than sending it somewhere hostile. Same-origin challenges pass through
untouched (`test_a_same_origin_challenge_is_relayed`).

Credential audience restriction (`SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE`,
default on): a forwarded JWT whose `aud` claim names no origin matching the
enrolled endpoint is refused before any network activity
(`test_a_token_bound_to_another_resource_is_not_replayed`) — a token minted
for server A must not be replayed against server B through the proxy. This is
**structural inspection, not verification**: Sentinel holds none of the
upstream's keys, so it checks what a token plainly claims about its audience
and nothing more. Opaque tokens are not inspectable and always pass
(`test_an_opaque_token_is_not_inspectable_and_passes`); that limit is stated
here rather than papered over.

<a id="mcp_gateway--server-discovery"></a>
#### Server discovery

```bash
python -m sentinel.interface.cli mcp-discover acme docs-mcp https://mcp.example/rpc tools.json
```

Contacts a candidate server, runs `initialize` + `tools/list`, records what it
served, writes the file `mcp-enrol` takes — and **enrols nothing**
(`test_discovery_records_the_server_as_observed_never_enrolled`). The server is
left `OBSERVED`, which the proxy refuses to dial, so discovering a server
grants it nothing. The review step survives; only the hand-authoring of JSON
goes away, because enrolment is still the moment an operator says "these are
the tools I reviewed" and fetching at enrolment time would mean approving
whatever the server happened to serve, unread.

This command takes an endpoint from argv, which the proxy deliberately refuses
to do from a request. The difference is the trust anchor: an argv is an
operator at a shell on the host, which is already how enrolment is guarded. The
same egress policy applies, so discovery cannot reach anywhere the proxy could
not. A server that answers `401` is reported, not worked around — discovery
holds no upstream credential and will not invent one
(`test_an_authorization_challenge_is_reported_not_worked_around`).

<a id="mcp_gateway--server-identity"></a>
#### Server identity

`mcp_servers.server_info` records what a server says it *is* at `initialize`
(`serverInfo` name/version). The tool pins catch a changed TOOL and catch
nothing about a changed SERVER: an endpoint can be rehosted, a DNS record
moved, or an approved address taken over, and in each case the tools may be
byte-identical while the party serving them is not.

A changed **name** is refused as impersonation
(`test_a_different_server_answering_an_enrolled_endpoint_is_refused`); a changed
**version** is recorded and allowed (`test_a_version_bump_is_recorded_and_allowed`),
because refusing every upgrade would make routine maintenance an outage and
train operators to ignore the signal. First contact is learned and recorded
rather than refused — enrolment approves an endpoint and its tools, and that
identity is trust-on-first-use, stated here rather than dressed up as
verification.

<a id="mcp_gateway--duplicate-tool-names"></a>
#### Duplicate tool names

A listing serving one name twice is refused rather than resolved, on both the
call and the listing path (`test_tool_name_collision_is_refused_rather_than_resolved`).
Whichever copy Sentinel evaluates, the **server** decides which copy actually
runs, so picking one silently means a benign definition can be inspected while
a hostile one executes under the same name. This was a real defect found by
writing the attack test: `_evaluate_tools_call` took the FIRST match while
`diff_tools` built a dict in which the LAST won, so an attacker choosing the
order chose which copy got inspected.

<a id="mcp_gateway--tool-provenance"></a>
#### Tool provenance

Every LIVE listing the proxy obtains is recorded before any decision is made
about it. `mcp_tool_provenance` holds one row per (tool, definition version)
with separate description/schema hashes, `first_seen`, `last_seen` and
`times_seen` — a changed definition opens a **new** row and leaves the old one
intact, so after a rug pull the investigation reads "when did the old
definition stop appearing" and "when did the new one start" straight off two
rows (`test_a_changed_definition_opens_a_new_provenance_row_keeping_the_old`).
`mcp_tool_changes` is the append-only drift log; every drift the gateway
observes lands there whether or not the caller kept the error
(`test_a_refused_rug_pull_lands_in_the_change_log`). Both tables carry FORCE
row-level security via `PROTECTED_TABLES`. The tool description itself is
still never stored — hashes only, per this module's standing rule about
retaining attacker-controlled text. Operator view:

```bash
python -m sentinel.interface.cli mcp-provenance acme docs-mcp
```

<a id="mcp_gateway--egress-classification"></a>
#### Egress classification

Every proxied call's audit record carries a `destination_class` — `internal`,
`allowlisted` or `external` (`sentinel/domain/mcp.py::classify_destination`),
judged without resolution: hostnames are classified by literal form and
allowlist membership only, because a pure function that pretended to know a
hostname's address would be a classification the attacker picks. The
resolution-aware refusal of private addresses stays where it is, in
`infrastructure/outbound.py` at connection time.

<a id="mcp_gateway--the-definition-cache"></a>
#### The definition cache

`SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS` (default `0`) lets a deployment
reuse a server's `tools/list` for `tools/call` evaluation for up to that many
seconds, removing the extra round trip per call. `0` means every call is
evaluated against the LIVE listing. Non-zero is an explicit trade: the
rug-pull detection window widens to at most the TTL
(`test_with_a_cache_ttl_the_second_call_skips_the_listing`). Per-process, and
keyed by (tenant, server) so one tenant's cache cannot answer another's.

<a id="mcp_gateway--adversarial-coverage"></a>
### Adversarial coverage

`tests_arch/test_mcp_attacks.py` carries one test per attack named in
specification section 71, kept in a dedicated module so the coverage is
auditable — eleven named attacks, eleven checkable names, rather than trusting
they are covered somewhere across four files. Each asserts the **side effect**
was prevented (the upstream was never dialled, the hostile definition never
reached policy), not merely that an error came back: a gateway that returns an
error and performs the action anyway passes the weak version of every one.

Writing them found the duplicate-tool-name defect described above.

<a id="mcp_gateway--measured-overhead"></a>
### Measured overhead

`scripts/run_mcp_proxy_bench.py` measures Sentinel's own per-call cost against
a stub upstream that returns instantly; results in `archive/pre-cleanup:docs/mcp_proxy_bench.json`.
It is **not** end-to-end MCP latency — a real server's response time is added
on top and dominates in any deployment — and quoting it as such would be the
fake-benchmark failure section 127 bans. It is the gateway's tax, which is the
part Sentinel controls and the only part it should claim.

Measured on SQLite with the cache off (every call fetches a live listing),
300 requests per point: p95 2.03 ms at concurrency 1, rising to 18.73 ms at
concurrency 16; p99 2.16 ms rising to 89.35 ms. Both inside the section 79
targets (p95 < 50 ms, p99 < 100 ms), with no server errors. The refusal path
for an unenrolled server costs p50 0.85 ms single-threaded — a gate that cost
more than the thing it guards would be a denial-of-service primitive. The tail
at higher concurrency is SQLite write contention on the audit and provenance
rows, not policy evaluation; PostgreSQL numbers are not claimed here because
they have not been measured.

<a id="mcp_gateway--what-is-not-built"></a>
### What is not built

- **No transparent interception.** The client must be pointed at the proxy
  URL; nothing rewrites traffic that does not arrive here.
- **No `resources/*`, `prompts/*`, sampling or roots.** Refused as
  `NOT_SUPPORTED`, not silently forwarded. Each future method addition must
  arrive with its evaluation, never as bare pass-through.
- **No relay of intermediate SSE traffic.** An upstream answering a POST with
  an SSE stream is parsed for the response that closes the interaction;
  server-initiated requests on that stream are not relayed.
- **No automatic server discovery.** `mcp-discover` contacts a candidate an
  operator names and records it as OBSERVED; nothing scans a network or a
  registry for servers, and nothing is ever enrolled without a second
  deliberate command.
- **No automatic re-pinning.** Drift refuses; a human re-approves.
- **No UI.** `mcp-list` is the only view of enrolled servers.


<a id="tool_gateway"></a>
<a id="tool_gateway--tool-gateway-openapi-ingestion-real-adapters-action-semantics-siem"></a>
## Tool gateway: OpenAPI ingestion, real adapters, action semantics, SIEM

<a id="tool_gateway--action-semantics-what-a-platform-operation-means"></a>
### Action semantics: what a platform operation MEANS

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


Companion to [MCP_GATEWAY.md](INTEGRATIONS.md#mcp_gateway), which documents the trust engine
these share.

<a id="tool_gateway--openapi-ingestion-not-a-second-gateway"></a>
### OpenAPI: ingestion, not a second gateway

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

<a id="tool_gateway--bounds-and-one-honest-limit"></a>
#### Bounds, and one honest limit

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

<a id="tool_gateway--real-tool-adapters"></a>
### Real tool adapters

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

<a id="tool_gateway--fail-closed-by-absence"></a>
#### Fail closed by absence

| Variable | Unset (default) |
|---|---|
| `SENTINEL_TOOL_FILE_ROOT` | `read_file` / `write_file` are **not registered** |
| `SENTINEL_TOOL_HTTP_ALLOWED_HOSTS` | `http_request` is **not registered** |

An unconfigured adapter is *absent*, not present-and-disabled — the proxy already
refuses unregistered tools, so the safe state is enforced by code that exists
rather than by a flag one boolean away from being on.

The two symlink tests skip on Windows, where creating symlinks needs privileges;
they run on `ubuntu-latest` in CI. The skip is reported, never silent.

<a id="tool_gateway--tier-1-platform-adapters-aws-github-kubernetes-postgresql"></a>
### Tier-1 platform adapters: AWS, GitHub, Kubernetes, PostgreSQL

`action_semantics` above knows what `iam:AttachUserPolicy` means. Until these
adapters existed it was classifying events that had **already happened somewhere
else** - Sentinel could name the consequence and could not stand in front of it,
because the only effects the enforcement path governed were reading a file,
writing a file and fetching a URL.

`sentinel/infrastructure/platforms/` registers four more into the **same**
`InlineToolProxy` effects mapping, so they reach an agent only through the kill
switch, the capability grant, `ProtectGate`, the budget and the circuit breaker.
There is no second execution path for the higher-privilege effects.

<a id="tool_gateway--the-confused-deputy-and-the-rule-that-defeats-it"></a>
#### The confused deputy, and the rule that defeats it

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

<a id="tool_gateway--the-tier-ceiling-is-containment-not-policy"></a>
#### The tier ceiling is containment, not policy

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

<a id="tool_gateway--what-is-deliberately-absent"></a>
#### What is deliberately absent

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

<a id="tool_gateway--no-new-dependencies"></a>
#### No new dependencies

No `boto3`, no `kubernetes`, no `PyGithub`. Each brings its own HTTP stack,
which would route the **highest-privilege egress in the product** around
`HardenedHttpClient`: no post-resolution address validation, no connection
pinning, redirects followed by default. SigV4 is an HMAC ladder over stdlib,
pinned to the published `aws4_testsuite` vector rather than to its own output
(`test_sigv4_matches_the_published_aws_test_vector`). PostgreSQL uses `psycopg`,
already a dependency because Sentinel's own store is PostgreSQL.

<a id="tool_gateway--three-containments-on-sql-because-text-matching-loses"></a>
#### Three containments on SQL, because text matching loses

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

<a id="tool_gateway--fail-closed-by-absence-again"></a>
#### Fail closed by absence, again

A platform with **no** settings has no adapter built. A platform with **some** of
its required settings is a start-up `ConfigurationError`, not a silent absence:
an operator who half-configures AWS has said what they wanted, and quietly
building nothing would leave them believing the adapter is live until the first
refusal, which is during an incident
(`test_a_half_configured_platform_is_a_start_up_error`).

There is deliberately no enable flag. There are credentials, or there is no
adapter.

<a id="tool_gateway--siem-delivery-real-via-the-outbox"></a>
### SIEM delivery (real, via the outbox)

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

<a id="tool_gateway--siem-export-filestdout"></a>
### SIEM export (file/stdout)

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

<a id="tool_gateway--siem-transports-otlp-and-syslog"></a>
### SIEM transports: OTLP and syslog

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

<a id="tool_gateway--fan-out-duplicate-over-loss"></a>
#### Fan-out: duplicate over loss

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

<a id="tool_gateway--kafka-is-not_supported-by-name"></a>
#### Kafka is NOT_SUPPORTED, by name

A Kafka producer is a broker-protocol client with its own pooling, partitioner
and retry semantics; there is no honest way to add one without a dependency, and
a "Kafka transport" that quietly posted to a REST proxy would not be Kafka.
Setting `SENTINEL_SIEM_KAFKA_*` is a **start-up error naming the reason**, not a
silent no-op (`test_kafka_is_refused_by_name_at_start_up`) - an operator must
learn at boot, not discover during an audit that a year of events went somewhere
else.

<a id="tool_gateway--no-network-delivery-from-the-cli-exporter-deliberately"></a>
#### No network delivery from the CLI exporter, deliberately

A built-in pusher needs credentials, retry policy and a delivery guarantee, and
getting those wrong means silently dropping security events — the failure this
product exists to prevent. Every SIEM already ingests a line stream, so piping to
a collector that solves delivery properly is the smaller claim and the safer one.

The event count goes to **stderr**, never stdout, because a summary line mixed
into the stream is a malformed event.

<a id="tool_gateway--production-preflight"></a>
### Production preflight

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


<a id="agent_platforms"></a>
<a id="agent_platforms--connecting-sentinel-to-gpts-and-cloud-agent-platforms"></a>
## Connecting Sentinel to GPTs and cloud agent platforms

One document does it for all of them: `docs/integrations/sentinel-agent-tool.openapi.json` (OpenAPI 3.1), with an identical 3.0 copy beside it, `sentinel-agent-tool.openapi-3.0.json`, for platforms that need the older format. Custom GPTs, Amazon Bedrock Agents, Azure AI Foundry / Copilot Studio and Google Vertex AI Agent Builder all accept an OpenAPI document, an HTTPS address and an API key. The document is derived from the running application by `scripts/build_agent_tool_spec.py`, and `tests_arch/test_agent_tool_spec.py` fails if it drifts or if a caller following it cannot complete the journey on the real routes.

It gives the assistant two operations:

| Operation | When the assistant calls it | Result |
|---|---|---|
| `checkAction` | Before anything that changes, sends, deletes, deploys or pays | `allow`, `warn`, `require_approval` or `block`, with the reason |
| `executeApprovedAction` | To run a tool through Sentinel under the authorization `checkAction` returned | The tool runs once; a receipt binds what ran to what was approved |

<a id="agent_platforms--what-must-be-true-first"></a>
### What must be true first

1. **HTTPS.** Every platform below refuses plain HTTP. The document's server is `https://app.joinsentinelai.com`; that address works only after the two DNS records for it exist (OWNER_ACTIONS 11). Until then nothing here can be connected. For another address: `python scripts/build_agent_tool_spec.py --server https://your-host --out my.json`.
2. **An `ingest` key for the tenant**, one per assistant if you want to tell them apart. An ingest key can ask and execute; it cannot read incidents or approve.
3. **A policy** that says which resources need a human (console → Policy).

<a id="agent_platforms--the-instruction-to-give-the-assistant"></a>
### The instruction to give the assistant

Paste this into the assistant's system instructions. It is the part that makes the assistant actually ask.

```
You must call checkAction before any action that changes, sends, deletes, deploys or pays for something.
Describe the exact tool, the resource and the exact arguments you intend to use.
- If decision is "allow" or "warn": proceed with exactly those arguments.
- If decision is "require_approval": do not proceed. Tell the user a person must approve it in Sentinel, and wait.
  When the user says it is approved, call executeApprovedAction with the same tool, resource and arguments and the authorization token.
- If decision is "block": do not proceed. Tell the user why, using the reason.
- If checkAction fails, times out or returns anything else: do not proceed. Never assume it would have been allowed.
Always send the same agentId. Never change the arguments after asking.
```

<a id="agent_platforms--platform-by-platform"></a>
### Platform by platform

| Platform | Where the document goes | Authentication | Note |
|---|---|---|---|
| **Custom GPT** (ChatGPT) | GPT editor → Configure → Actions → Create new action → paste the JSON | Authentication → API Key → Auth Type **Bearer** → the ingest key | `x-openai-isConsequential` is set: ChatGPT asks the user to confirm `executeApprovedAction`, not `checkAction`. A GPT shared publicly also needs a privacy-policy URL |
| **OpenAI Assistants / Responses API** | Not an Action: use the Python adapter `sentinel/sdk/adapters/openai_agents.py`, or declare two function tools with the same names and call the two endpoints from your code | Your server holds the key | The model never sees the key |
| **Amazon Bedrock Agents** | Agent → Action groups → Add → define with **API schema** → upload the JSON | An action group calls a Lambda function: the Lambda forwards the request to Sentinel with the key from Secrets Manager | Bedrock's schema support is OpenAPI 3.0: upload `sentinel-agent-tool.openapi-3.0.json` instead (same content, generated alongside) |
| **Azure AI Foundry agents** | Agent → Tools → Add → **OpenAPI 3.0 specified tool** → paste the JSON | Connection of type API key, header `Authorization`, value `Bearer <key>` | Use the `-3.0.json` file |
| **Microsoft Copilot Studio** | Tools → Add a tool → REST API → upload the JSON | API key, header `Authorization` | Use the `-3.0.json` file |
| **Google Vertex AI Agent Builder** | Agent → Tools → Create → type **OpenAPI** → paste the document (YAML or JSON) | API key or bearer token in the tool's authentication settings | |
| **Gemini function calling (your own code)** | `sentinel/sdk/adapters/gemini.py` | Your server holds the key | `sentinel.sdk.adapters.gemini` |
| **Anything else that speaks HTTP** (n8n, Zapier, Make, a script) | Two POST requests, shown below | Header `Authorization: Bearer <key>` | |

```bash
curl -s https://app.joinsentinelai.com/v1/protect/evaluate -H "Authorization: Bearer $SENTINEL_INGEST_KEY" -H "Content-Type: application/json" -d '{"agentId":"agent:my-assistant","tool":"create_refund","action":"pay","resource":"/orders/1042","arguments":{"amount":40}}'
```

<a id="agent_platforms--what-this-does-and-does-not-give-you"></a>
### What this does and does not give you

* **It gives the assistant a gate to ask, and a way to run approved actions with proof.** Approvals bind to the exact arguments; a changed or repeated execution is refused.
* **It does not force the assistant to ask.** A GPT or cloud agent calls `checkAction` because its instructions say so. Its *other* tools still work if it skips the call. Real enforcement needs the consequential tools to be reachable only through Sentinel's `executeApprovedAction` (the tool registered in Sentinel, the credential held by Sentinel, not by the assistant).
* **`executeApprovedAction` runs tools registered on the Sentinel deployment**: the brokered Kubernetes, GitHub and AWS operations, a demonstration `echo` tool, and **`app_call`** — any HTTPS business application an administrator has registered as a *connected application* (`PUT /v1/apps/<id>` with the destination, the allowed methods and paths, and the credential, which is sealed and never returned). The assistant then calls `app_call` with `{"app": "crm", "method": "POST", "path": "/refunds", "body": {...}}` and resource `app://crm/refunds`; Sentinel presents the credential, so the assistant never holds it. That is the enforcing path: remove the refund action from the assistant, register the CRM in Sentinel, and the only way to refund is through an approval.
* **The agent cannot see whether its request was approved**, by design (an ingest key reads nothing). It learns by trying `executeApprovedAction`: 403 until a person approves.

<a id="agent_platforms--what-has-been-verified"></a>
### What has been verified

| Claim | Evidence |
|---|---|
| The document matches the application and offers no way to assert trust | `tests_arch/test_agent_tool_spec.py` |
| A caller sending only what the document offers completes ask → require approval → refused → approve → execute once → replay and changed arguments refused, on SQLite and PostgreSQL | same file |
| **Imported into ChatGPT, Bedrock, Azure or Vertex** | **Not done.** No account on any of them has been used, and none can connect until HTTPS exists. The per-platform steps above follow each vendor's published procedure; the 3.0 copy exists because of their documented limits, not because an upload failed |

This document and the JSON file are private integration material; nothing here is published to a registry.
