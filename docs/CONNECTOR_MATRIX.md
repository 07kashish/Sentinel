# Connector matrix

The specification names roughly thirty discovery connectors. **Three are
implemented and validated; five more are implemented but have never
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

## Implemented

| Connector | Assets discovered | Coverage reporting | Tests |
|---|---|---|---|
| **Kubernetes** | `AGENT_RUNTIME` (pods), `SERVICE_ACCOUNT` | namespaces scanned, unreachable namespaces with reason, truncated listings, permissions used | `test_connectors.py` |
| **AWS IAM** | `SERVICE_ACCOUNT` (users), `CLOUD_ROLE` (roles) | path prefix scanned, truncation, permissions used | `test_connectors.py` |
| **GitHub Actions** | `SKILL` (agentic workflows), `REPOSITORY` | repositories scanned, unreadable repositories with status, truncated listings, per-workflow `content_examined`, permissions used | `test_github_discovery.py` (25) |

### What the three validated connectors deliberately do not do

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

## Implemented, never validated against a real tenant

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

## Running them

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

## Buildable without new dependencies

These need no SDK — the hardened client and, where relevant, the SigV4 signer
already cover them. They are not implemented, and are not claimed.

| Connector | Why it is reachable | What it would add |
|---|---|---|
| AWS Secrets Manager / KMS | JSON protocol already in `aws.py` `SERVICES` | `CREDENTIAL` |
| AWS EKS | Query protocol, same signer | `ENVIRONMENT`, `AGENT_RUNTIME` |
| Generic OpenAPI | `openapi.py` and `openapi_risk.py` exist | `API` |

---

## Needs an SDK or credential type this repository does not have

Listed because the specification names them, **not** because they are planned
for a particular release. Bedrock, Entra, Vertex, OpenAI and generic MCP were
in this table until the connectors were written; they are now above, under a
status that keeps "written" separate from "proven".

| Connector | Blocker |
|---|---|
| Microsoft Foundry | Azure credential chain, no tenant to test against |
| Copilot Studio | Graph API + admin consent |
| Anthropic Claude Code / Claude Enterprise | Vendor API where enrolment permits |
| Cursor | No published inventory API |
| GitHub Copilot | Enterprise admin API |
| LangGraph, CrewAI, AutoGen | Framework-local state, not a queryable service |
| Salesforce Agentforce | Vendor SDK |
| Databricks | Workspace API + PAT |
| n8n | Self-hosted API, instance-specific |
| Splunk, Datadog, QRadar | These are *outputs* — see below |
| ServiceNow, Jira, Slack, PagerDuty | SOAR/ITSM targets — see below |
| Okta | SCIM already covers provisioning; discovery would add app inventory |

### Splunk, Datadog, ServiceNow, Jira, Slack, PagerDuty

These appear in the specification's discovery list, and they are not discovery
sources for this architecture — they are **destinations**. Sentinel already
delivers to SIEM over webhook, OTLP and syslog (`siem_transports.py`) and to
SOAR/ITSM through the remediation catalogue.

Reading an inventory back out of them is possible and would tell you what
*those* tools know, which is a different question from what is running. Recorded
here so the omission is a decision rather than an oversight.

---

## The property that matters more than the count

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

## Adding a connector

1. Implement the `Connector` protocol: a `name` and `discover() -> AssetInventory`.
2. Map native types onto `AssetKind`, keeping the native type in `native_type` —
   the normalised kind answers cross-connector questions, the native type is how
   somebody finds the thing again in the console it came from.
3. Report coverage honestly. Every unreachable target needs a **reason**;
   "coverage was partial" is a shrug wearing a data structure.
4. Register it in `build_connectors` behind its credential, so an unconfigured
   connector is **absent** rather than present-and-returning-empty.
5. Add it to this table with its real status.
