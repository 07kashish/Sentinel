# Sentinel GAP LEDGER

Generated from commit `658f86b573e1` with a DIRTY working tree on 2026-09-04.

Regenerate with `PYTHONPATH=. python scripts/build_gap_ledger.py`. Every path cited below is resolved against the working tree at generation time, and a miss fails the run -- so this document cannot describe files that are not there.

**This is an audit, not release evidence.** It is generated from a possibly-dirty tree by design. Release evidence comes from `scripts/run_release_gates.py`, which refuses a dirty tree.

## Where this stands

| Status | Count |
|---|---:|
| COMPLETE | 30 |
| EXTERNALLY-UNVERIFIED | 8 |
| PARTIAL | 8 |

**9 entries block PRODUCTION GA.**

The honest summary: the engineering is broad and the testing is unusually rigorous. The capability the product is named for -- binding an authorization to the execution it authorized -- is **COMPLETE**.

Everything else is either done, deferred for a stated reason, or waiting on evidence that code cannot produce.

## GA blockers, in the order they should be addressed

- **Phase 15 — AWS production implementation in real Terraform: network, security, ecs, database, redis, queue, storage, kms, secrets, observability, waf, backup, budgets** (PARTIAL). Apply it, in the order docs/AWS_PRODUCTION_ARCHITECTURE.md sets out: identity first (free), then dev, then pilot with a design partner. Deliberately NOT applied here -- the operator has said cost-incurring resources must not be started, and an apply is theirs to run. Import the hand-built bucket into state at the same time.

Then the external gates, which no amount of engineering closes: INDEPENDENT_PENTEST, PRODUCTION_SOAK, INDEPENDENT_FAILURE_DOMAIN_DR, DESIGN_PARTNER_VALIDATION, PRODUCTION_CUSTOMER_VALIDATION, MEASURED_AWS_UNIT_ECONOMICS, REAL_WORLD_DETECTION_METRICS, REFERENCE_CUSTOMERS.

## Full ledger

### Phase 0 — Forensic repository audit with machine-readable ledger

**COMPLETE**

- *What exists*: This generator plus its two outputs.
- *What was checked*: Generated from the working tree; every cited path resolved or the run fails.
- *Competitive relevance*: none - internal instrument
- *Implementation*: `scripts/build_gap_ledger.py`
- *Recommended action*: Regenerate whenever a phase closes.
- *Acceptance criteria*: Ledger regenerates clean and cites no missing path.

### Phase 1 — No secret can enter a distribution artifact

**COMPLETE**

- *What exists*: Ignore rules across git and Docker, a release secret scan, and a redaction layer so findings are never printed.
- *What was checked*: .gitignore line 11 ignores .env and `git check-ignore -v .env` confirms it; .dockerignore present; scan gate wired into the release runner.
- *Competitive relevance*: table stakes
- *Implementation*: `.gitignore`, `.dockerignore`, `scripts/run_release_gates.py`
- *Tests*: `tests_arch/test_security_rules.py`
- *Docs*: `docs/SECURITY.md`
- *Recommended action*: None.
- *Acceptance criteria*: A planted credential fails the release gate and is not echoed.

### Phase 2 — Distributed security state; refuse multi-replica with process-local limits

**COMPLETE**

- *What exists*: RedisCache implements the shared Cache protocol including distributed locks. Topology is now OBSERVED from the process table at server startup, and a deployment whose rate limiter would be per-process across replicas refuses to serve.
- *What was checked*: The gap was real: `_redis_present_for_multi_shard` reads SENTINEL_WORKER_SHARD_COUNT, an operator-declared value, so `uvicorn --workers 4` with that variable unset passed preflight while four processes each enforced the full rate. sentinel/composition/topology.py now reads the launch command and sibling processes instead, and test_four_workers_are_refused_with_nothing_declared asserts the refusal WITHOUT declaring anything -- that test fails against the predecessor check, which is what makes it evidence rather than decoration. Two further tests enter the real lifespan and prove create_application consults the observation and lets the refusal escape, because a guard that is never called is this repository's most-repeated defect.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/persistence/cache.py`, `sentinel/composition/topology.py`, `sentinel/composition/preflight.py`, `sentinel/interface/asgi.py`
- *Tests*: `tests_arch/test_runtime_topology.py`, `tests_arch/test_production_preflight.py`
- *Docs*: `docs/DEPLOYMENT.md`
- *Recommended action*: None. Note the residual boundary, which is stated in the code and in the preflight output rather than hidden: observation reads /proc, so it returns UNOBSERVABLE on Windows. Production then refuses without a shared limiter unless the operator sets SENTINEL_SINGLE_PROCESS_ATTESTED, and an attestation cannot override a contradicting observation -- otherwise it would be a switch for turning the check off.
- *Acceptance criteria*: A deployment with more than one real worker and no Redis URL refuses to start WITHOUT the shard variable being set. Met.

### Phase 3 — Authorization-to-execution binding: approved parameter digest must equal executed parameter digest

**COMPLETE**

- *What exists*: ExecutionAuthorization commits to a domain-separated approved_parameter_digest and to the signed delegation chain digest; verify_binding recomputes both immediately before execution and pins tool, MCP server, action, resource, tenant and agent; ExecutionReceipt binds authorization -> executed request -> result and is stored durably. SENTINEL_REQUIRE_EXECUTION_BINDING refuses the unbound path, and InlineToolProxy -- the chokepoint the MCP gateway routes through -- consumes it. And observed_binding.py compares what a TRACE saw against the authorized scope, which is the only evidence here that does not depend on the caller having been honest -- wired through SkillDetonationService and the container, not left as a module with tests and no callers.
- *What was checked*: All nine enumerated negatives refuse, each paired with the positive from the same fixture. At the seam, refusals are observed by COUNTING side-effect invocations rather than by catching the exception. The trace comparison is three-valued: CONSISTENT, VIOLATED or UNOBSERVED, and UNOBSERVED is not a pass -- an empty file list means nothing unless a file-opening syscall was captured, because the emptiness may describe the FILTER rather than the process. Tested against the REAL captured strace fixture, not only against a hand-built shape.

WIRING IT FOUND A LIVE DEFECT, which is the argument for doing the wiring rather than declaring the module done. The whole detonation subsystem -- Detonator, assess, and both container implementations -- had passing tests and ZERO production callers, and was never in the reachability registry, so nothing noticed. Crossing that seam exposed that `assess` searched `outbound_payloads` for canary VALUES while both real detonators fill that field with canary NAMES (deliberately: a credential-shaped string must not enter an evidence record). So CANARY_EXFILTRATION -- the one behaviour the module calls proof rather than signal -- could not fire from either sandbox. It passed every test because assess's tests hand-built observations containing values while the detonators' tests asserted names. Fixed in assess, not in the detonators, so the canary value still never reaches an evidence record; a test asserts the name is present and the value is absent. 177 tests across the binding and detonation modules.
- *Security risk*: The declaration residual is now covered by observation where a trace exists. What remains is scope rather than soundness: the tracer runs in DETONATION, not in the live path, so a live execution is still bound by declaration plus parameter digest plus delegation chain, and the syscall-level check applies to skills that are detonated -- which now requires SENTINEL_DETONATION_IMAGE and SENTINEL_DETONATION_TRACING to be set. Unset, the service REFUSES rather than falling back to a subprocess, and an untraced sandbox returns UNOBSERVED rather than a pass. Enforcing from a trace at runtime would mean stopping a syscall mid-flight, which is a seccomp or LSM problem and a different piece of software -- so a trace violation is a finding and the containment path acts on it.
- *Competitive relevance*: This is the differentiator. Prisma/Noma/Cisco largely observe and score; none binds an approval to an execution cryptographically, and none compares a syscall trace against the scope that was approved.
- *Implementation*: `sentinel/domain/execution_binding.py`, `sentinel/domain/observed_binding.py`, `sentinel/application/tool_runner.py`, `sentinel/application/tool_proxy.py`, `sentinel/application/skill_detonation.py`, `sentinel/composition/detonation_wiring.py`, `sentinel/infrastructure/sql/receipt_store.py`, `sentinel/composition/settings.py`
- *Tests*: `tests_arch/test_execution_binding.py`, `tests_arch/test_execution_binding_seam.py`, `tests_arch/test_observed_binding.py`, `tests_arch/test_skill_detonation.py`, `tests_arch/test_components_are_reachable.py`, `tests_arch/test_receipt_store.py`
- *Docs*: `docs/EXECUTION_TRUST_ARCHITECTURE.md`
- *Recommended action*: None. The remaining work is adoption rather than mechanism: migrate call sites and set the flag true, which is a deployment activity.
- *Acceptance criteria*: Nine negative tests pass, no production call site can reach a tool without an authorization once the flag is set, the delegation chain is bound, and a trace can contradict a declaration. Met.

### Phase 4 — Agent identity and signed delegation chains

**COMPLETE**

- *What exists*: Cryptographic agent identity and key management, plus a DelegationPassport whose every hop is signed by its ISSUER with the issuer's own Ed25519 key. The chain is a hash chain -- each hop commits to its predecessor's digest -- and verification enforces monotonicity hop by hop: capabilities a subset, scope no wider, environment no higher, expiry no later.
- *What was checked*: 19 defect kinds, each explained. The load-bearing tests are the monotonicity ones, where EVERY HOP IS CORRECTLY SIGNED and individually well-formed while hop 2 grants what hop 1 never held -- the attack is a valid signature over a grant the signer was not entitled to make, not a forged one. A hop signed by the wrong party is a SEPARATE defect from an invalid signature, because a cryptographically perfect signature by somebody other than the named issuer is the failure this whole design exists to stop. An unknown key yields UNKNOWN_KEY and never None. 37 tests.
- *Security risk*: none. The residual that existed -- hops asserted by the control plane rather than signed by each delegator -- is closed: a verifier holding the issuer public keys reconstructs the chain from signatures alone, and the platform cannot add, widen or reorder a hop without a key it does not have.
- *Competitive relevance*: differentiator
- *Implementation*: `sentinel/domain/identity.py`, `sentinel/domain/keys.py`, `sentinel/domain/delegation_constraints.py`, `sentinel/domain/delegation_passport.py`, `sentinel/infrastructure/delegation_signing.py`
- *Tests*: `tests_arch/test_delegation_passport.py`, `tests_arch/test_delegation_constraints.py`
- *Docs*: `docs/ENTERPRISE_CONTROLS.md`
- *Recommended action*: None. One honest limitation is recorded in the tests rather than hidden: because a hop may not both permit and prohibit the same capability, PROHIBITED_CAPABILITY_GRANTED co-occurs with CAPABILITY_EXPANSION -- it is defence in depth, and it earns its keep by accumulating from ANY earlier hop where the expansion check compares only against the immediate parent.
- *Acceptance criteria*: A tampered hop, a reordered chain, a dropped middle hop and a hop signed by the wrong party all fail verification without the control plane being consulted. Met.

### Phase 5 — Enterprise discovery: pluggable connectors across 17 priority platforms; agent asset graph

**PARTIAL**

- *What exists*: Nine connectors now. The four that existed -- AWS IAM, GitHub, Kubernetes, PostgreSQL -- discover the identities an agent could act as. Five new ones talk to the control planes where agents are DECLARED: Bedrock Agents (AgentCore), Microsoft Entra, Vertex AI reasoning engines, OpenAI assistants and any MCP server via tools/list. Plus discovery_wiring.py and scripts/run_discovery.py, which is the part that was actually missing.
- *What was checked*: AUDITING IS NOT WIRING, and this phase is where that cost something. build_connectors had tests, was cited in this ledger, was enumerated by scripts/build_state_audit.py -- and had no caller anywhere under sentinel/ or scripts/. The audit trail is exactly what made it look delivered.

What the new connectors get right is the honesty of a zero. An unconfigured connector is ABSENT, never present-and-empty, because an empty inventory cannot be told apart from a clean estate. A truncated listing sets pagination_complete=False with the reason -- and a mis-aimed mutation revealed that only ONE of the four page-cap branches was covered, so the other three are now parametrised and all four fail under mutation. A body that will not parse is UNREACHABLE rather than zero results, which is the defect shape this codebase keeps rediscovering. A JSON-RPC error arrives at HTTP 200, so an MCP server that refuses is recorded rather than read as a server with no tools. Entra service principals are SERVICE_ACCOUNT and never AGENT: Graph has no concept of an agent and an app registration called prod-agent-sync is an app registration.

MCP tool descriptions and OpenAI function descriptions are deliberately NOT stored -- both are attacker-authored text, which is why test_mcp_attacks.py exists, and an inventory is read by analysts and summarised by models. 84 tests.
- *Security risk*: Visibility gaps, not vulnerabilities -- an undiscovered agent is an unenforced agent. Two specific residuals: no credential value reaches a URL, a log or a report (BearerCredentials and McpEndpoint redact in __repr__, and tests assert the scope is shown while the token is not), and sign_request now signs a caller-supplied PATH, which _signable_path restricts to an unreserved-character literal so the signed string and the transmitted one cannot drift -- a mismatch there surfaces as an opaque 403 that gets debugged in IAM for a day.
- *Competitive relevance*: Parity gap, narrowed. Connector breadth is where the incumbents are strongest. Nine of seventeen, and the five that matter most for agents specifically are now present.
- *Implementation*: `sentinel/infrastructure/platforms/ai_connectors.py`, `sentinel/infrastructure/platforms/ai_discovery.py`, `sentinel/infrastructure/platforms/connectors.py`, `sentinel/composition/discovery_wiring.py`, `scripts/run_discovery.py`, `sentinel/domain/assets.py`
- *Tests*: `tests_arch/test_ai_connectors.py`, `tests_arch/test_discovery_wiring.py`, `tests_arch/test_connectors.py`, `tests_arch/test_platform_discovery.py`, `tests_arch/test_components_are_reachable.py`
- *Docs*: `docs/CONNECTOR_MATRIX.md`, `docs/AGENT_DISCOVERY.md`
- *Recommended action*: REQUIRES EXTERNAL VALIDATION. Not one of the five new connectors has authenticated against a real tenant, and no test in a repository can establish that it would: request shapes, auth headers, pagination fields and scopes come from each vendor's published contract, and a published contract is not a successful call. Every connector reports this itself via `external_validation`, and describe_discovery names the unvalidated ones in the report rather than in a document nobody opens while reading a count. Obtain credentials and run scripts/run_discovery.py; sequence by which tenants are actually obtainable. The remaining eight platforms follow the same pattern.
- *Acceptance criteria*: Each new connector authenticates against a real tenant, normalises, syncs incrementally, detects deletion, and ships a least-privilege permission guide. No fake connectors. The code and the least-privilege scopes are met; the authentication is not, and cannot be from here -- which is why this stays PARTIAL rather than being scored on the code existing.

### Phase 6 — MCP security: registry, pinning, drift, poisoning detection, egress control

**COMPLETE**

- *What exists*: MCP registry with cryptographic server identity, tool manifest and schema fingerprinting, description-drift and poisoning detection, SSRF and egress restriction through the hardened outbound client, and invocation lineage.
- *What was checked*: The adversarial suite test_mcp_attacks.py exercises poisoning and impersonation paths; fingerprint pinning is present in the domain model; the egress policy is the same one enforced for the S3 sink.
- *Competitive relevance*: Differentiator. The depth here exceeds the observe-only posture most competitors ship.
- *Implementation*: `sentinel/domain/mcp.py`, `sentinel/domain/mcp_estate.py`, `sentinel/infrastructure/mcp_registry.py`, `sentinel/infrastructure/mcp_wire.py`, `sentinel/infrastructure/outbound.py`
- *Tests*: `tests_arch/test_mcp_attacks.py`, `tests_arch/test_mcp_registry.py`, `tests_arch/test_mcp_gateway.py`, `tests_arch/test_mcp_estate.py`, `tests_arch/test_mcp_wire_proxy.py`
- *Docs*: `docs/MCP_GATEWAY.md`
- *Recommended action*: None for the security model. The MCP Security Center is a console surface, tracked under Phase 19.
- *Acceptance criteria*: Adversarial MCP suite passes and each guard is mutation-detected.

### Phase 7 — A2A security and a Delegation Passport bound into the Execution Passport

**COMPLETE**

- *What exists*: A2A registry, agent cards, capability manifests, call graph, and detection of amplification, loops, card drift and cross-agent injection -- plus the signed DelegationPassport, whose digest is now committed to by ExecutionAuthorization and compared at execution.
- *What was checked*: `delegation_passport_digest` on the authorization is compared against the chain the caller actually presents, and a mismatch is DELEGATION_SUBSTITUTED. The attack it stops is subtle: a chain that is perfectly valid, grants the same capability, and belongs to somebody else -- whose authority is being exercised is the question. Threaded through ProtectedToolRunner and InlineToolProxy, and the proxy test counts side-effect invocations rather than trusting the exception.
- *Security risk*: An authorization issued WITHOUT a bound chain cannot compare one, and that is a real state -- not every action flows through a delegation. It is REPORTED as delegation_bound=False rather than inferred from an absence, because comparing to nothing would accept any chain and comparing to an empty string would refuse every legitimate call.
- *Competitive relevance*: differentiator
- *Implementation*: `sentinel/domain/a2a.py`, `sentinel/infrastructure/a2a_registry.py`, `sentinel/domain/delegation_passport.py`, `sentinel/domain/execution_binding.py`, `sentinel/application/tool_proxy.py`
- *Tests*: `tests_arch/test_a2a_delegation.py`, `tests_arch/test_a2a_proxy.py`, `tests_arch/test_delegation_passport.py`, `tests_arch/test_execution_binding_seam.py`
- *Docs*: `docs/A2A_GATEWAY.md`
- *Recommended action*: None.
- *Acceptance criteria*: An independent verifier validates the chain from signatures alone, a forged hop fails, and a valid chain from the wrong principal is refused at execution. Met.

### Phase 8 — Endpoint and shadow-agent discovery sensor

**COMPLETE**

- *What exists*: A read-only sensor that reads ONLY an allowlist of agent configuration paths -- MCP configs for Claude Desktop, Cursor, Continue and Claude Code, framework manifests, and CI workflow names. Three-valued coverage, three-valued enrolment, and a fleet total that counts only hosts whose absences mean something.
- *What was checked*: Run live on this machine: 2 allowlisted paths read, COMPLETE, 0 findings. The privacy properties are tests rather than intentions -- a planted .bash_history, .ssh/id_rsa, .aws/credentials and a documents file are all present in the fixture and none appears in the scan; a planted API key is digested to 16 characters and its value is absent from both the scan and the serialised report; and an AST check asserts the scanner calls no write, unlink, rename or chmod, because a write introduced later would pass every behavioural test until it hit the wrong file. 33 tests.
- *Security risk*: The sensor is the component most likely to be uninstalled, and not because of a bug: one engineer finding it read something personal ends the rollout. So the allowlist is the entire surface, `--explain` prints it before anybody runs it for real, credential VALUES are never retained, and the host label is the hostname rather than a durable device fingerprint.
- *Competitive relevance*: Parity gap closed. Competitors ship endpoint agents; this is narrower than theirs by design -- configuration discovery, not EDR.
- *Implementation*: `sentinel/domain/endpoint_sensor.py`, `sentinel/infrastructure/endpoint_scan.py`, `scripts/run_endpoint_sensor.py`
- *Tests*: `tests_arch/test_endpoint_sensor.py`
- *Docs*: `docs/AGENT_DISCOVERY.md`
- *Recommended action*: Windows paths are deliberately absent: they need their own allowlist and their own review, and a Windows machine reports UNREADABLE rather than appearing clean. Add them when a design partner runs Windows.
- *Acceptance criteria*: A read-only sensor collecting MCP and agent configuration without personal content, whose absences are distinguishable from its failures. Met. NOT met: signed and remotely attestable -- the sensor is a script, not a signed binary, which matters when it is distributed rather than run from a checkout.

### Phase 9 — AI-BOM and agent supply chain with impact analysis

**COMPLETE**

- *What exists*: Machine-readable BOM over agents, models, prompts, frameworks, MCP servers, tools, datasets and cloud resources, with a Completeness verdict that refuses to read an empty scan as a clean estate.
- *What was checked*: Completeness.UNUSABLE is returned by _judge_completeness when no sources are present or every source examined zero items. Read directly and covered by test_ai_bom.py.
- *Competitive relevance*: Parity, with the completeness honesty as an edge.
- *Implementation*: `sentinel/domain/ai_bom.py`
- *Tests*: `tests_arch/test_ai_bom.py`
- *Docs*: `docs/sentinel.cdx.json`
- *Recommended action*: None.
- *Acceptance criteria*: An empty scan reports UNUSABLE, never a clean estate.

### Phase 10 — Adversarial red-team platform with reproducible benchmarks

**COMPLETE**

- *What exists*: Scenario packs across injection, tool poisoning, authorization bypass, exfiltration and delegation abuse, with a campaign runner recording expected versus actual outcome per scenario.
- *What was checked*: AttackOutcome.NOTHING_OBSERVED separates observation from judgement, so an unobserved attack is never scored as prevented. That was the specific defect found in the predecessor runner, which counted 5xx responses as blocks.
- *Competitive relevance*: parity
- *Implementation*: `sentinel/domain/attack_campaign.py`, `scripts/run_attack_campaign.py`
- *Tests*: `tests_arch/test_attack_campaign.py`, `tests_arch/test_red_team_suite.py`, `tests_arch/test_security_prompt_injection.py`
- *Docs*: `docs/ADVERSARIAL_REVIEW.md`
- *Recommended action*: Add the nine Phase 3 negative scenarios once that binding exists.
- *Acceptance criteria*: Every scenario records objective, expectation, observation and whether enforcement blocked. Synthetic results never presented as customer proof.

### Phase 11 — Detection science: ensemble, staged rollout, measured false-positive rate

**COMPLETE**

- *What exists*: Deterministic rules, sequence correlation, graph analysis and statistical detection, kept architecturally separate from authorization, with OBSERVE/SHADOW/WARN/APPROVAL/ENFORCE stages and a promotion gate.
- *What was checked*: test_soft_detection_independent.py enforces that soft detection cannot reach the authorization path. A benign false-positive corpus is recorded under docs/evidence.
- *Competitive relevance*: Parity, and deliberately not the moat.
- *Implementation*: `sentinel/infrastructure/detection.py`, `sentinel/infrastructure/soft_detection.py`, `sentinel/domain/sequences.py`
- *Tests*: `tests_arch/test_detection_mode.py`, `tests_arch/test_sequence_corpus.py`, `tests_arch/test_soft_detection_independent.py`, `tests_arch/test_evaluation_promotion.py`
- *Docs*: `docs/benign_tool_call_false_positives.json`
- *Recommended action*: None. Real-world detection metrics remain an external gate.
- *Acceptance criteria*: No detector can influence an authorization decision, and each has a version, corpus and rollback.

### Phase 12 — Policy-bounded automated containment

**COMPLETE**

- *What exists*: Idempotent, reversible-where-possible containment actions behind approval thresholds, with dry-run and simulation, and no LLM in the control path.
- *What was checked*: test_gated_remediation.py covers the approval gate and test_native_sentinel_containment.py covers the executed path.
- *Competitive relevance*: parity
- *Implementation*: `sentinel/domain/containment.py`, `sentinel/domain/remediation.py`, `sentinel/infrastructure/containment.py`, `sentinel/infrastructure/native_containment.py`
- *Tests*: `tests_arch/test_response_and_containment.py`, `tests_arch/test_gated_remediation.py`, `tests_arch/test_native_sentinel_containment.py`, `tests_arch/test_remediation_execution.py`
- *Docs*: `docs/RESPONSE_AND_CONTAINMENT.md`, `docs/REMEDIATION_MATRIX.md`
- *Recommended action*: None.
- *Acceptance criteria*: Every action is authorized, idempotent, evidenced and simulable.

### Phase 13 — Execution Passport 2.0 as a published spec with an offline verifier and two client libraries

**COMPLETE**

- *What exists*: A written specification, a generated JSON Schema, a 16-vector conformance corpus with a malicious half, and TWO independent verifiers -- the Python reference and a dependency-free JavaScript one -- required to agree on every vector.
- *What was checked*: The second implementation earned its keep immediately: it found a real specification gap. Python has arbitrary-precision integers and accepted 2**53 + 1; JavaScript has one number type and refused it. Past 2^53 an IEEE-754 double cannot hold the value exactly, so the document round-trips to a different number and its digest changes in a verifier the issuer does not control. The Python canonicaliser was corrected to match and both now refuse it. Digests are compared DIRECTLY across the two implementations, not just via the runner, because a runner passing proves nothing if the JS digest function echoed the claimed value back. 33 tests.
- *Security risk*: none. Verification needs no network, no database and no cooperation from the issuer -- the JS verifier imports only node builtins, so an auditor installs no package tree and there is no build step to trust either.
- *Competitive relevance*: Differentiator. Nobody else ships portable execution evidence with a second independent verifier.
- *Implementation*: `sentinel/domain/passport.py`, `sentinel/interface/passport_cli.py`, `spec/execution-passport/README.md`, `spec/execution-passport/verify.mjs`, `spec/execution-passport/schema.json`, `scripts/build_passport_vectors.py`, `scripts/build_passport_schema.py`
- *Tests*: `tests_arch/test_passport_conformance.py`, `tests_arch/test_execution_passport.py`, `tests_arch/test_passport_standard.py`
- *Docs*: `spec/execution-passport/README.md`
- *Recommended action*: v2 adds the Phase 3 parameter digests to the schema. Deliberately not done yet: publishing a field before its shape is settled means breaking it later, and the spec says so rather than sketching them.
- *Acceptance criteria*: Two independent implementations agree on every conformance vector, including the malicious ones, with no network access. Met -- 16/16.

### Phase 14 — Transparency log with WORM anchoring and independent verification

**COMPLETE**

- *What exists*: RFC 6962 Merkle log with inclusion and consistency proofs, an append-only store whose primary key makes append-only the database property, and S3 Object Lock COMPLIANCE publication.
- *What was checked*: A real root is published and AWS returned Mode: COMPLIANCE. Deletion was ATTEMPTED and refused: AccessDenied because object protected by object lock. /v1/transparency/root returns independently_verifiable true. This is the only phase whose central claim was tested against a live adversarial action rather than a mock.
- *Competitive relevance*: differentiator
- *Implementation*: `sentinel/domain/transparency.py`, `sentinel/domain/root_sink.py`, `sentinel/infrastructure/s3_root_sink.py`, `sentinel/infrastructure/sql/transparency_store.py`, `sentinel/interface/transparency_routes.py`, `scripts/publish_transparency_root.py`
- *Tests*: `tests_arch/test_transparency.py`, `tests_arch/test_transparency_routes.py`, `tests_arch/test_transparency_store.py`, `tests_arch/test_root_sink.py`, `tests_arch/test_s3_root_sink.py`
- *Docs*: `docs/TRANSPARENCY_SINK.md`
- *Recommended action*: None for the mechanism. Note the daily publisher is registered Interactive-only on the operator workstation, so it does not run while logged out; that is a deployment weakness, not a code one.
- *Acceptance criteria*: An auditor fetches the locked object from S3 and verifies a proof without consulting this deployment. Met.

### Phase 15 — AWS production implementation in real Terraform: network, security, ecs, database, redis, queue, storage, kms, secrets, observability, waf, backup, budgets

**PARTIAL**  ·  **blocks GA**

- *What exists*: All thirteen modules plus a `stack` module that wires them once, and three environment roots (dev, pilot, production) that differ only in values. Graviton throughout, NAT off by default with VPC endpoints instead, Object Lock COMPLIANCE on the evidence bucket, two IAM roles per task, and a WAF that starts in count mode everywhere.
- *What was checked*: `terraform validate` passes on ALL THREE environments -- dev, pilot and production, each initialised separately. `scripts/check_terraform_posture.py` reads the stack's `posture` output and refuses a production environment whose posture contradicts its name -- and test_terraform_posture.py proves that checker can actually FAIL by mutating each of the eight production controls in a copied tree and requiring it to notice. That mattered: the checker passed 3/3 on its first run while its regex was matching its own HEADER COMMENT rather than the assignment, so it would have reported success whatever the configuration said. 20 tests.
- *Security risk*: PARTIAL, and the reason is not the code. NOTHING HERE HAS EVER BEEN APPLIED. `validate` proves the configuration is coherent and proves nothing about whether it works, so every gate downstream of a running environment -- soak, capacity, cross-region DR, measured unit economics -- stays open. The one production resource that DOES exist, the Object Lock bucket, was created by CLI and has no Terraform representation, which is its own drift problem and is recorded rather than tidied away.
- *Competitive relevance*: Table stakes. A platform that cannot be deployed cannot be evaluated.
- *Implementation*: `deploy/terraform/aws/modules/stack`, `deploy/terraform/aws/modules/network`, `deploy/terraform/aws/modules/database`, `deploy/terraform/aws/modules/ecs`, `deploy/terraform/aws/modules/storage`, `deploy/terraform/aws/envs/dev`, `deploy/terraform/aws/envs/pilot`, `deploy/terraform/aws/envs/production`, `scripts/check_terraform_posture.py`
- *Tests*: `tests_arch/test_terraform_posture.py`
- *Docs*: `docs/AWS_PRODUCTION_ARCHITECTURE.md`
- *Recommended action*: Apply it, in the order docs/AWS_PRODUCTION_ARCHITECTURE.md sets out: identity first (free), then dev, then pilot with a design partner. Deliberately NOT applied here -- the operator has said cost-incurring resources must not be started, and an apply is theirs to run. Import the hand-built bucket into state at the same time.
- *Acceptance criteria*: terraform validate and plan clean for all three environments AND an applied environment serving traffic. The first half is met; the second is what makes this PARTIAL rather than COMPLETE.

### Phase 16 — Kubernetes enterprise hardening

**COMPLETE**

- *What exists*: Helm chart with non-root, read-only filesystem, dropped capabilities, seccomp, resource limits, network policies, PDB, HPA, probes and graceful termination.
- *What was checked*: Seven templates present under deploy/helm/sentinel/templates and covered by test_helm_postgres_archive.py plus the deployment environment test.
- *Competitive relevance*: table stakes
- *Implementation*: `deploy/helm/sentinel`, `deploy/k8s`
- *Tests*: `tests_arch/test_helm_postgres_archive.py`, `tests_arch/test_deployment_environment_is_canonical.py`
- *Docs*: `docs/DEPLOYMENT.md`
- *Recommended action*: None.
- *Acceptance criteria*: Chart lints, conforms and passes policy-as-code checks.

### Phase 17 — Formally verified tenant isolation

**COMPLETE**

- *What exists*: PostgreSQL row-level security with FORCE, plus application-level checks, plus adversarial integration tests for cross-tenant read, write, IDOR, forged header, cache poisoning and evidence leakage.
- *What was checked*: test_tenant_isolation_rls.py runs against both engines via the engine_config fixture; a fitness rule requires new SQL-touching test modules to be parametrised over both, so an isolation test cannot silently cover only SQLite.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/sql`, `sentinel/infrastructure/orgs.py`
- *Tests*: `tests_arch/test_tenant_isolation_rls.py`, `tests_arch/test_multi_tenant_soak.py`, `tests_arch/test_tenant_integrations.py`, `tests_arch/test_tenant_siem_credentials.py`
- *Docs*: `docs/ENTERPRISE_CONTROLS.md`
- *Recommended action*: None.
- *Acceptance criteria*: Every cross-tenant attempt fails. Met on both engines.

### Phase 18 — Enterprise identity: OIDC, SAML, SCIM, MFA, RBAC and ABAC, maker/checker, break-glass

**COMPLETE**

- *What exists*: OIDC and SAML with XML hardening, SCIM provisioning, WebAuthn passkeys and MFA, role and attribute authorization, and an audited privileged-action path.
- *What was checked*: test_saml_xml_hardening.py covers the signature-wrapping class of attack; test_security_passkeys.py and test_security_mfa.py cover the authenticator paths.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/oidc.py`, `sentinel/infrastructure/saml.py`, `sentinel/infrastructure/webauthn.py`, `sentinel/domain/mfa.py`
- *Tests*: `tests_arch/test_security_mfa.py`, `tests_arch/test_security_passkeys.py`, `tests_arch/test_saml_xml_hardening.py`, `tests_arch/test_security_audit_trail.py`
- *Docs*: `docs/ENTERPRISE_CONTROLS.md`
- *Recommended action*: None.
- *Acceptance criteria*: Every privileged action is audited and no SSO assertion is trusted without signature validation.

### Phase 19 — Security operations console covering twenty modules

**COMPLETE**

- *What exists*: An API surface across ten route modules, now including the approved-versus-executed diff -- the view the ledger called the single most valuable one this product can show. Backed by a durable, append-only receipt store with its own migration and RLS policy.
- *What was checked*: 34 route tests drive the REAL application, so an unregistered route fails there rather than in a deployment. Parameter VALUES are never served and a planted probe -- chosen so it appears nowhere else in a response, after an earlier test in this repository reported a leak that was a substring of a resource ARN -- is asserted absent. `only_mismatched` defaults FALSE, because a mismatches-only view makes a healthy estate and a deployment where nothing is bound look identical.
- *Security risk*: none. The disclosure boundary is deliberate: this surface is read by a browser, cached by it and pasted into tickets, so it serves digests and differing KEY NAMES and never the parameter values -- a response carrying both sets would be the most sensitive one in the product.
- *Competitive relevance*: Differentiator. Competitors show what was decided; this shows whether what ran matched it.
- *Implementation*: `sentinel/interface`, `sentinel/interface/binding_routes.py`, `sentinel/infrastructure/sql/receipt_store.py`
- *Tests*: `tests_arch/test_binding_routes.py`, `tests_arch/test_receipt_store.py`, `tests_arch/test_console_bundle.py`
- *Docs*: `docs/ENTERPRISE_CONTROLS.md`
- *Recommended action*: None for the diff. The remaining console modules the prompt enumerates are visualisations of data that already has an API, which is a front-end body of work rather than a platform one.
- *Acceptance criteria*: Each dashboard question in the prompt is answerable from the API without a bespoke query, and the approved-versus-executed diff exists. Met. Worth recording: the first coverage endpoint reported a bound-versus-unbound ratio that was structurally always 1.0, because ExecutionReceipt requires an authorization digest and the unbound path returns no receipt at all -- a metric that could only report perfect coverage. A test caught it and the endpoint now reports its own blindness instead.

### Phase 20 — Enterprise workflow integrations

**COMPLETE**

- *What exists*: Six connectors in `soar.py` -- ServiceNow, Jira, PagerDuty, Slack, Teams and a generic webhook -- each going through the hardened outbound client, plus SIEM export with per-tenant credentials and routing, OTLP and syslog transports.
- *What was checked*: A CORRECTION to my own Phase 0 audit, which recorded this as PARTIAL with 'no dedicated Slack, Teams, Jira, ServiceNow or PagerDuty adapter was found'. That was wrong: a grep across sentinel/infrastructure/*.py returned ONE matching file and I read the count as meaning the capability barely existed, when the one file was soar.py and it holds all six. The audit rule I wrote for myself -- never infer status from the presence or absence of a file -- is exactly what I failed to apply.

What is actually there is better than a set of adapters: the injection escaping is per-destination and correct. `escape_slack` handles ampersand FIRST, because escaping `<` before `&` would turn a literal `&lt;` the attacker typed into a real `<` on the way out; it neutralises `@here`/`@channel` broadcasts with a zero-width space; and it replaces backticks, because a value that breaks out of a code span formats the rest of the message including the fields below it. `escape_ticket_text` collapses newlines, because a description is read as labelled lines and a value that can insert a newline can insert its own label -- which is how `Approved by: security` appears in a ticket nobody wrote it into. 57 tests.
- *Security risk*: none. Every connector uses the hardened client, so none of them reintroduces the redirect token-leak class already proven in this codebase, and each destination gets escaping written for ITS syntax rather than a shared sanitiser that is wrong for all of them.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/soar.py`, `sentinel/infrastructure/siem.py`, `sentinel/infrastructure/siem_transports.py`, `sentinel/composition/notifications.py`
- *Tests*: `tests_arch/test_remediation_execution.py`, `tests_arch/test_siem_delivery.py`, `tests_arch/test_siem_export.py`, `tests_arch/test_siem_transports.py`, `tests_arch/test_tenant_integrations.py`
- *Docs*: `docs/ENTERPRISE_CONTROLS.md`
- *Recommended action*: None. Case history, comments and ticket synchronisation are deeper integrations that need a real instance to develop against, and they are worth building on design-partner demand rather than speculatively.
- *Acceptance criteria*: Each adapter delivers through the hardened client, carries no secret in a URL, is per-tenant scoped, and escapes for its own destination syntax. Met.

### Phase 21 — Compliance evidence automation without claiming certification

**COMPLETE**

- *What exists*: Control mappings for SOC 2, ISO 27001, NIST CSF, NIST AI RMF, OWASP LLM Top 10 and MITRE ATLAS, with generated evidence packages.
- *What was checked*: COMPLIANCE_MAP.md, COMPLIANCE_MATRIX.md and ASI_THREAT_CONTROL_MATRIX.md present; the docs distinguish supports compliance evidence from certified compliant.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/domain/protect.py`
- *Tests*: `tests_arch/test_enterprise_controls.py`
- *Docs*: `docs/COMPLIANCE_MAP.md`, `docs/COMPLIANCE_MATRIX.md`, `docs/ASI_THREAT_CONTROL_MATRIX.md`
- *Recommended action*: None. Certification itself is an external gate and NOT_APPLICABLE to a codebase.
- *Acceptance criteria*: No document claims certification. Met.

### Phase 22 — OpenTelemetry instrumentation and defined SLOs

**PARTIAL**

- *What exists*: observability.py with OTLP export, a Prometheus scrape config and alert rules, plus -- new -- sentinel/domain/slo.py and scripts/evaluate_slos.py, which COMPUTE the SLO verdicts that were previously prose somebody typed into a table.
- *What was checked*: The old action on this entry read 'None in code. Achievement against the SLOs requires the production soak.' Half of that was wrong: achievement does require the soak, but an EVALUATOR is code and there was none. docs/OBSERVABILITY.md carried a Status column reading UNVERIFIED, MET on PostgreSQL, MISSED on SQLite -- hand-authored verdicts on generated measurements, which drift in one direction because nobody forgets to downgrade a MET.

The verdict is three-valued and UNMEASURABLE is not a pass. A 99.9%/30d target permits ~2,592 seconds of failure, so the 420-second soak cannot report MET however clean it looks -- the entire error budget could be spent in a window longer than the run. A VIOLATION, by contrast, is reported from any window, because falsifying an SLO needs less evidence than confirming one. The CLI exits 1 for unmeasurable and 2 for violated, so a soak too short to fail can never be a green build.

Two findings from building it. The soak artifact carries `meets_ingest_p95_target`, a boolean the producer wrote about itself; the evaluator now prints it beside the computed verdict so the two can disagree visibly. And my first artifact mapper read plausible keys the file does not have, so every target came back UNMEASURABLE while the harness read nothing at all -- caught, and pinned by a test that asserts real numbers come out of the real file. 26 tests.
- *Security risk*: none. The residual is honesty rather than exposure, and it is now structural: no code path can report MET for a target whose window the run did not cover.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/domain/slo.py`, `scripts/evaluate_slos.py`, `sentinel/infrastructure/observability.py`, `deploy/alerts`, `deploy/prometheus.yml`
- *Tests*: `tests_arch/test_slo_evaluation.py`, `tests_arch/test_readiness_probe_cache.py`
- *Docs*: `docs/OBSERVABILITY.md`, `docs/MONITORING.md`
- *Recommended action*: Run the production soak. The targets are defined, the evaluator exists and exits non-zero until they are genuinely met, so what remains is elapsed time under real traffic -- which is PRODUCTION_SOAK and cannot be produced from a repository.
- *Acceptance criteria*: Targets defined; achievement claimed only from measurement. The definition and the measurement machinery are met; the measurement is not.

### Phase 23 — Reproducible performance engineering to 10,000+ concurrent agents

**PARTIAL**

- *What exists*: Reproducible benchmark harnesses for ingest, authorization, MCP proxy and persistence, with recorded artifacts carrying commit provenance.
- *What was checked*: Benchmark artifacts exist under docs/evidence with .provenance.json files naming commit and tree digest. They were produced on a developer workstation, so they characterise this machine, not the target architecture, and the prompt asks for the saturation point on real infrastructure.
- *Competitive relevance*: parity
- *Implementation*: `scripts/build_release_evidence.py`
- *Tests*: `tests_arch/test_persistence_benchmarks.py`
- *Docs*: `docs/PERFORMANCE_REPORT.md`, `docs/authorization_bench.json`, `docs/mcp_proxy_bench.json`
- *Recommended action*: Re-run against the Phase 15 environment once it exists. Blocked on Phase 15, not on harness work.
- *Acceptance criteria*: Saturation identified on target infrastructure and a safe operating envelope documented.

### Phase 24 — Chaos engineering across every dependency

**PARTIAL**

- *What exists*: Fault injection for the database, outbound network and execution paths, asserting no silent authorization bypass and no duplicate destructive action -- and now, in test_infrastructure_chaos.py, the fault an AZ loss actually presents to this process: the STORE BEHIND A SECURITY GATE stops answering. Each gate is exercised against a partitioned store and each refusal is paired with the positive built from the same fixture, because a refusal test alone passes against a gate that refuses everything.
- *What was checked*: test_dependency_chaos.py, test_outbound_chaos.py, test_execution_chaos.py and test_infrastructure_chaos.py pass. Wiring the AZ-loss case FOUND A DEFECT rather than confirming the design: AgentCapabilityGate.decide documented `Returns; never raises` and read the grant store as its first statement, ahead of the observe-mode branch -- so a store outage raised out of OBSERVE mode, the mode whose purpose is to decide nothing while an operator discovers which grants are needed and which Phase 30 uses to onboard design partners. A blip in a store that was deciding nothing became an outage for the partner. Both modes now answer, marked `degraded`, in opposite directions: observe allows because it never decided, enforcing refuses because an unreadable grant store cannot be told apart from an absent grant. Every assertion was confirmed by mutation -- reinstating the unguarded read fails four tests, silencing `degraded` fails three, dropping it from as_dict fails one. What remains needs real infrastructure: whole-node loss, KMS unavailability and a genuine AZ evacuation.
- *Security risk*: Gate-level fail-closed behaviour under store loss is now asserted rather than incidental. Node-level and KMS-level faults remain unverified, and a partitioned-store double is not proof that AWS loses a zone this way.
- *Competitive relevance*: differentiator
- *Implementation*: `sentinel/infrastructure/outbound.py`, `sentinel/application/agent_capabilities.py`
- *Tests*: `tests_arch/test_dependency_chaos.py`, `tests_arch/test_execution_chaos.py`, `tests_arch/test_infrastructure_chaos.py`, `tests_arch/test_outbound_chaos.py`, `tests_arch/test_ledger_multi_replica.py`
- *Docs*: `docs/SCALE_AND_ASSURANCE.md`
- *Recommended action*: Run against real infrastructure after Phase 15 for node loss, KMS unavailability and AZ evacuation. The gate-level half is done and guarded; a repository cannot produce the rest.
- *Acceptance criteria*: Security gates fail closed under every injected fault, including AZ loss.

### Phase 25 — Backup, PITR and an independent failure-domain DR exercise

**PARTIAL**

- *What exists*: Automated backups, WAL archiving, point-in-time recovery, four in-domain drills behind one entry point (scripts/run_dr_test.py, --strict fails on a skip), and now scripts/run_cross_region_dr_drill.py -- the cross-region exercise the gate actually needs.
- *What was checked*: The SQLite drill passes live and each drill prints what it does NOT prove beside its pass.

The cross-region script is mostly REFUSALS, because the failure mode for this drill is one that thinks it crossed a region and did not -- and a passing DR drill is exactly the artifact nobody re-checks. It refuses the same region twice, the same region in different case, two different NAMES for one location (us-standard is us-east-1, which a textual inequality check accepts), a destination inside the source bucket, an empty archive, and -- separately -- an archive that could not be LISTED, because unreadable and empty are different faults with different fixes.

A mutation caught my own test being wrong here: the lookalike-bucket case used a source path ending in /wal, which a bare startswith already rejects for unrelated reasons, so the test passed with the prefix bug reinstated. Corrected to a bare source, where s3://sentinel-wal-eu really does prefix-match s3://sentinel-wal-eu2. 19 tests on the cross-region preconditions, 14 on the in-domain entry point.
- *Security risk*: none. The residual is the gate and it is stated in every verdict: every drill that has RUN did so in one failure domain. independent_failure_domain_verified is a hardcoded False in both evidence artifacts, a test forbids the constant turning true, and the cross-region script derives its observed-regions-differ flag from the endpoints a run actually reached rather than from the arguments it was given -- an operator can pass any two region names.
- *Competitive relevance*: table stakes
- *Implementation*: `scripts/run_cross_region_dr_drill.py`, `scripts/run_dr_test.py`, `scripts/run_dr_postgres_wal_pitr_drill.py`, `scripts/run_dr_sqlite_drill.py`, `deploy/wal-archive`
- *Tests*: `tests_arch/test_cross_region_dr.py`, `tests_arch/test_dr_test_entrypoint.py`, `tests_arch/test_dr_postgres_wal_pitr_drill.py`, `tests_arch/test_persistence_backup_pitr.py`
- *Docs*: `docs/DR_RUNBOOK.md`, `docs/DISASTER_RECOVERY.md`, `docs/dr_postgres_wal_pitr_s3_drill.json`
- *Recommended action*: Run the cross-region exercise with real credentials and --i-accept-cross-region-costs. The preconditions, the refusals and the evidence format are done; the restore itself needs a destination instance this repository must not be able to create, and it costs money.
- *Acceptance criteria*: A restore into a genuinely separate failure domain validates integrity. NOT met and not self-certifiable -- even a successful run by the authors of the system is not independent verification, which is the whole content of the word.

### Phase 26 — Software supply chain: SBOM, scans, provenance, signed images and release manifest

**COMPLETE**

- *What exists*: CycloneDX SBOM, license and dependency scanning, secret scanning over history AND over the built artifact, commit-plus-tree binding on every artifact, a DAST gate with a dynamic-api-security CI job, and KEYLESS container image signing with an SBOM attestation.
- *What was checked*: Signing is keyless via GitHub OIDC, so the old objection -- artifact_signing 'needs a signing key this runner does not hold' -- has gone away rather than been worked around: there is no key. The CI job signs by DIGEST and then VERIFIES what it signed in the same job, because a signing step whose output nobody checks can silently produce an unverifiable signature. Verification pins BOTH the certificate identity and the OIDC issuer, and 18 tests cover the two ways a keyless check reads as a pass while checking nothing: an unpinned identity (which an attacker who signed their own image satisfies) and a missing cosign treated as success.
- *Security risk*: none for the mechanism. The residual is procedural: the signing job is OPT-IN, because signing requires pushing and pushing publishes. Until a repository sets SENTINEL_PUBLISH_IMAGES, no image is signed -- so a deployment must still verify the digest it is given, which is why the ecs Terraform module refuses an image reference that is not pinned by digest.
- *Competitive relevance*: table stakes
- *Implementation*: `scripts/run_release_gates.py`, `scripts/release_binding.py`, `scripts/verify_image_signature.py`, `.github/workflows/ci.yml`
- *Tests*: `tests_arch/test_image_signing.py`, `tests_arch/test_release_binding.py`, `tests_arch/test_vcs_integrity.py`, `tests_arch/test_source_hygiene.py`
- *Docs*: `docs/sentinel.cdx.json`, `docs/DEPENDENCY_LOCKING.md`
- *Recommended action*: Set SENTINEL_PUBLISH_IMAGES=true when a registry is chosen, then verify the resulting digest with scripts/verify_image_signature.py before deploying it.
- *Acceptance criteria*: Every release binds commit, build inputs, container digest, SBOM and test evidence, and the image signature is verifiable by identity rather than by a distributed key. Met.

### Phase 27 — One command produces release evidence for the exact current commit, failing on a dirty tree

**COMPLETE**

- *What exists*: A release-evidence builder plus a gate runner, with commit-and-tree binding on every artifact and a void-the-run rule when the tree changes mid-run.
- *What was checked*: test_ga_gates_cannot_be_faked.py exists specifically to prevent converting missing evidence into PASS, and historical evidence from another commit cannot satisfy the current gate.
- *Competitive relevance*: Differentiator in rigour, invisible to buyers.
- *Implementation*: `scripts/build_release_evidence.py`, `scripts/run_release_gates.py`, `scripts/release_binding.py`
- *Tests*: `tests_arch/test_release_gate_runner.py`, `tests_arch/test_ga_gates_cannot_be_faked.py`, `tests_arch/test_release_binding.py`
- *Docs*: `docs/RELEASE_GATES.md`, `docs/RELEASE_READINESS.md`
- *Recommended action*: Expose it under a task runner name for discoverability. The mechanism is done.
- *Acceptance criteria*: A dirty tree fails; evidence from another commit never satisfies the gate. Met.

### Phase 28 — Clean release packaging from an explicit allowlist, rescanned after packaging

**COMPLETE**

- *What exists*: An allowlist-based packager producing a deterministic zip with a sha256, a provenance sidecar reusing the existing release_binding machinery, and a gitleaks scan of the EXTRACTED artifact. A dirty tree is refused; a FAIL deletes the artifact; a missing scanner yields UNVERIFIED and a non-zero exit rather than a pass.
- *What was checked*: Built at commit 6ab8131: 503 files, gitleaks PASS. Verified by value rather than by pattern -- the two live credential strings were read out of .env and searched for in every collected file, and are absent. The scanner is proven able to FAIL: a derived canary credential is detected, so the PASS is not vacuous.
- *Security risk*: none for the packager itself. The residual is procedural: nothing PREVENTS somebody zipping the working directory by hand, and that directory contains a live .env. The packager makes the right thing easy; it cannot make the wrong thing impossible.
- *Competitive relevance*: table stakes
- *Implementation*: `scripts/build_release_artifact.py`
- *Tests*: `tests_arch/test_release_packaging.py`
- *Docs*: `docs/RELEASE_GATES.md`
- *Recommended action*: None. Worth noting for whoever extends this: two of my own checks here were vacuous before they were fixed, and both failed in the direction of a confident pass. The raw-bytes leak search could never match because a zip is DEFLATE-compressed, and the obvious canary -- AWS's published AKIAIOSFODNN7EXAMPLE -- is deliberately allowlisted by gitleaks, so a scan test built on it reports success against a scanner that is doing nothing. Both are now encoded as control assertions that fail if the check stops checking.
- *Acceptance criteria*: The artifact contains only allowlisted paths, a post-package secret scan passes, and the scan is demonstrably capable of failing. Met.

### Phase 29 — Documentation integrity enforced by CI

**COMPLETE**

- *What exists*: Guard tests that verify documents cite real tests, that claimed test counts hold, and that status documents match the code.
- *What was checked*: These guards have caught real drift in this work: a claimed count of 41 tests where pytest collected 30, and a stated RPO recalled from memory that contradicted the recorded artifact. A guard that has never failed is not evidence; these have.
- *Competitive relevance*: differentiator in rigour
- *Implementation*: `tests_arch/test_documentation_cites_real_tests.py`
- *Tests*: `tests_arch/test_documentation_cites_real_tests.py`, `tests_arch/test_delivery_status.py`, `tests_arch/test_research_page.py`
- *Docs*: `docs/DELIVERY_STATUS.md`, `docs/RESEARCH.md`
- *Recommended action*: None.
- *Acceptance criteria*: Documentation contradicting implementation fails CI. Met.

### Phase 30 — Design-partner onboarding with progressive enforcement

**COMPLETE**

- *What exists*: An observe-only onboarding mode that discovers, builds the identity graph and AI-BOM, shows privilege risk and recommends policy, then advances through OBSERVE/SIMULATE/WARN/APPROVAL/ENFORCE.
- *What was checked*: adoption.py with test_adoption.py, and a design-partner runbook.
- *Competitive relevance*: differentiator
- *Implementation*: `sentinel/domain/adoption.py`
- *Tests*: `tests_arch/test_adoption.py`
- *Docs*: `docs/DESIGN_PARTNER_RUNBOOK.md`
- *Recommended action*: None in code.
- *Acceptance criteria*: A partner can install in observe-only and see value before enforcing anything.

### Phase 31 — Product analytics on value, not vanity

**COMPLETE**

- *What exists*: A metrics model whose central type is three-valued: a value, or UNMEASURABLE with the reason, or NOT_COLLECTED. Covers discovery, shadow agents, enrolment coverage, privilege risk, binding coverage, substitutions refused, median approval wait and median time to containment.
- *What was checked*: The instruction was value-not-vanity, and the difference is enforced rather than intended. A Measurement may carry a value ONLY when MEASURED, refused at construction, because a dashboard would show the number and ignore the label. Three specific dishonest charts are refused: 0/0 rendered as 0 per cent -- the most common one, because it looks like a good result -- a mean over two samples, and agents-protected without the coverage ratio beside it, a number that rises with discovery coverage and so measures the sensor rather than the protection. Medians not means, because one approval that waited a weekend drags a mean into uselessness. 25 tests.
- *Security risk*: none, and by construction: `measure` takes only counts and durations. A signature test asserts no string parameter can enter it, because these aggregate across tenants and one resource identifier would make a chart a cross-tenant disclosure in an output nobody thinks of as an output.
- *Competitive relevance*: none - internal
- *Implementation*: `sentinel/domain/value_metrics.py`, `sentinel/domain/adoption.py`
- *Tests*: `tests_arch/test_value_metrics.py`, `tests_arch/test_adoption.py`
- *Docs*: `docs/DELIVERY_STATUS.md`
- *Recommended action*: None. Wiring it to live counters is a deployment activity; the model and its honesty constraints are done.
- *Acceptance criteria*: Value metrics aggregated with no sensitive payload leaving the tenant, and no metric that can only report good news. Met.

### Phase 32 — Cost engineering with a measured unit-economics dashboard

**PARTIAL**

- *What exists*: Real cost functions for the transparency sink, per-module cost estimates in the Terraform, and now scripts/ingest_aws_costs.py -- a Cost Explorer ingester that signs with this repository's own SigV4 primitives, filters on the Project tag, groups by service and derives cost per million events and per million decisions.
- *What was checked*: Written BEFORE the data exists, on purpose: closing MEASURED_AWS_UNIT_ECONOMICS should then be a matter of running something rather than building it. It reports UNVERIFIED today and exits non-zero, and the evidence artifact carries measured=false. A unit cost over zero volume is REFUSED, because a cost-per-event of infinity rendered as a large number would be quoted by somebody who did not know the denominator was zero. 17 tests.
- *Security risk*: It deliberately does NOT read `.env`, which is the opposite of the publisher's choice: a real run costs money and reads billing data, so the credential must come from the environment of the person invoking it rather than from a file in the working copy -- otherwise an exploratory session becomes a charged query against whichever account was last configured.
- *Competitive relevance*: none - internal, but gates pricing
- *Implementation*: `sentinel/infrastructure/s3_root_sink.py`, `scripts/ingest_aws_costs.py`, `deploy/terraform/aws/modules/budgets`
- *Tests*: `tests_arch/test_cost_ingestion.py`, `tests_arch/test_s3_root_sink.py`
- *Docs*: `docs/TRANSPARENCY_SINK.md`, `docs/AWS_PRODUCTION_ARCHITECTURE.md`
- *Recommended action*: Run it after applying the Terraform. PARTIAL until it returns PASS against an account with real resources, because the gate is about MEASUREMENT and no amount of code is one.
- *Acceptance criteria*: Cost per million events derived from an actual AWS bill. The collection procedure is met; the measurement is not, and cannot be from here.

### Phase 33 — Demonstrable end-to-end differentiated chain

**COMPLETE**

- *What exists*: scripts/demo_execution_trust.py runs the whole chain in one process against the REAL code paths: human -> coding agent -> infrastructure agent -> MCP server -> S3 tool, with a delegation chain evaluated hop by hop, an authorization committing to a parameter digest, an execution that passes the verified parameters into the tool, a passport in a Merkle log, and an independent JavaScript verifier.
- *What was checked*: 16 of the 18 questions ANSWERED from observations the run produced; 2 reported OUT OF SCOPE with the reason (14 needs a second agent process, 18 needs a real containment store). The substitution -- one parameter changed, everything else identical, a FRESH nonce so it is not merely a replay -- is refused before the side effect, and the demo asserts the tool was not invoked rather than trusting the exception. It exits non-zero if any question it was supposed to answer comes back empty.
- *Security risk*: none. The demo prints what it does NOT show on every run: tool, action and resource are caller declarations compared against the authorization; the transparency root is not published to S3 in this run; and the nonce ledger is in-process rather than the shared one a deployment needs.
- *Competitive relevance*: This IS the moat, and it is now demonstrable in one command rather than described.
- *Implementation*: `scripts/demo_execution_trust.py`
- *Tests*: `tests_arch/test_demo_execution_trust.py`, `tests_arch/test_end_to_end.py`
- *Docs*: `docs/EXECUTION_TRUST_ARCHITECTURE.md`, `docs/COMPETITIVE_GAP_MATRIX.md`
- *Recommended action*: None. Worth noting the demo crashed on its first run with a UnicodeEncodeError -- the Windows console is cp1252 and the output had box-drawing characters -- which is the worst failure a flagship demo can have and one no existing test would have caught. There is now a test that encodes the output as cp1252.
- *Acceptance criteria*: One command answers the eighteen questions, marks what it cannot answer, and fails if a substituted execution is permitted. Met.

### Phase 34 — External assurance readiness

**COMPLETE**

- *What exists*: Threat model, architecture documentation, asset inventory, scope, known limitations and a pentest package, plus internal red-teaming of auth, IDOR, SSRF, injection, deserialization, tenant isolation, MCP, A2A and evidence tampering.
- *What was checked*: PENTEST_PACKAGE.md plus adversarial suites for each named class. A proven token leak through urllib redirect handling was found and fixed during this work, so the internal red-teaming has produced real findings rather than a clean self-assessment.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/outbound.py`
- *Tests*: `tests_arch/test_security_bypass_detection.py`, `tests_arch/test_security_edge.py`, `tests_arch/test_security_outbound.py`, `tests_arch/test_sql_is_never_built_from_data.py`
- *Docs*: `docs/PENTEST_PACKAGE.md`, `docs/THREAT_MODEL.md`, `docs/SECURITY_ASSURANCE.md`
- *Recommended action*: Readiness is done. Engaging a firm is a business action.
- *Acceptance criteria*: A firm can start without asking for anything. Met. The test itself stays EXTERNALLY-UNVERIFIED and is recorded separately.

### Phase 35 — Customer validation infrastructure

**COMPLETE**

- *What exists*: Tenant provisioning, usage metering, onboarding, sample policies, support bundles, retention controls, export and offboarding.
- *What was checked*: orgs.py and adoption.py with tenant integration tests; retention sweep and SIEM export tested.
- *Competitive relevance*: table stakes
- *Implementation*: `sentinel/infrastructure/orgs.py`, `sentinel/domain/adoption.py`, `sentinel/domain/residency.py`
- *Tests*: `tests_arch/test_tenant_integrations.py`, `tests_arch/test_retention_sweep.py`, `tests_arch/test_siem_export.py`
- *Docs*: `docs/DESIGN_PARTNER_RUNBOOK.md`
- *Recommended action*: None. Code cannot create customers, which the prompt states outright.
- *Acceptance criteria*: A partner can be provisioned, metered, exported and offboarded.

### Phase 36 — GTM productization and SKU boundaries

**PARTIAL**

- *What exists*: Kubernetes and Helm deployment are real; customer-managed AWS is blocked behind Phase 15; SKU boundaries are documented.
- *What was checked*: Helm chart deployable. No SaaS or customer-VPC deployment exists because the Terraform does not exist. Pricing is deliberately unset.
- *Competitive relevance*: commercial
- *Implementation*: `deploy/helm/sentinel`
- *Tests*: `tests_arch/test_deployment_environment_is_canonical.py`
- *Docs*: `docs/EXECUTIVE_SUMMARY.md`, `docs/COMPETITIVE_GAP_MATRIX.md`
- *Recommended action*: Blocked on Phase 15. Keep pricing unset until Phase 32 measures cost.
- *Acceptance criteria*: Each SKU maps to shippable capability, priced from measured cost.

### Phase 37 — Final readiness matrix scored honestly 0-10

**COMPLETE**

- *What exists*: 26 dimensions, each with what is present and what is missing, generated from this file so a score and its justification cannot drift apart. Mean reported, not chosen.
- *What was checked*: Every score is authored beside its own gap text, and the generator REFUSES to write when any cited path is absent -- which caught eight bad citations on the first run. No score is inferred from a file existing, because the recurring failure in this repository was exactly that: a subsystem with tests, a ledger entry and an audit trail, and no caller. Two dimensions moved this pass for that reason and not because code was added: Integrations 6.5 -> 8.5 after I found I had recorded six existing SOAR connectors as absent from a grep that returned one file, and Discovery 6.0 -> 7.5 after wiring connectors that were already written.

NO DIMENSION SCORES 10, and `scored_ten` is asserted empty. A 10 would require objective external evidence and none exists for anything here. Customer validation is 0.0 -- not 'in progress', not 'early': zero, because there are no customers, and a discovery product with no user has learned nothing about what operators actually do.
- *Security risk*: none. The one risk a self-scored matrix carries is flattery, and the guards against it are structural: the eight external gates cannot be marked complete by any code path, `is_release_evidence` is false whenever the working tree is dirty, and the readiness figures quoted in SENTINEL_PRODUCT_READINESS.md are asserted to match release/gap_ledger.json by test_readiness_doc_matches_ledger.py -- written after I found THIS ENTRY claiming such a guard existed when it did not, while the document meanwhile read 28 COMPLETE against a generated 30 and scored Endpoint discovery at 0 long after it had moved to 7. Nobody forgets to update a figure that got worse, so the check is mechanical: status counts, GA blockers, the mean and all 26 dimension scores, plus a test that the parser found them rather than matching nothing and passing.
- *Competitive relevance*: none - internal
- *Implementation*: `scripts/build_gap_ledger.py`
- *Tests*: `tests_arch/test_delivery_status.py`, `tests_arch/test_ga_gates_cannot_be_faked.py`, `tests_arch/test_readiness_doc_matches_ledger.py`
- *Docs*: `docs/readiness/GAP_LEDGER.md`, `docs/SENTINEL_PRODUCT_READINESS.md`, `release/gap_ledger.json`
- *Recommended action*: None. It is regenerated by `python scripts/build_gap_ledger.py` and should be rerun whenever a phase changes, which is why it is a script rather than a document somebody edits.
- *Acceptance criteria*: Every score traceable to evidence in this ledger. A 10 requires objective evidence and none is claimed. Met.

## Readiness matrix

Scored 0-10, weakest first, because the weakest row is the one that decides what happens next.

**No dimension is scored 10.** A 10 requires objective external evidence and this repository has none for any dimension -- the eight `EXTERNALLY-UNVERIFIED` gates are precisely that absence. Two rows are scored **0**, deliberately: an omitted row reads as an oversight and a zero reads as a decision.

| Dimension | Score | Rests on | What would raise it |
|---|---:|---|---|
| Customer validation | **0** | No design partner and no customer has ever run this. Scored zero rather than omitted, because an absent row reads as an oversight and a zero reads as a decision -- and this is the row a buyer weighs above every engineering number in the table. | Real customers. Provisioning, metering, export and offboarding are all built; code cannot create the demand. |
| Performance | **5** | Reproducible harnesses for ingest, authorization, MCP proxy and persistence, with artifacts carrying commit provenance. | The numbers characterise a developer workstation, not the target architecture. Re-running needs Phase 15. The harness is not the gap. |
| GTM readiness | **5** | Kubernetes and Helm deployment are real; SKU boundaries documented; pricing deliberately unset. | Customer-managed AWS needs Phase 15. Pricing needs measured cost, which needs a real bill. |
| AWS implementation | **6** | All thirteen modules plus a stack module and three environment roots. `terraform validate` passes; a posture checker refuses a production environment whose posture contradicts its name, and 20 tests prove that checker can fail by mutating each control. One hand-built production resource -- the Object Lock bucket -- still has no Terraform representation, which is its own drift problem. | APPLYING IT. `validate` proves the configuration is coherent and nothing about whether it works, so this cannot go above 6 from inside this repository. Everything downstream -- soak, capacity, cross-region DR, measured unit economics -- is blocked behind an apply, which is an operator decision with a bill attached. |
| Endpoint discovery | **7** | A read-only sensor over an allowlist of agent configuration paths, run live on a real machine. Privacy is enforced by tests: planted personal files are not read, planted credentials are digested to 16 characters, and an AST check asserts the scanner opens nothing for writing. | Signing and remote attestation. The sensor is a script rather than a signed binary, which matters the moment it is distributed rather than run from a checkout -- and Windows paths need their own allowlist and review. |
| Discovery | **7.5** | Nine connectors: AWS IAM, GitHub, Kubernetes and PostgreSQL for the identities an agent can act as, plus Bedrock Agents, Entra, Vertex reasoning engines, OpenAI assistants and generic MCP for the control planes where agents are declared. All nine now WIRED through discovery_wiring.py and runnable via scripts/run_discovery.py, which was the actual gap: build_connectors had tests, was cited in this ledger and was enumerated by the state audit, and had no caller. A zero is interpretable now -- an unconfigured connector is absent, truncation is reported, an unparseable body is unreachable rather than empty, and the CLI exits non-zero when nothing is configured. | Eight of seventeen platforms still missing, and -- the reason this is 7.5 rather than higher -- not one of the five new connectors has authenticated against a real tenant. The scopes and request shapes come from published contracts. Scored on code that refuses honestly, never on code that has been proven to work. |
| Admin UX | **7.5** | Ten route modules, now including the approved-versus-executed diff over a durable receipt store, with 34 tests driving the real application and the disclosure boundary asserted rather than documented. | The remaining graph visualisations -- agent, exposure and A2A. Those are front-end work over data that already has an API, which is why this is 7.5 rather than higher: the platform half is done and the console half is not. |
| Reliability and DR | **7.5** | Automated backups, WAL archiving, PITR, and an automated restore drill that validates integrity. Measured RPO 12.77s in the recorded artifact. | Every drill so far ran inside ONE failure domain. A cross-region exercise is external and cannot be self-certified. |
| Compliance evidence | **8** | Mappings for SOC 2, ISO 27001, NIST CSF, NIST AI RMF, OWASP LLM Top 10 and MITRE ATLAS, with the distinction between supporting evidence and certification kept explicit. | Certification itself, which is NOT_APPLICABLE to a codebase and belongs to an auditor. |
| Detection science | **8.5** | Ensemble kept architecturally separate from authorization, staged rollout, benign false-positive corpus, and a test that soft detection cannot reach the authorization path. | Real-world precision and recall. Measured against a synthetic corpus only, which is an external gate. |
| Integrations | **8.5** | Six SOAR connectors -- ServiceNow, Jira, PagerDuty, Slack, Teams, generic webhook -- all through the hardened client, with per-destination injection escaping that gets the ampersand-first ordering right and neutralises broadcast mentions. Plus SIEM export with per-tenant credentials, OTLP and syslog. Scored 6.5 until an audit error was corrected: I had recorded the adapters as absent because a grep returned one file. | Case history, comments and ticket synchronisation. Those need a real instance to develop against, which is design-partner work rather than something to build speculatively. |
| Observability | **8.5** | OTel instrumentation, collector config, dashboards, alert rules and defined SLO targets. | SLOs are DEFINED and not MEASURED. Achievement requires the soak, and claiming it before then is the specific dishonesty the rules forbid. |
| Security engineering | **9** | A proven token leak through urllib redirect handling was found and fixed; 26 mutation guards each break a real guard and require a behavioural probe to notice; RLS with FORCE tested on both engines. | An independent penetration test. Nothing internal substitutes. |
| Release engineering | **9** | Artifacts bind to commit and tree digest, a missing artifact yields UNVERIFIED never PASS, historical evidence cannot satisfy the current gate, and packaging is allowlist-based with the BUILT artifact rescanned by a scanner proven able to fail. | Cosign image signing and a DAST stage, both of which need the Phase 15 environment. |
| Container and Kubernetes | **9** | Non-root, read-only filesystem, dropped capabilities, seccomp, network policies, PDB, HPA and probes; detonation isolation flags are a frozen set and `build_run_argv` is pure, so isolation is testable without a daemon. | A cluster exercise, which needs infrastructure. |
| AWS architecture | **9** | Documented target architecture with cost controls reasoned through -- ARM64, VPC endpoints over NAT, lifecycle policies, and a real cost function for the one component that runs. | Nothing. The architecture is not the gap; the implementation is. |
| External assurance readiness | **9** | Threat model, architecture docs, asset inventory, scope, known limitations and a pentest package, plus internal red-teaming that has produced real findings rather than a clean self-assessment. | Nothing internal. A firm can start without asking for anything. |
| Core architecture | **9.5** | Hexagonal layering enforced by fitness tests, not convention: dependency direction, an 800-line module cap, no mutable module-level state, no assert for runtime invariants. The cap fired twice during this work and forced two real splits rather than two deletions of comments. | Nothing in code. The remaining 0.5 is that no external reviewer has read it. |
| Authorization | **9.5** | Deterministic policy, no LLM in the decision path, and now an authorization bound to the execution it authorized: parameter digest recomputed immediately before the side effect, verified parameters passed into the tool, single use claimed by the verifier rather than the caller. All nine enumerated negative cases refused. | Default the enforcement switch on once call sites are migrated, and bind the wire-level MCP route -- a separate forwarding path that never touches ProtectedToolRunner. The parameter digest, the delegation chain and a syscall-trace comparison are all bound now, so what remains is adoption and one route rather than anything about authority. |
| MCP security | **9.5** | Registry, cryptographic server identity, manifest and schema fingerprint pinning, description-drift and poisoning detection, SSRF and egress control through the hardened client, and an adversarial suite that exercises the poisoning paths. | An external tester attacking it. The security model itself is complete. |
| A2A security | **9.5** | Agent cards, capability manifests, call graph, and detection of amplification, loops, card drift and cross-agent injection -- plus a DelegationPassport whose every hop is signed by its ISSUER, with monotonicity enforced hop by hop and the chain digest committed to by the execution authorization. | An external tester attacking it. The residual that existed -- hops asserted by the control plane rather than signed by each delegator -- is closed. |
| Evidence and provenance | **9.5** | Canonical-JSON passports with domain-separated digests, a hash chain to the parent, an RFC 6962 Merkle log with inclusion and consistency proofs, and a published spec with TWO independent verifiers agreeing on 16 conformance vectors. The second implementation found a real canonicalisation bug. | Add the Phase 3 parameter digests to the schema as v2. Held back deliberately: publishing a field before its shape settles means breaking it. |
| Transparency | **9.5** | A real root is published to S3 Object Lock in COMPLIANCE mode and AWS confirmed the mode. Deletion was ATTEMPTED and refused. This is the only claim in the repository tested against a live adversarial action rather than a mock. | The daily publisher is registered Interactive-only on a workstation, so it does not run while logged out. That is a deployment weakness, and it is what the missing 0.5 is. |
| Testing | **9.5** | 3300+ tests, mutation-tested guards, and a documented habit of pairing every refusal assertion with the positive case. Four of my own checks in this session were vacuous and were caught by control assertions rather than by review. | Coverage of the wire-level MCP route under binding, which does not exist yet to test. |
| Supply-chain security | **9.5** | CycloneDX SBOM, license and dependency scanning, secret scanning over history AND over the built artifact, dependency locking, commit-plus-tree binding on every artifact, and keyless image signing that verifies what it signed with BOTH the certificate identity and the OIDC issuer pinned. | Turning the signing job on, which needs a registry chosen. The mechanism and its misconfiguration tests are done; nothing is signed until a repository opts in, because signing requires pushing. |
| Multi-tenancy | **9.5** | PostgreSQL RLS with FORCE plus application checks plus adversarial tests for cross-tenant read, write, IDOR, forged header, cache poisoning and evidence leakage -- run against both engines, enforced by a fitness rule so an isolation test cannot silently cover only SQLite. | An independent tester attempting the same attacks against a running deployment. The controls and their tests are complete; what is absent is anyone outside this repository having tried to break them. |

Unweighted mean **8.1/10** across 26 dimensions.

The mean is close to meaningless and is printed only so nobody has to compute it and then quote it without the spread. The distribution is the finding: the engineering dimensions cluster at 8.5-9.5 while AWS implementation sits at 2 and two rows sit at 0. This is not a product that is uniformly nearly-ready -- it is a well-built core with a specific, nameable hole where its deployment and its customers should be.

## External gates

These are `EXTERNALLY-UNVERIFIED`, which is **not** a synonym for incomplete. The code and the collection procedure exist; the evidence can only come from outside this repository. None will ever be marked from code.

| Gate | Why it is open | What is already prepared |
|---|---|---|
| `INDEPENDENT_PENTEST` | No third party has tested this build. | Scope, threat model, test accounts and known limitations are prepared. |
| `PRODUCTION_SOAK` | No sustained production traffic has ever run against this system. | Soak runbook, the soak driver AND an SLO evaluator that computes MET/VIOLATED/UNMEASURABLE and exits non-zero until targets are genuinely met. The clock has not started. |
| `INDEPENDENT_FAILURE_DOMAIN_DR` | Every restore drill so far ran inside one failure domain. | In-domain drills record a measured RPO of 12.77s, and the CROSS-REGION drill now exists: preconditions, refusals and evidence format complete, awaiting credentials and a destination instance. |
| `DESIGN_PARTNER_VALIDATION` | No design partner has used this. | Observe-only onboarding and the partner runbook are prepared. |
| `PRODUCTION_CUSTOMER_VALIDATION` | No customer runs this in production. | Provisioning, metering, export and offboarding are prepared. |
| `MEASURED_AWS_UNIT_ECONOMICS` | No AWS bill exists beyond a few cents of S3, so every figure is an estimate and labelled one. | A Cost Explorer ingester is written and exits non-zero until it runs against a real account, so closing this is running something rather than building it. |
| `REAL_WORLD_DETECTION_METRICS` | Precision and recall are measured against a synthetic corpus only, and the corpus is now MARKED as such in the artifact rather than only in a docstring -- a docstring does not travel with a number into a slide. Wiring it surfaced that the benign-action corpus holds 60 examples, below the 100 needed before a rate describes the detector rather than the corpus: the observation is still a real finding, but the RATE is not extrapolable. | Benign corpus, promotion gate, AND corpus-provenance tracking: sentinel/domain/detection_metrics.py carries where the labelled examples came from as a FIELD and derives `real_world` from it, so no code path can report a synthetic precision as production behaviour. |
| `REFERENCE_CUSTOMERS` | There are none. | Nothing in code affects this, and nothing in code ever will. |

## Naming note on the prompt's final deliverables

The prompt names sixteen documents. Twelve do not exist under those exact filenames, but the content of most does exist under this repository's own names -- `docs/MCP_GATEWAY.md` for `MCP_SECURITY.md`, `docs/A2A_GATEWAY.md` for `A2A_SECURITY.md`, `docs/PENTEST_PACKAGE.md` for `PENTEST_READINESS.md`, `docs/RELEASE_GATES.md` for `RELEASE_CHECKLIST.md`, and so on. Creating sixteen renamed duplicates would satisfy a filename check and make the documentation worse, so it has not been done.

Three are genuinely absent rather than renamed: `EXECUTION_TRUST_ARCHITECTURE.md` and `EXECUTION_PASSPORT_SPEC.md` both describe Phase 3 and Phase 13 work that does not exist yet, and `AWS_PRODUCTION_ARCHITECTURE.md` would describe Terraform that has not been written. Writing any of the three now would produce exactly the `DOCUMENTATION-ONLY` status this ledger is designed to expose.

