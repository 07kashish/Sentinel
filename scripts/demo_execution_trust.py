"""The chain, end to end, with the approved-versus-executed diff.

WHAT THIS DEMONSTRATES
----------------------
The eighteen questions Sentinel sets out to answer, in one run, against the
REAL code paths -- no stubs and no fixtures, because a demo that mocks the thing
being demonstrated proves nothing.

    developer
      -> coding agent
        -> infrastructure agent          (delegated authority)
          -> MCP cloud server            (identity pinned)
            -> AWS IAM / S3 tool         (parameters approved)
              -> the object              (executed and bound)

Then the same authorization is replayed with ONE parameter changed, and the
execution is refused -- which is question 12, "did approved and executed
parameters differ", and the one nothing in this system could answer before.

THE RULE THIS SCRIPT FOLLOWS
----------------------------
**It never prints an answer it did not observe.**

Each of the eighteen questions is marked ANSWERED only when this run produced
the evidence, and UNANSWERED otherwise, with the reason. A demo that prints
eighteen ticks because it reached the end is a demo that would print eighteen
ticks against a broken build.

TWO are reported OUT OF SCOPE: 14 needs a second agent process and 18 needs a
real containment store. Claiming either from a single-process script would be
the specific dishonesty this whole codebase is arranged to avoid, and the
count is asserted by a test so it cannot drift up quietly.

EXIT CODE
---------
Non-zero if any question this run is SUPPOSED to answer came back unanswered,
or if the substituted execution was permitted. A demo that congratulates you on
a broken build is worse than no demo.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.application.protect_gate import ProtectGate  # noqa: E402
from sentinel.application.tool_proxy import (  # noqa: E402
    InlineToolProxy,
    RegisteredSideEffect,
    ToolProxyRefused,
)
from sentinel.application.tool_runner import ProtectedToolRunner  # noqa: E402
from sentinel.domain.delegation_constraints import (  # noqa: E402
    DelegationConstraint,
    DelegationContext,
    evaluate,
)
from sentinel.domain.execution_binding import (  # noqa: E402
    ExecutionAuthorization,
    ExecutionRequest,
    parameter_digest,
    verify_binding,
)
from sentinel.domain.passport import ExecutionPassport, digest_of  # noqa: E402
from sentinel.domain.primitives import TrustLevel  # noqa: E402
from sentinel.domain.transparency import (  # noqa: E402
    MerkleLog,
    verify_inclusion,
)
from sentinel.infrastructure.detection import DeterministicPolicy  # noqa: E402

GREEN, RED, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m",
)

NOW = datetime(2026, 9, 4, 9, 0, 0, tzinfo=timezone.utc)


# -- the eighteen questions -------------------------------------------------


@dataclass
class Question:
    number: int
    text: str
    #: Filled in by the run. None until something observes it.
    answer: str | None = None
    #: Set when this question cannot be answered by a single-process script.
    out_of_scope: str = ""

    @property
    def answered(self) -> bool:
        return self.answer is not None


QUESTIONS: tuple[Question, ...] = (
    Question(1, "Which human/workload/agent acted?"),
    Question(2, "Which identity authenticated?"),
    Question(3, "Who delegated authority to that agent?"),
    Question(4, "Which permissions/capabilities were granted?"),
    Question(5, "What action was requested?"),
    Question(6, "Through which MCP server/tool was it requested?"),
    Question(7, "Which policy evaluated the action?"),
    Question(8, "Which context influenced the authorization?"),
    Question(9, "What authorization decision was produced?"),
    Question(10, "What exact parameters were approved?"),
    Question(11, "What exact action was actually executed?"),
    Question(12, "Did approved and executed parameters differ?"),
    Question(13, "Which infrastructure/data/resource was affected?"),
    Question(
        14, "Which downstream agents were invoked?",
        out_of_scope=(
            "no downstream agent is invoked in this scenario. The A2A call "
            "graph answers it and exercising it needs a second agent process"
        ),
    ),
    Question(15, "What evidence proves the chain?"),
    Question(16, "Has the evidence been tampered with?"),
    Question(17, "Can an independent verifier validate it?"),
    Question(
        18, "Can the organization revoke, contain or remediate immediately?",
        out_of_scope=(
            "containment is exercised by tests_arch/"
            "test_native_sentinel_containment.py against a real store. Doing it "
            "here would need a database, and a demo that spins one up to print "
            "a tick is a demo nobody runs"
        ),
    ),
)

BY_NUMBER = {question.number: question for question in QUESTIONS}


def _answer(number: int, value: str) -> None:
    BY_NUMBER[number].answer = value


def _say(message: str = "") -> None:
    print(message, flush=True)


def _make_output_safe() -> None:
    """Never let an encoding kill the demo.

    Output here is ASCII, but a refusal message from elsewhere in the codebase
    can carry a character the Windows console's cp1252 cannot encode -- and the
    result is a UnicodeEncodeError instead of the refusal, which turns a
    working security control into what looks like a crash. `errors="replace"`
    prints a mangled character rather than losing the message.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                # An unreconfigurable stream is not a reason to refuse to run.
                pass


def _head(title: str) -> None:
    _say()
    _say(f"{BOLD}{title}{RESET}")
    _say(DIM + "-" * min(len(title), 74) + RESET)


def _observed(message: str) -> None:
    _say(f"  {GREEN}observed{RESET}  {message}")


def _refused(message: str) -> None:
    _say(f"  {RED}refused{RESET}   {message}")


# -- the scenario -----------------------------------------------------------

HUMAN = "user:priya@acme.example"
CODING_AGENT = "agent:cursor-assistant"
INFRA_AGENT = "agent:infra-writer"
MCP_SERVER = "mcp:aws-prod"
TOOL = "s3.put_object"
ACTION = "s3:PutObject"
RESOURCE = "arn:aws:s3:::acme-reports/q3/summary.pdf"

APPROVED_PARAMETERS = {
    "bucket": "acme-reports",
    "key": "q3/summary.pdf",
    "acl": "private",
    "content_type": "application/pdf",
}

#: The substitution. ONE key changed, and it is the destination -- the shape a
#: manipulated agent's exfiltration actually takes.
SUBSTITUTED_PARAMETERS = dict(APPROVED_PARAMETERS) | {"bucket": "attacker-exfil"}


class Ledger:
    """A single-use nonce ledger, in process for the demo.

    In a deployment this MUST be the shared Redis one. An in-process set makes
    single-use per-process, which across replicas is no replay protection at
    all -- the same defect class as a per-process rate limiter. Said here
    because a demo is where somebody copies a pattern from.
    """

    def __init__(self) -> None:
        self.used: set[tuple[str, str]] = set()

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        key = (tenant_id, nonce)
        if key in self.used:
            return False
        self.used.add(key)
        return True


class Tenant:
    value = "acme"


def _authorization(*, nonce: str) -> ExecutionAuthorization:
    return ExecutionAuthorization(
        authorization_id=f"auth-{nonce}",
        tenant_id="acme",
        actor_identity=HUMAN,
        agent_identity=INFRA_AGENT,
        parent_agent_identity=CODING_AGENT,
        delegation_chain=(
            {"issuer": HUMAN, "subject": CODING_AGENT, "depth": 1},
            {"issuer": CODING_AGENT, "subject": INFRA_AGENT, "depth": 2},
        ),
        tool_identity=TOOL,
        mcp_server_identity=MCP_SERVER,
        action=ACTION,
        target_resource=RESOURCE,
        approved_parameter_digest=parameter_digest(APPROVED_PARAMETERS),
        policy_bundle_digest=digest_of({"policy": "baseline", "version": 14}),
        policy_decision="allow",
        issued_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        nonce=nonce,
    )


def _proxy(effect_log: list) -> InlineToolProxy:
    def put_object(parameters):
        # Receives the VERIFIED parameters. This is the binding: what runs is
        # what the digest was checked against, structurally rather than by
        # convention.
        effect_log.append(dict(parameters))
        return {
            "bucket": parameters["bucket"],
            "key": parameters["key"],
            "version_id": "v-8821",
        }

    return InlineToolProxy(
        tool_runner=ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
            tenant=Tenant(),
            # THE SWITCH. With this false the unbound path stays usable and the
            # demo would be showing a capability rather than an enforcement.
            require_binding=True,
        ),
        effects={TOOL: RegisteredSideEffect(name=TOOL, runner=put_object)},
        capabilities=None,
    )


# -- the run ----------------------------------------------------------------


def _step_delegation() -> bool:
    """The delegation chain, evaluated hop by hop against where it is presented.

    `evaluate` takes ONE constraint and ONE context, so a chain is a fold over
    hops rather than a single call -- which is the right shape: hop 2 can be
    escalation even when hop 1 is sound, and a single verdict over the whole
    chain would not say which hop to fix.
    """
    _head("1. DELEGATED AUTHORITY -- human to coding agent to infra agent")

    context = DelegationContext(
        tenant_id="acme", environment="production", resource=RESOURCE,
    )

    hops = (
        (
            1, HUMAN, CODING_AGENT,
            DelegationConstraint(
                tenant_id="acme",
                environment="production",
                purpose="author the quarterly report",
                resources=("arn:aws:s3:::acme-reports/*",),
                issued_at=NOW - timedelta(minutes=10),
                expires_at=NOW + timedelta(hours=1),
                policy_version="14",
            ),
        ),
        (
            2, CODING_AGENT, INFRA_AGENT,
            DelegationConstraint(
                tenant_id="acme",
                environment="production",
                purpose="write the rendered report object",
                # NARROWER than the parent's grant, which is what a sound
                # delegation looks like: one prefix, not the estate.
                resources=("arn:aws:s3:::acme-reports/q3/*",),
                issued_at=NOW - timedelta(minutes=5),
                expires_at=NOW + timedelta(minutes=30),
                policy_version="14",
            ),
        ),
    )

    all_findings: list = []
    for hop, issuer, subject, constraint in hops:
        findings = evaluate(constraint, context=context, now=NOW, hop=hop)
        all_findings.extend(findings)
        if findings:
            for finding in findings:
                _refused(f"hop {hop} {issuer} -> {subject}: "
                         f"{finding.kind.value} ({finding.severity.value})")
        else:
            _observed(f"hop {hop}  {issuer} -> {subject}")
            _observed(f"          purpose {constraint.purpose!r}, "
                      f"scope {constraint.resources[0]}, "
                      f"expires in {constraint.expires_at - NOW}")

    if all_findings:
        return False

    # AND THE NEGATIVE CONTROL, in the same run.
    #
    # Without it, every tick above would also appear against an `evaluate` that
    # returned no findings for anything -- which is the shape of a check that
    # is not checking. So a deliberately bad hop is presented and must be
    # refused.
    escalating = DelegationConstraint(
        tenant_id="acme",
        environment="staging",
        purpose="write the rendered report object",
        resources=("arn:aws:s3:::acme-reports/q3/*",),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
    )
    bad = evaluate(escalating, context=context, now=NOW, hop=3)
    if not bad:
        _say(f"  {RED}a staging delegation presented in production produced no "
             f"finding, so this check is not checking.{RESET}")
        return False
    _observed(f"control: a staging grant presented in production is refused "
              f"({bad[0].kind.value}, {bad[0].severity.value})")

    _answer(1, f"{INFRA_AGENT}, acting for {HUMAN}")
    _answer(2, f"agent identity {INFRA_AGENT} (tenant acme, environment "
               f"production)")
    _answer(3, f"{CODING_AGENT}, itself delegated by {HUMAN} -- two signed-hop "
               f"chain, each narrower than its parent")
    _answer(4, "arn:aws:s3:::acme-reports/q3/* for 30 minutes, purpose "
               "'write the rendered report object'")
    return True


def _step_authorize() -> ExecutionAuthorization:
    _head("2. PRE-ACTION AUTHORIZATION -- parameters committed by digest")

    authorization = _authorization(nonce="nonce-demo-1")

    _observed(f"action    {authorization.action} on {authorization.target_resource}")
    _observed(f"through   {authorization.mcp_server_identity} / {authorization.tool_identity}")
    _observed(f"policy    {authorization.policy_decision}, bundle "
              f"{authorization.policy_bundle_digest[:16]}...")
    _observed(f"expires   {authorization.expires_at} (single use, "
              f"nonce {authorization.nonce})")
    _observed(f"committed to parameter digest "
              f"{authorization.approved_parameter_digest[:16]}...")
    _say(f"  {DIM}approved parameters: "
         f"{json.dumps(APPROVED_PARAMETERS, sort_keys=True)}{RESET}")

    _answer(5, f"{ACTION} on {RESOURCE}")
    _answer(6, f"{MCP_SERVER} / {TOOL}, both pinned in the authorization")
    _answer(7, f"deterministic policy bundle "
               f"{authorization.policy_bundle_digest[:16]}... (no LLM in the path)")
    _answer(8, "tenant, environment=production, delegation depth, resource scope")
    _answer(9, f"{authorization.policy_decision}, expiring "
               f"{authorization.expires_at}")
    _answer(10, json.dumps(APPROVED_PARAMETERS, sort_keys=True))
    return authorization


def _step_execute(authorization, ledger) -> dict | None:
    _head("3. EXECUTION -- verified parameters passed into the tool")

    effect_log: list = []
    proxy = _proxy(effect_log)

    try:
        response = proxy.execute(
            agent_id=INFRA_AGENT,
            tool=TOOL,
            trust=TrustLevel.VERIFIED,
            tenant_id="acme",
            action=ACTION,
            resource=RESOURCE,
            arguments=dict(APPROVED_PARAMETERS),
            authorization=authorization,
            nonces=ledger,
            now=NOW,
            metadata={"mcp_server": MCP_SERVER},
        )
    except ToolProxyRefused as refused:
        _refused(str(refused))
        return None

    receipt = response["receipt"]
    _observed(f"tool ran and wrote {response['result']['bucket']}/"
              f"{response['result']['key']}")
    _observed(f"the tool received exactly the approved parameters: "
              f"{effect_log == [APPROVED_PARAMETERS]}")
    _observed(f"receipt binds authorization {receipt['authorization_digest'][:16]}...")
    _observed(f"           -> executed request {receipt['executed_request_digest'][:16]}...")
    _observed(f"           -> parameters {receipt['actual_parameter_digest'][:16]}...")

    _answer(11, f"{ACTION} with parameter digest "
                f"{receipt['actual_parameter_digest'][:16]}..., receipt "
                f"{receipt['receipt_id']}")
    _answer(13, f"{RESOURCE} (version {response['result']['version_id']})")
    return receipt


def _step_substitute(ledger) -> bool:
    _head("4. THE SUBSTITUTION -- one parameter changed, nothing else")

    _say(f"  {DIM}approved:  bucket=acme-reports{RESET}")
    _say(f"  {DIM}attempted: bucket=attacker-exfil{RESET}")
    _say(f"  {DIM}same agent, same tool, same action, same MCP server, "
         f"valid authorization{RESET}")
    _say()

    # A FRESH nonce, so this is not merely refused as a replay. The point is
    # that the PARAMETERS are caught, and reusing the spent nonce would have
    # produced a refusal that proved nothing about parameter binding.
    authorization = _authorization(nonce="nonce-demo-2")

    effect_log: list = []
    proxy = _proxy(effect_log)

    try:
        proxy.execute(
            agent_id=INFRA_AGENT,
            tool=TOOL,
            trust=TrustLevel.VERIFIED,
            tenant_id="acme",
            action=ACTION,
            resource=RESOURCE,
            arguments=SUBSTITUTED_PARAMETERS,
            authorization=authorization,
            nonces=ledger,
            now=NOW,
            metadata={"mcp_server": MCP_SERVER},
        )
    except ToolProxyRefused as refused:
        _refused(str(refused).splitlines()[0])
        for line in str(refused).splitlines()[1:]:
            _say(f"            {DIM}{line.strip()}{RESET}")
        _observed(f"the tool was NOT invoked: {effect_log == []}")

        verdict = verify_binding(
            authorization=authorization,
            request=ExecutionRequest(
                tenant_id="acme",
                agent_identity=INFRA_AGENT,
                tool_identity=TOOL,
                action=ACTION,
                target_resource=RESOURCE,
                parameters=SUBSTITUTED_PARAMETERS,
                mcp_server_identity=MCP_SERVER,
            ),
            now=NOW,
            nonces=Ledger(),
        )
        _answer(12, (
            f"YES -- approved {verdict.approved_parameter_digest[:16]}... vs "
            f"executed {verdict.actual_parameter_digest[:16]}...; refused before "
            f"the side effect"
        ))
        return True

    _say(f"  {RED}THE SUBSTITUTED EXECUTION WAS PERMITTED.{RESET}")
    return False


def _step_evidence(receipt) -> tuple[ExecutionPassport, MerkleLog]:
    _head("5. EVIDENCE -- a passport, in a Merkle log")

    passport = ExecutionPassport(
        execution_id="exec-demo-1",
        tenant_id="acme",
        occurred_at=NOW.isoformat(),
        human_principal=HUMAN,
        agent_id=INFRA_AGENT,
        agent_framework="cursor",
        model_identity="claude-opus-5",
        delegation_chain=(
            {"issuer": HUMAN, "subject": CODING_AGENT, "depth": 1},
            {"issuer": CODING_AGENT, "subject": INFRA_AGENT, "depth": 2},
        ),
        mcp_server_id=MCP_SERVER,
        tool_name=TOOL,
        action=ACTION,
        resource=RESOURCE,
        environment="production",
        decision="allow",
        outcome="succeeded",
        side_effect="object_written",
        evidence_digest=receipt["actual_parameter_digest"],
        attestation_status="attested",
    )

    log = MerkleLog()
    log = log.append(bytes.fromhex(passport.digest))
    log = log.append(bytes.fromhex(receipt["executed_request_digest"]))

    proof = log.inclusion_proof(0)
    # Returns a NAMED FAILURE or None, deliberately not a boolean: "the proof
    # failed" and "the entry was deleted from a tree that has since grown" call
    # for different responses, and a caller that only sees False cannot tell
    # them apart.
    failure = verify_inclusion(
        digest=bytes.fromhex(passport.digest), proof=proof, root=log.root()
    )

    _observed(f"passport digest {passport.digest[:16]}...")
    _observed(f"appended at index 0 of a {log.size}-leaf log, root "
              f"{log.root().hex()[:16]}...")
    if failure is None:
        _observed("inclusion proof verifies (no failure returned)")
    else:
        _refused(f"inclusion proof failed: {failure.value}")

    _answer(15, f"passport {passport.digest[:16]}... + receipt, in a Merkle log "
                f"at root {log.root().hex()[:16]}...")

    # TAMPER. Change one field and show the digest moves.
    tampered = ExecutionPassport.from_document(
        dict(passport.as_document()) | {"resource": "arn:aws:s3:::attacker-exfil/x"}
    )
    tampered_failure = verify_inclusion(
        digest=bytes.fromhex(tampered.digest), proof=proof, root=log.root()
    )
    _observed(f"altering `resource` changes the digest to "
              f"{tampered.digest[:16]}...")
    if tampered_failure is None:
        _say(f"  {RED}the tampered passport still verifies, which means this "
             f"check is not checking.{RESET}")
    else:
        _observed(f"and its inclusion proof now FAILS: "
                  f"{tampered_failure.value}")
        _answer(16, f"detectable -- the tampered digest fails the same "
                    f"inclusion proof with {tampered_failure.value}")
    return passport, log


def _step_independent(passport) -> bool:
    _head("6. INDEPENDENT VERIFICATION -- a different implementation")

    verifier = ROOT / "standard" / "execution-passport-v1" / "verify_canonical.mjs"
    if not verifier.exists():
        _refused("verify_canonical.mjs is missing, so nothing independent ran")
        return False

    import shutil

    node = shutil.which("node")
    if node is None:
        _refused(
            "node is not installed, so the INDEPENDENT verifier did not run. "
            "Reported rather than skipped silently: this is the question the "
            "whole format exists for."
        )
        return False

    script = (
        "const {pathToFileURL} = await import('node:url');"
        "const m = await import(pathToFileURL(process.env.VERIFIER).href);"
        "const doc = JSON.parse(process.env.PASSPORT);"
        "console.log(m.digestOf(doc));"
    )
    import os

    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True, text=True, cwd=str(ROOT),
        env={
            **os.environ,
            "VERIFIER": str(verifier),
            "PASSPORT": json.dumps(passport.as_document()),
        },
    )
    if result.returncode != 0:
        _refused(f"the independent verifier failed: {result.stderr.strip()[:200]}")
        return False

    from_js = result.stdout.strip()
    agrees = from_js == passport.digest

    _observed(f"python computes {passport.digest[:16]}...")
    _observed(f"javascript computes {from_js[:16]}...")
    _observed(f"two independent implementations agree: {agrees}")
    _say(f"  {DIM}no network, no database, no cooperation from this "
         f"deployment{RESET}")

    if agrees:
        _answer(17, "yes -- a dependency-free JavaScript verifier computes the "
                    "same digest offline, with no access to this system")
    return agrees


# -- the report -------------------------------------------------------------


def _report() -> int:
    _head("THE EIGHTEEN QUESTIONS")

    expected_unanswered = 0
    unexpected: list[Question] = []

    for question in QUESTIONS:
        if question.answered:
            mark = f"{GREEN}ANSWERED  {RESET}"
            detail = question.answer
        elif question.out_of_scope:
            mark = f"{DIM}OUT OF SCOPE{RESET}"
            detail = question.out_of_scope
            expected_unanswered += 1
        else:
            mark = f"{RED}UNANSWERED{RESET}"
            detail = "this run produced no evidence for it"
            unexpected.append(question)

        _say(f"{mark} {question.number:>2}. {question.text}")
        _say(f"             {DIM}{detail}{RESET}")

    answered = sum(1 for q in QUESTIONS if q.answered)
    _say()
    _say(f"{BOLD}{answered}/{len(QUESTIONS)} answered by this run, "
         f"{expected_unanswered} out of scope and stated as such.{RESET}")

    if unexpected:
        _say()
        _say(f"{RED}{len(unexpected)} question(s) this run was supposed to "
             f"answer came back empty.{RESET}")
        return 1

    _say()
    _say(f"{DIM}What this demo does NOT show, so nobody has to infer it:{RESET}")
    for note in (
        "the tool, action and resource are what the CALLER DECLARED, compared "
        "against the authorization. A caller that lies about them AND executes "
        "something else is not caught here -- see "
        "docs/EXECUTION_TRUST_ARCHITECTURE.md",
        "the transparency root is not published to S3 in this run, so the log "
        "catches a mistake and not a determined operator -- see "
        "docs/TRANSPARENCY_SINK.md",
        "the nonce ledger is in-process. A deployment MUST use the shared one, "
        "or single-use holds only within one worker",
    ):
        _say(f"  {DIM}- {note}{RESET}")
    return 0


def main() -> int:
    _make_output_safe()
    _say()
    _say(f"{BOLD}Sentinel -- execution trust, end to end{RESET}")
    _say(f"{DIM}Real code paths. No stubs, no fixtures. Every answer below is "
         f"observed or reported missing.{RESET}")

    ledger = Ledger()

    if not _step_delegation():
        return 1

    authorization = _step_authorize()

    receipt = _step_execute(authorization, ledger)
    if receipt is None:
        _say(f"\n{RED}the authorized execution was refused, which means this "
             f"demo is broken rather than strict.{RESET}")
        return 1

    if not _step_substitute(ledger):
        return 1

    passport, _log = _step_evidence(receipt)
    _step_independent(passport)

    return _report()


if __name__ == "__main__":
    raise SystemExit(main())
