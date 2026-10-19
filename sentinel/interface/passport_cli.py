"""`passport-inspect` and `passport-verify`: the operator half of Phase 5.

WHY VERIFY IS A COMMAND AND NOT AN ENDPOINT
---------------------------------------------
An endpoint that verifies a passport is a service somebody has to trust to be
telling the truth about it, which is the trust the passport exists to remove. A
command reads two files -- a signed passport and a public key -- and needs no
running Sentinel at all. The same code path an external auditor would run.

`passport-create` is deliberately ABSENT. A passport is written by the execution
path, from what actually happened, at the moment it happened. A command that
minted one from arguments would produce a signed document asserting facts nobody
observed -- which is indistinguishable from evidence and is not evidence. If a
caller needs to construct one, they build an `ExecutionPassport` in code where
the fields come from the execution, not from a shell prompt.

EXIT CODES ARE THE ANSWER
-------------------------
`verify` exits non-zero on any defect, so a script that pipes a directory of
passports through it does not have to parse prose to find the bad one.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence, TextIO

from sentinel.domain.passport import ExecutionPassport, verify_structure

__all__ = ["passport_command"]


def _load_public_key(path: Path) -> Any:
    """Read a PEM public key. PEM, because that is what a counterparty sends.

    A raw 32-byte Ed25519 key is smaller and is what nobody has. An auditor
    handed a key by a customer has a PEM file.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    return load_pem_public_key(path.read_bytes())


def _render(findings: Sequence[Any], stream: TextIO) -> None:
    for finding in findings:
        stream.write(f"  {finding.defect.value}\n")
        stream.write(f"    {finding.detail}\n")
        stream.write(f"    why it matters: {finding.defect.explanation}\n")


def passport_command(
    command: str, rest: Sequence[str], *, stream: TextIO
) -> int:
    """Dispatch one passport verb. Returns a process exit code."""
    if command == "passport-inspect":
        return _inspect(rest, stream=stream)
    if command == "passport-verify":
        return _verify(rest, stream=stream)
    stream.write(f"unknown passport command {command!r}\n")
    return 64  # EX_USAGE


def _inspect(rest: Sequence[str], *, stream: TextIO) -> int:
    """Show what a passport SAYS, and check everything that needs no key.

    Separate from `verify` because they answer different questions. Inspect is
    "what does this claim, and is it internally coherent"; verify adds "and was
    it signed by the key you hold". A reader with no key can still learn that a
    delegation chain does not connect.
    """
    if not rest:
        stream.write("usage: passport-inspect <passport.json>\n")
        return 64

    payload = json.loads(Path(rest[0]).read_text(encoding="utf-8"))
    document = payload.get("passport", payload)
    passport = ExecutionPassport.from_document(document)

    stream.write(f"execution   {passport.execution_id}\n")
    stream.write(f"tenant      {passport.tenant_id}\n")
    stream.write(f"at          {passport.occurred_at}\n")
    stream.write(f"principal   {passport.human_principal or '(none recorded)'}\n")
    stream.write(f"agent       {passport.agent_id} {passport.agent_version}\n")
    stream.write(f"action      {passport.action}\n")
    stream.write(f"resource    {passport.resource}\n")
    stream.write(f"decision    {passport.decision}  risk {passport.risk_score}\n")
    stream.write(f"outcome     {passport.outcome or '(not recorded)'}\n")
    stream.write(f"attestation {passport.attestation_status}\n")
    stream.write(f"digest      {passport.digest}\n")
    if passport.previous_passport_digest:
        stream.write(f"follows     {passport.previous_passport_digest}\n")

    findings = verify_structure(passport, document=document)
    if findings:
        stream.write(f"\n{len(findings)} structural defect(s):\n")
        _render(findings, stream)
        return 1

    stream.write(
        "\nstructurally sound. NOT a signature check: run passport-verify with "
        "the signer's public key to learn whether this document is authentic.\n"
    )
    return 0


def _verify(rest: Sequence[str], *, stream: TextIO) -> int:
    """Signature, key window and structure. The full check, offline."""
    if len(rest) < 2:
        stream.write("usage: passport-verify <passport.json> <public-key.pem>\n")
        return 64

    from sentinel.infrastructure.passport_signing import SignedPassport, VerifyingKey
    from sentinel.infrastructure.passport_signing import verify as verify_signed

    payload = json.loads(Path(rest[0]).read_text(encoding="utf-8"))
    signed = SignedPassport.from_dict(payload)
    if not signed.signature:
        stream.write(
            "this document carries no signature. passport-inspect will still "
            "report its structure; there is nothing here to verify.\n"
        )
        return 1

    public = _load_public_key(Path(rest[1]))
    # The key id comes from the DOCUMENT, and the window from the caller's key
    # material. A verifier who has been handed a key has been told which key it
    # is; taking the id from the passport would let a forged passport nominate
    # the key that verifies it.
    key = VerifyingKey(key_id=signed.key_id, public_key=public)

    findings = verify_signed(signed, key=key)
    if findings:
        stream.write(f"REFUSED — {len(findings)} defect(s):\n")
        _render(findings, stream)
        return 1

    passport = ExecutionPassport.from_document(signed.document)
    stream.write("VERIFIED\n")
    stream.write(f"  execution {passport.execution_id}\n")
    stream.write(f"  digest    {passport.digest}\n")
    stream.write(f"  signed by {signed.key_id} at {signed.signed_at}\n")
    if signed.signed_at:
        try:
            datetime.fromisoformat(signed.signed_at)
        except ValueError:  # pragma: no cover - verify already reported this
            pass
    stream.write(
        "\nThis says the document was signed by the key supplied and has not "
        "changed since. It does NOT say the signer was authorised, which is a "
        "question about key distribution, not about this file.\n"
    )
    return 0
