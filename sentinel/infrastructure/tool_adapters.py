"""Real tool side effects, and the containment that survives an ALLOW.

WHY THESE EXIST
---------------
`InlineToolProxy` shipped with `echo` and `noop` registered. Both are honest
placeholders and neither does anything, which means the enforcement path around
them -- ProtectGate, the kill switch, the budget, the circuit breaker -- had
never governed an effect that could actually hurt. A gate whose only subject is
`noop` is a gate nobody has tested against the thing it is for.

These are the three effects an agent actually wants and an operator actually
fears: fetch a URL, read a file, write a file.

THE DIVISION OF RESPONSIBILITY, WHICH IS THE WHOLE POINT
----------------------------------------------------------
**The gate decides policy. The adapter enforces containment.** They are not the
same job and the adapter must not lean on the gate:

  * `ProtectGate` reasons about the request as described -- action, resource,
    prompt text. It is the right place to decide "reading .env is BLOCK".
  * The adapter reasons about what the request RESOLVES to. `ProtectGate` cannot
    know that `metadata.attacker.example` resolves to 169.254.169.254, or that
    `reports/../../../../etc/shadow` leaves the sandbox, or that a symlink named
    `notes.txt` points at `/etc/passwd`. Those facts do not exist until you
    resolve them.

So every adapter here re-checks its own invariants AFTER the gate has already
said ALLOW. That is not redundancy. An ALLOW means "policy permits this action",
never "this path is inside the sandbox".

FAIL CLOSED BY NOT EXISTING
---------------------------
None of these register themselves. `build_tool_adapters` returns only the ones
the operator configured, and an unconfigured adapter is simply absent -- at which
point `InlineToolProxy.execute` refuses it as an unregistered tool, which it
already does correctly. There is no half-configured mode where a file tool runs
with a default root, because the obvious default root is the process's working
directory and that is the whole application.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.domain.errors import DomainRuleViolated
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
)

__all__ = [
    "ToolAdapterNotAttempted",
    "ToolAdapterRejectedByTarget",
    "ToolAdapterRefused",
    "FileSandbox",
    "build_tool_adapters",
    "http_request_adapter",
    "read_file_adapter",
    "write_file_adapter",
]

#: Refuse to write more than this in one call. A tool that can write unbounded
#: bytes is a disk-exhaustion primitive reachable by an agent that has been
#: allowed exactly one legitimate-looking action.
MAX_WRITE_BYTES = 1_048_576

#: Refuse to read more than this. Same reasoning in the other direction: the
#: result travels back through the API response.
MAX_READ_BYTES = 1_048_576


class _NotAttemptedMarker:
    #: Read by the runner. True means the effect is KNOWN not to have happened:
    #: either nothing mutating left this process, or the target answered with a
    #: definitive rejection. The operation FAILED; it is not an unknown outcome.
    effect_known_absent = True


class ToolAdapterRefused(DomainRuleViolated):
    """An adapter refused to perform an effect the gate had already allowed.

    Deliberately NOT retryable. Every refusal here is a containment decision --
    the path is outside the sandbox, the host is not on the allowlist -- and
    none of them become true on a second attempt. A retryable refusal would turn
    a blocked traversal into a blocked traversal repeated until something gives.
    """

    is_retryable = False


# ── Filesystem containment ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FileSandbox:
    """A directory that file effects may not leave.

    `root` is resolved once at construction. Every candidate path is resolved
    and then checked for containment against that resolved root, in that order,
    because the checks people write in the other order do not work:

      * checking the string before resolving misses `a/../../etc/passwd`;
      * checking after resolving but comparing to an UNRESOLVED root fails on
        any system where the root itself contains a symlink -- /tmp on macOS is
        /private/tmp, so a correct path compares unequal and a sandbox that
        refuses everything gets disabled by whoever is on call.

    Symlinks are the case that matters most. A file inside the sandbox named
    `notes.txt` may be a symlink to /etc/shadow, and nothing about its NAME says
    so. `Path.resolve()` follows it, which is why resolution happens before the
    containment test rather than after.
    """

    root: Path

    @classmethod
    def at(cls, root: str | Path) -> "FileSandbox":
        resolved = Path(root).expanduser().resolve()
        if not resolved.is_dir():
            raise ToolAdapterRefused(
                f"tool file root {resolved} is not an existing directory; "
                "refusing to create it, because a sandbox root that appears on "
                "demand is one nobody reviewed"
            )
        return cls(root=resolved)

    def resolve(self, candidate: str) -> Path:
        """Resolve a caller-supplied path and prove it is inside the sandbox."""
        if not candidate or not candidate.strip():
            raise ToolAdapterRefused("path is empty")

        # `strict=False`: a write targets a file that does not exist yet, and
        # resolving strictly would refuse every create. The containment check
        # below does not depend on existence.
        resolved = (self.root / candidate).expanduser().resolve(strict=False)

        if not self._contains(resolved):
            raise ToolAdapterRefused(
                f"path {candidate!r} resolves to {resolved}, which is outside "
                f"the tool sandbox {self.root}. Refused after resolution, so "
                "traversal and symlinks are both covered."
            )
        return resolved

    def _contains(self, resolved: Path) -> bool:
        # `is_relative_to` compares path components, not string prefixes. A
        # prefix comparison would accept `/srv/sandbox-evil` for a root of
        # `/srv/sandbox`, which is a real and frequently shipped bug.
        return resolved == self.root or resolved.is_relative_to(self.root)


# ── The adapters ─────────────────────────────────────────────────────────────


def read_file_adapter(sandbox: FileSandbox) -> RegisteredSideEffect:
    """Read a file from inside the sandbox, bounded."""

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        path = sandbox.resolve(str(args.get("path", "")))
        if not path.is_file():
            raise ToolAdapterRefused(f"{args.get('path')!r} is not a file")

        size = path.stat().st_size
        if size > MAX_READ_BYTES:
            raise ToolAdapterRefused(
                f"file is {size} bytes, over the {MAX_READ_BYTES}-byte read limit"
            )
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            # Returned as a refusal rather than as mojibake. A tool that
            # silently mangles binary content produces evidence nobody can trust.
            raise ToolAdapterRefused(
                "file is not valid UTF-8; this adapter returns text only"
            ) from None
        return {"path": str(path), "bytes": len(data), "content": text}

    return RegisteredSideEffect(name="read_file", runner=run)


def write_file_adapter(sandbox: FileSandbox) -> RegisteredSideEffect:
    """Write a file inside the sandbox, bounded, creating parent directories."""

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        path = sandbox.resolve(str(args.get("path", "")))
        content = args.get("content", "")
        if not isinstance(content, str):
            raise ToolAdapterRefused("content must be a string")

        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolAdapterRefused(
                f"content is {len(data)} bytes, over the "
                f"{MAX_WRITE_BYTES}-byte write limit"
            )
        if path == sandbox.root:
            raise ToolAdapterRefused("refusing to write over the sandbox root")

        # The parent is resolved and contained by construction: `path` passed
        # the containment check, so anything above it and below the root is too.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"path": str(path), "bytes": len(data)}

    return RegisteredSideEffect(name="write_file", runner=run)


def http_request_adapter(client: HardenedHttpClient) -> RegisteredSideEffect:
    """Make one outbound HTTP request through the hardened client.

    The client is injected rather than constructed here, and it is the SAME
    hardened client the rest of the process uses: post-resolution address
    validation, connection pinned to the validated address so DNS rebinding has
    nothing to rebind, redirects refused rather than followed, response bounded.

    Writing a second HTTP client for tool calls would mean the path an ATTACKER
    reaches is the one that never got those defences -- which is the reverse of
    how the effort should be spent.
    """

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        url = str(args.get("url", "")).strip()
        if not url:
            raise ToolAdapterRefused("url is required")
        method = str(args.get("method", "GET")).upper()

        body = args.get("body")
        if body is not None and not isinstance(body, str):
            raise ToolAdapterRefused("body must be a string")
        payload = body.encode("utf-8") if body else None

        # Caller-supplied headers are NOT forwarded. An agent that can set
        # headers can set Authorization, and this process holds credentials the
        # agent must never be able to aim at a destination of its choosing.
        try:
            response = client.request(
                method=method,
                url=url,
                headers={},
                body=payload,
                idempotent=method in {"GET", "HEAD"},
            )
        except OutboundRefused as exc:
            raise ToolAdapterRefused(f"outbound request refused: {exc}") from exc

        text = response.body.decode("utf-8", errors="replace")
        return {
            "status": response.status,
            "headers": dict(response.headers),
            "body": text,
            # The address actually dialled. "we fetched the URL" is not an
            # auditable statement; "we connected to 203.0.113.7:443" is.
            "peer": response.peer,
        }

    return RegisteredSideEffect(name="http_request", runner=run)


# ── Composition ──────────────────────────────────────────────────────────────


def build_tool_adapters(
    *,
    file_root: str = "",
    http_allowed_hosts: frozenset[str] = frozenset(),
    http_client: HardenedHttpClient | None = None,
) -> dict[str, RegisteredSideEffect]:
    """Build exactly the adapters the operator configured, and no others.

    An unconfigured adapter is ABSENT rather than present-and-disabled. That is
    the stronger position: `InlineToolProxy.execute` already refuses unregistered
    tools, so absence is enforced by code that exists, whereas a disabled flag is
    one boolean away from being on.

    `http_allowed_hosts` is required to enable the HTTP adapter, rather than
    defaulting to "any public address". The hardened client refuses private and
    link-local destinations already, but "any public host on the internet" is
    still an egress channel, and an agent that has been talked into exfiltrating
    data does not need a private address to do it.
    """
    adapters: dict[str, RegisteredSideEffect] = {}

    if file_root.strip():
        sandbox = FileSandbox.at(file_root)
        for adapter in (read_file_adapter(sandbox), write_file_adapter(sandbox)):
            adapters[adapter.name] = adapter

    if http_allowed_hosts:
        client = http_client or HardenedHttpClient(
            policy=OutboundPolicy(allowed_hosts=http_allowed_hosts)
        )
        adapter = http_request_adapter(client)
        adapters[adapter.name] = adapter

    return adapters


class ToolAdapterNotAttempted(_NotAttemptedMarker, ToolAdapterRefused):
    """Refused BEFORE any mutating request was sent: validation, the tier
    ceiling, a credential that could not be minted. Raising this for anything
    that happens after the mutating request left would turn an unknown outcome
    into a recorded failure, which is the lie the operation model exists to stop.
    """


class ToolAdapterRejectedByTarget(_NotAttemptedMarker, ToolAdapterRefused):
    """The target RECEIVED the request and definitively refused it (a 4xx: a
    conflict, a forbidden, a validation error). That response is proof the
    mutation was not admitted. A 5xx or a lost response is never this.
    """
