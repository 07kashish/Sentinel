"""Real tool effects, and the containment that has to hold after an ALLOW.

WHAT THIS MODULE IS ACTUALLY TESTING
--------------------------------------
Not "does the gate block bad tool calls" -- `test_protect_gate.py` covers that.
This covers the half that runs when the gate has ALREADY said ALLOW.

The distinction is the reason these adapters exist as separate objects at all.
`ProtectGate` reasons about the request as DESCRIBED; the adapter reasons about
what it RESOLVES to. No policy engine can know that `notes.txt` is a symlink to
/etc/shadow, because that fact does not exist until something follows the link.

So every test here runs the adapter DIRECTLY, with no gate in front of it, which
is the honest model of an attacker who has found a request the policy permits.
If containment only works when the gate also refuses, it is not containment.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinel.infrastructure.tool_adapters import (
    MAX_WRITE_BYTES,
    FileSandbox,
    ToolAdapterRefused,
    build_tool_adapters,
    read_file_adapter,
    write_file_adapter,
)


@pytest.fixture
def sandbox(tmp_path: Path) -> FileSandbox:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "notes.txt").write_text("inside the sandbox", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "deep.txt").write_text("nested file", encoding="utf-8")

    # A secret OUTSIDE the sandbox. Every escape test below aims at this file,
    # so a passing test means the content was genuinely unreachable rather than
    # that the path happened not to exist.
    (tmp_path / "secret.txt").write_text("SENSITIVE", encoding="utf-8")
    return FileSandbox.at(root)


def _read(sandbox: FileSandbox, path: str):
    return read_file_adapter(sandbox).runner({"path": path})


def _write(sandbox: FileSandbox, path: str, content: str = "x"):
    return write_file_adapter(sandbox).runner({"path": path, "content": content})


# ── The happy path, so the refusals below mean something ─────────────────────


def test_a_file_inside_the_sandbox_can_be_read(sandbox):
    """Without this, an adapter that refused everything would pass every other
    test in this module."""
    result = _read(sandbox, "notes.txt")
    assert result["content"] == "inside the sandbox"
    assert result["bytes"] == 18


def test_a_nested_file_can_be_read(sandbox):
    assert _read(sandbox, "nested/deep.txt")["content"] == "nested file"


def test_a_file_can_be_written_and_read_back(sandbox):
    _write(sandbox, "new/dir/out.txt", "written")
    assert _read(sandbox, "new/dir/out.txt")["content"] == "written"


# ── Traversal ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "../secret.txt",
        "../../secret.txt",
        "nested/../../secret.txt",
        "./nested/./../../secret.txt",
        "nested/../nested/../../secret.txt",
    ],
)
def test_traversal_out_of_the_sandbox_is_refused_on_read(sandbox, path):
    """Each of these resolves to the secret file that really is out there."""
    with pytest.raises(ToolAdapterRefused, match="outside the tool sandbox"):
        _read(sandbox, path)


@pytest.mark.parametrize("path", ["../escaped.txt", "nested/../../escaped.txt"])
def test_traversal_out_of_the_sandbox_is_refused_on_write(sandbox, path, tmp_path):
    with pytest.raises(ToolAdapterRefused, match="outside the tool sandbox"):
        _write(sandbox, path)
    assert not (tmp_path / "escaped.txt").exists(), "a file was written outside"


def test_an_absolute_path_outside_the_sandbox_is_refused(sandbox, tmp_path):
    with pytest.raises(ToolAdapterRefused):
        _read(sandbox, str(tmp_path / "secret.txt"))


# ── Symlinks: the case a string check cannot see ─────────────────────────────


@pytest.mark.skipif(
    os.name == "nt" and not os.environ.get("SENTINEL_TEST_SYMLINKS"),
    reason=(
        "creating symlinks on Windows needs Developer Mode or admin. Set "
        "SENTINEL_TEST_SYMLINKS=1 to run. Reported, never silently skipped."
    ),
)
def test_a_symlink_pointing_out_of_the_sandbox_is_refused(sandbox, tmp_path):
    """The case that motivates resolving BEFORE checking containment.

    Nothing about the NAME `innocent.txt` says it points at the secret. A check
    that inspects the string, or that checks containment before resolving, lets
    this straight through.
    """
    link = sandbox.root / "innocent.txt"
    link.symlink_to(tmp_path / "secret.txt")

    with pytest.raises(ToolAdapterRefused, match="outside the tool sandbox"):
        _read(sandbox, "innocent.txt")


@pytest.mark.skipif(
    os.name == "nt" and not os.environ.get("SENTINEL_TEST_SYMLINKS"),
    reason="creating symlinks on Windows needs Developer Mode or admin",
)
def test_a_symlinked_directory_cannot_be_used_to_escape(sandbox, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("SENSITIVE", encoding="utf-8")
    (sandbox.root / "shortcut").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ToolAdapterRefused):
        _read(sandbox, "shortcut/loot.txt")


# ── A sibling directory sharing a name prefix ────────────────────────────────


def test_a_sibling_directory_with_the_same_prefix_is_not_inside(tmp_path):
    """`/srv/sandbox-evil` must not count as inside `/srv/sandbox`.

    This is what a string `startswith` comparison gets wrong, and it is a real
    and frequently shipped bug. `is_relative_to` compares path COMPONENTS.
    """
    root = tmp_path / "sandbox"
    root.mkdir()
    evil = tmp_path / "sandbox-evil"
    evil.mkdir()
    (evil / "loot.txt").write_text("SENSITIVE", encoding="utf-8")

    sandbox = FileSandbox.at(root)
    with pytest.raises(ToolAdapterRefused):
        _read(sandbox, "../sandbox-evil/loot.txt")


def test_a_root_containing_a_symlink_still_accepts_its_own_files(tmp_path):
    """The other direction, and the reason the ROOT is resolved too.

    On macOS /tmp is a symlink to /private/tmp. A sandbox that resolved the
    candidate but compared it against an unresolved root would refuse every
    legitimate path -- and a containment check that refuses everything gets
    switched off by whoever is on call at 3am.
    """
    real = tmp_path / "real_root"
    real.mkdir()
    (real / "ok.txt").write_text("fine", encoding="utf-8")

    sandbox = FileSandbox.at(real)
    assert _read(sandbox, "ok.txt")["content"] == "fine"


# ── Bounds ───────────────────────────────────────────────────────────────────


def test_an_oversized_write_is_refused(sandbox):
    with pytest.raises(ToolAdapterRefused, match="write limit"):
        _write(sandbox, "big.txt", "a" * (MAX_WRITE_BYTES + 1))
    assert not (sandbox.root / "big.txt").exists()


def test_a_directory_is_not_readable_as_a_file(sandbox):
    with pytest.raises(ToolAdapterRefused, match="not a file"):
        _read(sandbox, "nested")


def test_writing_over_the_sandbox_root_is_refused(sandbox):
    with pytest.raises(ToolAdapterRefused):
        _write(sandbox, ".")


def test_an_empty_path_is_refused(sandbox):
    """Without this, an empty path resolves to the root itself."""
    with pytest.raises(ToolAdapterRefused, match="empty"):
        _read(sandbox, "")


def test_non_utf8_content_is_refused_rather_than_mangled(sandbox):
    """Returning replacement characters would produce evidence nobody can
    trust, in a product whose output is used to decide what happened."""
    (sandbox.root / "binary.bin").write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ToolAdapterRefused, match="UTF-8"):
        _read(sandbox, "binary.bin")


def test_non_string_content_is_refused_on_write(sandbox):
    with pytest.raises(ToolAdapterRefused, match="must be a string"):
        write_file_adapter(sandbox).runner({"path": "x.txt", "content": {"a": 1}})


# ── The sandbox root itself ──────────────────────────────────────────────────


def test_a_missing_sandbox_root_is_refused_rather_than_created(tmp_path):
    """A sandbox root that appears on demand is one nobody reviewed."""
    with pytest.raises(ToolAdapterRefused, match="not an existing directory"):
        FileSandbox.at(tmp_path / "does-not-exist")


def test_a_file_as_a_sandbox_root_is_refused(tmp_path):
    target = tmp_path / "a-file"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(ToolAdapterRefused):
        FileSandbox.at(target)


# ── Registration is fail-closed by ABSENCE ───────────────────────────────────


def test_no_adapters_are_registered_without_configuration():
    """The default posture. An unconfigured adapter is absent, and
    InlineToolProxy refuses unregistered tools -- so the safe state is enforced
    by code that exists rather than by a flag one boolean away from being on.
    """
    assert build_tool_adapters() == {}


def test_file_adapters_appear_only_when_a_root_is_configured(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    assert sorted(build_tool_adapters(file_root=str(root))) == [
        "read_file",
        "write_file",
    ]
    assert "http_request" not in build_tool_adapters(file_root=str(root))


def test_the_http_adapter_requires_an_explicit_host_allowlist():
    """"Any public address" is still an egress channel.

    The hardened client already refuses private and link-local destinations, so
    this is not about SSRF -- it is that an agent talked into exfiltrating data
    does not need a private address to do it.
    """
    assert "http_request" not in build_tool_adapters()
    assert "http_request" in build_tool_adapters(
        http_allowed_hosts=frozenset({"api.example.com"})
    )


def test_a_blank_file_root_does_not_register_file_adapters():
    """Whitespace is not configuration."""
    assert build_tool_adapters(file_root="   ") == {}


# ── The enforcement path now governs a REAL effect ───────────────────────────
#
# Until these adapters existed, the only tools registered on the inline proxy
# were `echo` and `noop`. Every test of the kill switch, the budget and the gate
# was therefore a test of machinery guarding something that could not do harm.
# These run the whole path -- ProtectGate, ProtectControls, InlineToolProxy --
# against an effect that really touches the filesystem.


def _proxy(sandbox: FileSandbox, *, enforce: bool = True, kill_switch: bool = False):
    from sentinel.application.protect_controls import ProtectControls
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.infrastructure.detection import DeterministicPolicy

    runner = ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=enforce),
        controls=ProtectControls(kill_switch=kill_switch),
    )
    return InlineToolProxy(
        tool_runner=runner, effects=build_tool_adapters(file_root=str(sandbox.root))
    )


def test_an_allowed_write_actually_reaches_the_filesystem(sandbox):
    """The control case. If the proxy silently performed nothing, every
    enforcement assertion below would pass while proving nothing."""
    from sentinel.domain.primitives import TrustLevel

    _proxy(sandbox).execute(
        agent_id="agent-1",
        tool="write_file",
        trust=TrustLevel.UNSIGNED,
        arguments={"path": "report.txt", "content": "produced by the agent"},
        action="write_file",
        resource="report.txt",
    )
    assert (sandbox.root / "report.txt").read_text("utf-8") == "produced by the agent"


def test_the_kill_switch_stops_a_real_effect_from_touching_the_disk(sandbox):
    """Previously this could only be demonstrated against `noop`."""
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    # ToolProxyRefused, not KillSwitchActive: the proxy normalises every refusal
    # to one type so a caller cannot accidentally handle some of them and let
    # the rest escape. The original cause stays on __cause__ and is asserted.
    with pytest.raises(ToolProxyRefused, match="kill switch"):
        _proxy(sandbox, kill_switch=True).execute(
            agent_id="agent-1",
            tool="write_file",
            trust=TrustLevel.UNSIGNED,
            arguments={"path": "blocked.txt", "content": "should never exist"},
            action="write_file",
            resource="blocked.txt",
        )
    assert not (sandbox.root / "blocked.txt").exists(), (
        "the kill switch was active and the file was written anyway"
    )


def test_an_unregistered_tool_is_refused_even_though_the_adapter_exists(sandbox):
    """`http_request` is a real adapter, but this proxy was built without an
    HTTP allowlist -- so it must not be reachable. Fail closed by absence."""
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    with pytest.raises(ToolProxyRefused, match="not registered"):
        _proxy(sandbox).execute(
            agent_id="agent-1",
            tool="http_request",
            trust=TrustLevel.UNSIGNED,
            arguments={"url": "https://example.com"},
        )


def test_containment_holds_even_when_the_gate_allows_the_call(sandbox, tmp_path):
    """The claim this whole module exists to support.

    The gate is given an innocuous-looking action it has no reason to block.
    The adapter refuses anyway, because the path resolves outside the sandbox --
    a fact no policy engine can know from the request as described.
    """
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    with pytest.raises(ToolProxyRefused) as raised:
        _proxy(sandbox).execute(
            agent_id="agent-1",
            tool="read_file",
            trust=TrustLevel.UNSIGNED,
            arguments={"path": "../secret.txt"},
            action="read_file",
            resource="notes.txt",  # what it CLAIMS to be reading
        )

    # The message must attribute this to the EFFECT, not to the detector.
    # Reported as "protect evaluation failed", a blocked sandbox escape sends
    # whoever is on-call to investigate the classifier instead of the agent.
    assert "outside the tool sandbox" in str(raised.value)
    assert "protect evaluation failed" not in str(raised.value), (
        "containment working was reported as the detector malfunctioning"
    )
    assert not (sandbox.root / "secret.txt").exists()
