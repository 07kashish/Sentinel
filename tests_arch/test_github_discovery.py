"""A workflow that calls a model and holds a key is an agent with a cron trigger.

Most organisations have more of those than deliberate agent deployments, and
nobody counts them: they are invisible to every tool that inventories "AI
agents" by looking for a framework import.

The tests below are mostly about the connector's holes rather than its hits. A
discovery connector that silently drops what it could not read reports a clean
estate, which is the most damaging output an inventory can produce -- so every
unreadable repository, truncated listing and undecodable file must surface as a
named reason in the coverage record.
"""

from __future__ import annotations

import base64

import pytest

from sentinel.domain.assets import AssetKind
from sentinel.infrastructure.outbound import OutboundRefused, OutboundUnavailable
from sentinel.infrastructure.platforms.github import GithubCredentials
from sentinel.infrastructure.platforms.github_discovery import (
    AI_MARKERS,
    GithubDiscoveryRequest,
    discover_github_estate,
)

CREDS = GithubCredentials(token="ghp_" + "0" * 36)

AGENTIC_WORKFLOW = """
name: nightly triage
on:
  schedule:
    - cron: '0 2 * * *'
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: pip install anthropic
      - run: python triage.py
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
"""

PLAIN_WORKFLOW = """
name: unit tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
"""


class _Response:
    def __init__(self, status: int, body: object = None, *, raw: str | None = None):
        self.status = status
        self._body = body
        self._raw = raw

    def json(self):
        if self._raw is not None:
            raise OutboundRefused("not JSON")
        return self._body


class _FakeClient:
    """Answers canned responses, and records what was asked for."""

    def __init__(self, routes: dict[str, object]):
        self._routes = routes
        self.calls: list[str] = []

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.calls.append(url)
        for fragment, response in self._routes.items():
            if fragment in url:
                if isinstance(response, Exception):
                    raise response
                return response
        return _Response(404, {"message": "Not Found"})


def _content(text: str) -> _Response:
    return _Response(
        200,
        {
            "encoding": "base64",
            "content": base64.b64encode(text.encode()).decode(),
        },
    )


def _listing(*workflows, total: int | None = None) -> _Response:
    items = list(workflows)
    return _Response(
        200,
        {
            "total_count": total if total is not None else len(items),
            "workflows": items,
        },
    )


def _workflow(name: str, path: str, state: str = "active") -> dict:
    return {"id": 1, "name": name, "path": path, "state": state}


def _discover(client, repositories=("acme/api",), **kwargs):
    return discover_github_estate(
        client=client,
        credentials=CREDS,
        request=GithubDiscoveryRequest(repositories=repositories, **kwargs),
    )


# ── what it finds ────────────────────────────────────────────────────────────


def test_a_workflow_that_calls_a_model_is_reported_as_a_skill():
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("nightly triage", ".github/workflows/triage.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    inventory = _discover(client)
    skills = inventory.by_kind(AssetKind.SKILL)

    assert len(skills) == 1
    assert "anthropic" in skills[0].attributes["markers"]
    assert skills[0].attributes["content_examined"] is True


def test_a_plain_build_workflow_is_not_reported():
    """The connector must discriminate, or it flags every repository and gets
    filtered out of every report within a week.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("unit tests", ".github/workflows/test.yml")
            ),
            "contents/": _content(PLAIN_WORKFLOW),
        }
    )

    assert _discover(client).by_kind(AssetKind.SKILL) == ()


def test_the_repository_itself_is_recorded_as_what_the_workflows_act_on():
    client = _FakeClient({"actions/workflows": _listing()})
    inventory = _discover(client)

    repositories = inventory.by_kind(AssetKind.REPOSITORY)
    assert [r.identifier for r in repositories] == ["github:acme/api"]


def test_a_workflow_is_linked_to_its_repository():
    """Without the edge, the exposure graph cannot answer 'what can this
    workflow reach'.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("agent run", ".github/workflows/agent.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    skill = _discover(client).by_kind(AssetKind.SKILL)[0]
    assert skill.relates_to == ("github:acme/api",)


def test_a_marker_in_the_workflow_name_alone_is_enough():
    """Content reads can be denied by a token's scope. The name is weaker
    evidence and is still evidence.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("claude code review", ".github/workflows/review.yml")
            ),
            "contents/": _Response(403, {"message": "Resource not accessible"}),
        }
    )

    inventory = _discover(client)
    assert len(inventory.by_kind(AssetKind.SKILL)) == 1


# ── the holes, which are the point ───────────────────────────────────────────


def test_a_repository_that_could_not_be_read_is_named_with_its_status():
    """Not omitted. A connector that drops what it could not read reports a
    clean estate.
    """
    client = _FakeClient({"actions/workflows": _Response(404, {})})
    inventory = _discover(client)

    assert inventory.coverage.is_partial
    assert len(inventory.coverage.unreachable) == 1
    assert "404" in inventory.coverage.unreachable[0].reason


def test_a_refused_request_is_recorded_rather_than_ending_the_scan():
    """One bad repository must not lose the other twelve."""
    client = _FakeClient(
        {
            "acme/broken": OutboundRefused("blocked destination"),
            "acme/api/actions/workflows": _listing(
                _workflow("agent", ".github/workflows/a.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    inventory = _discover(client, repositories=("acme/broken", "acme/api"))

    assert len(inventory.by_kind(AssetKind.SKILL)) == 1
    assert any(
        "OutboundRefused" in u.reason for u in inventory.coverage.unreachable
    )


def test_an_unavailable_host_is_recorded_with_its_exception_type():
    client = _FakeClient({"actions/workflows": OutboundUnavailable("dns failure")})
    inventory = _discover(client)

    assert "OutboundUnavailable" in inventory.coverage.unreachable[0].reason


def test_a_truncated_listing_is_reported_and_not_followed_silently():
    """A connector that stopped at page one and said nothing reports a subset
    as a total.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("a", ".github/workflows/a.yml"), total=250
            ),
            "contents/": _content(PLAIN_WORKFLOW),
        }
    )

    inventory = _discover(client)

    assert inventory.coverage.pagination_complete is False
    assert any("subset" in u.reason for u in inventory.coverage.unreachable)


def test_a_workflow_whose_content_is_unreadable_is_recorded_as_such():
    """It EXISTS and was judged on its name alone. A reader comparing two rows
    needs to know one was judged on content and the other on a filename.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("build", ".github/workflows/build.yml")
            ),
            "contents/": _Response(403, {"message": "no"}),
        }
    )

    inventory = _discover(client)

    assert any(
        "content unreadable" in u.reason for u in inventory.coverage.unreachable
    )


def test_undecodable_content_is_a_hole_and_not_an_empty_file():
    """THE SUBTLE ONE.

    An empty string matches no markers, so treating a decode failure as empty
    content would quietly turn an agentic workflow into a clean one -- a
    scanner fault reported as a security result.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("build", ".github/workflows/build.yml")
            ),
            "contents/": _Response(
                200, {"encoding": "base64", "content": "!!!not base64!!!"}
            ),
        }
    )

    inventory = _discover(client)

    assert inventory.coverage.is_partial
    assert any(
        "undecodable" in u.reason or "content unreadable" in u.reason
        for u in inventory.coverage.unreachable
    )


def test_an_unexpected_content_encoding_is_refused_rather_than_guessed():
    """A wrong guess yields an empty string, and an empty string is clean."""
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("build", ".github/workflows/build.yml")
            ),
            "contents/": _Response(
                200, {"encoding": "utf-16-surprise", "content": "abc"}
            ),
        }
    )

    inventory = _discover(client)

    assert any(
        "encoding" in u.reason for u in inventory.coverage.unreachable
    )


def test_an_unparseable_listing_is_a_hole():
    client = _FakeClient({"actions/workflows": _Response(200, raw="<html>502</html>")})
    inventory = _discover(client)

    assert any(
        "unparseable" in u.reason for u in inventory.coverage.unreachable
    )


def test_a_listing_that_is_not_an_object_is_refused():
    client = _FakeClient({"actions/workflows": _Response(200, [1, 2, 3])})
    inventory = _discover(client)

    assert any("expected an object" in u.reason for u in inventory.coverage.unreachable)


# ── what it refuses to guess ─────────────────────────────────────────────────


def test_repositories_are_required_and_not_discovered():
    """Listing every repository an organisation owns needs an org-wide read
    this deployment may not have. Falling back to what the token happens to
    see produces a confident report about a subset.
    """
    with pytest.raises(ValueError) as raised:
        GithubDiscoveryRequest(repositories=())

    assert "org-wide read" in str(raised.value)


def test_a_malformed_slug_is_refused_rather_than_used_to_build_a_path():
    client = _FakeClient({})
    inventory = _discover(
        client, repositories=("../../etc/passwd", "acme/api/extra", "ok")
    )

    assert not client.calls, "a request was built from a malformed slug"
    assert len(inventory.coverage.unreachable) == 3
    assert all(
        "owner/repo slug" in u.reason for u in inventory.coverage.unreachable
    )


def test_nothing_is_ever_reported_as_attested():
    """Nothing here binds a digest to what actually ran. OBSERVED is the
    strongest honest level, and claiming more would make the AI-BOM's
    provenance census a work of fiction.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("agent", ".github/workflows/a.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    for asset in _discover(client).assets:
        assert asset.attributes.get("provenance") != "attested"


def test_the_permissions_actually_used_are_recorded():
    """An operator reviewing a connector needs to know what it asked for, not
    what its documentation says it might ask for.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("agent", ".github/workflows/a.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    used = _discover(client).coverage.permissions_used

    assert any("actions/workflows" in p for p in used)
    assert any("contents" in p for p in used)


def test_skipping_content_reads_records_that_the_deeper_scan_did_not_happen():
    """Otherwise a reader assumes it did, and treats a name-only scan as
    equivalent evidence.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("claude review", ".github/workflows/a.yml")
            )
        }
    )

    inventory = _discover(client, read_workflow_content=False)
    skill = inventory.by_kind(AssetKind.SKILL)[0]

    assert skill.attributes["content_examined"] is False
    assert not any("contents" in p for p in inventory.coverage.permissions_used)


# ── the denominator and the heuristic ────────────────────────────────────────


def test_the_examined_count_is_the_denominator():
    """"3 agentic workflows" means something different out of 4 than out of
    400.
    """
    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("a", ".github/workflows/a.yml"),
                _workflow("b", ".github/workflows/b.yml"),
                _workflow("c", ".github/workflows/c.yml"),
            ),
            "contents/": _content(PLAIN_WORKFLOW),
        }
    )

    inventory = _discover(client)

    assert inventory.coverage.examined == 3
    assert inventory.by_kind(AssetKind.SKILL) == ()


def test_the_markers_are_exported_so_they_can_be_read():
    """A heuristic that cannot be inspected is a number to be trusted."""
    assert isinstance(AI_MARKERS, frozenset)
    assert "anthropic" in AI_MARKERS
    assert "mcp" in AI_MARKERS


def test_the_module_states_that_the_markers_are_a_heuristic():
    """It will miss a vendored binary and flag a mention in a comment. Left
    unsaid, somebody compares the count against reality and concludes the
    scanner is broken.
    """
    import inspect

    from sentinel.infrastructure.platforms import github_discovery

    doc = " ".join((inspect.getdoc(github_discovery) or "").split())

    assert "heuristic" in doc
    assert "will miss" in doc


def test_the_inventory_carries_the_limits_that_absence_is_not_evidence():
    client = _FakeClient({"actions/workflows": _listing()})

    limits = _discover(client).as_dict()["limits"]

    assert "NOT evidence" in limits


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.infrastructure.platforms import github_discovery

    mutable = [
        name
        for name, value in vars(github_discovery).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"


def test_the_inventory_feeds_the_ai_bom_without_translation():
    """The connector and the bill of materials share one vocabulary, so a new
    connector does not need a mapping layer nobody maintains.
    """
    from sentinel.domain.ai_bom import compile_ai_bom

    client = _FakeClient(
        {
            "actions/workflows": _listing(
                _workflow("agent", ".github/workflows/a.yml")
            ),
            "contents/": _content(AGENTIC_WORKFLOW),
        }
    )

    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_discover(client),),
        generated_at="2026-09-03T00:00:00Z",
    )

    skills = bom.of_kind(AssetKind.SKILL)
    assert len(skills) == 1
    # An Actions workflow has no digest, so the BOM must flag it unattested.
    assert any(f.component == skills[0].identifier for f in bom.findings)
