"""Every route declares a capability, or is on a list somebody signed off.

WHY A PINNED LIST AND NOT A RULE
--------------------------------
"Every route requires a capability" is false and should be: the console shell
has to be fetchable before anyone has authenticated, and a liveness probe that
needs a credential is a liveness probe that reports the credential service.

So the rule cannot be "always". It has to be "these six, and adding a seventh is
a decision somebody makes on purpose". A new unauthenticated route is otherwise
indistinguishable from the five that are fine — it is one more line in a diff,
and the diff is where authorization holes are easiest to miss.

WHY THIS READS THE DECORATORS AND NOT THE RUNNING APP
--------------------------------------------------------
`Depends(require(Capability.X))` is enforced by FastAPI BEFORE the handler runs.
A check written inside a handler body is a different thing: it can be returned
past, wrapped in a condition, or skipped on an error path. The generator looks
only at parameter defaults for that reason, and this suite pins what it finds.

`/metrics/prometheus` is the instructive case. It appears here as
undeclared because it does not use a capability — it compares a bearer token
inside the handler. That is a deliberate design (a scrape credential is not a
user capability), and it is exactly the kind of thing a reader should have to
look at rather than infer.
"""

from __future__ import annotations

from scripts.dev.route_inventory import collect

#: Routes that intentionally require no capability, and why each one does not.
#:
#: Adding to this set is the point at which somebody is deciding to expose an
#: endpoint without authorization. It should be uncomfortable and it should be
#: reviewed.
PUBLIC_BY_DESIGN: dict[tuple[str, str], str] = {
    ("GET", "/console"): (
        "The SPA shell. It must load before anyone can type a token into it. "
        "The bundle was audited for the property that it discloses nothing: no "
        "credentials, no internal hostnames, no tenant identifiers."
    ),
    ("GET", "/console/app.js"): (
        "Static asset of the shell above, served before authentication for "
        "the same reason. The bundle is treated as PUBLISHED and was "
        "audited for that: no key material, no internal hostnames, no "
        "tenant identifiers, and every fetch target a relative path."
    ),
    ("GET", "/console/app.css"): (
        "Static asset of the shell above. Referenced no external host, "
        "which is checked so the stylesheet cannot become a beacon."
    ),
    ("GET", "/health/live"): (
        "Liveness. A probe that needs a credential reports the health of the "
        "credential path, not of this process, and takes the service down with "
        "it when auth is degraded."
    ),
    ("GET", "/health/ready"): (
        "Readiness, for the same reason. Both are deliberately incapable of "
        "disclosing anything beyond up or not up."
    ),
    ("GET", "/metrics/prometheus"): (
        "NOT unauthenticated. It checks a scrape token inside the handler "
        "rather than declaring a capability, because a scrape credential is "
        "not a user capability and Prometheus holds no principal. It appears "
        "in this list because the generator reads decorators, and that "
        "difference is worth a reader's attention rather than an inference."
    ),

}


def _undeclared() -> set[tuple[str, str]]:
    return {
        (route["method"], route["path"])
        for route in collect()
        if route["capability"] is None
    }


def test_no_route_is_unauthenticated_without_being_listed():
    """The regression that matters: a NEW public endpoint."""
    surprises = _undeclared() - set(PUBLIC_BY_DESIGN)
    assert not surprises, (
        "these routes declare no capability and are not on the reviewed list:\n"
        + "\n".join(f"  {m} {p}" for m, p in sorted(surprises))
        + "\n\nEither add `Depends(require(Capability.X))`, or add the route to "
        "PUBLIC_BY_DESIGN with the reason it is safe to expose. A route that "
        "is public by accident looks exactly like one that is public on "
        "purpose."
    )


def test_the_public_list_has_no_stale_entries():
    """An entry for a route that no longer exists is permission granted to a
    path nobody is watching. If the route comes back, it comes back already
    exempted.
    """
    stale = set(PUBLIC_BY_DESIGN) - _undeclared()
    assert not stale, (
        f"PUBLIC_BY_DESIGN lists routes that are no longer undeclared: "
        f"{sorted(stale)}. Remove them."
    )


def test_every_exemption_carries_a_reason():
    for route, reason in PUBLIC_BY_DESIGN.items():
        assert len(reason.strip()) > 40, (
            f"{route} is exempted without a reason anyone could disagree with"
        )


def test_no_mutating_route_is_public():
    """A GET with no capability is a disclosure risk. A POST with no capability
    is a foothold, and there is no version of this codebase where one is
    correct.

    Separated from the pinned list deliberately: this one is a RULE, not a
    reviewed exception, so it cannot be satisfied by adding a line to
    PUBLIC_BY_DESIGN.
    """
    offenders = [
        (r["method"], r["path"], r["module"])
        for r in collect()
        if r["mutating"] and r["capability"] is None
    ]
    assert not offenders, (
        "these state-changing routes require no capability:\n"
        + "\n".join(f"  {m} {p}  ({mod})" for m, p, mod in offenders)
    )


def test_the_generator_actually_found_the_surface():
    """A generator that silently found nothing would make every check above
    pass vacuously -- the failure mode this repository has hit before, where a
    parser change turned a gate into a no-op that reported success.
    """
    routes = collect()
    assert len(routes) >= 30, f"only {len(routes)} routes found; parser broken?"
    assert any(r["path"].startswith("/v1/") for r in routes)
    assert any(r["capability"] for r in routes), "no capability was ever parsed"


def test_path_parameters_are_reported_for_every_templated_route():
    """A pentest scope needs the injection points, and a templated segment is
    the most obvious one.
    """
    for route in collect():
        templated = "{" in route["path"]
        assert bool(route["path_parameters"]) == templated, (
            f"{route['path']} has path_parameters {route['path_parameters']!r}, "
            "which does not match its template"
        )
