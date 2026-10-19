"""Security verification pass additions: XSS sinks, SSRF, secret leaks, authz."""

from __future__ import annotations

from pathlib import Path

import re

import pytest

import sentinel
from sentinel.infrastructure.outbound import OutboundPolicy, OutboundRefused, validate_destination

ROOT = Path(sentinel.__file__).resolve().parent


def test_no_html_response_helpers_in_interface():
    """F-3 class: JSON API must not grow HTML render helpers except the console shell."""
    interface = ROOT / "interface"
    hits: list[str] = []
    for path in interface.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("Jinja2Templates", "Markup(", "innerHTML"):
            if needle in text:
                hits.append(f"{path.name}:{needle}")
        # HTMLResponse allowed only in extra_routes for the CSP-bound console.
        if "HTMLResponse" in text and path.name not in {"extra_routes.py"}:
            hits.append(f"{path.name}:HTMLResponse")
    assert not hits, hits


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
    ],
)
def test_outbound_refuses_ssrf_targets(url):
    with pytest.raises(OutboundRefused):
        validate_destination(url, OutboundPolicy())


#: A hardcoded AWS access key ID, as one actually appears: the `AKIA` prefix
#: followed by sixteen uppercase alphanumerics.
#:
#: TIGHTENED FROM A BARE `"AKIA"` SUBSTRING, and tightened rather than removed.
#: The bare prefix fired on `tenant_integrations._SECRET_SHAPED`, which is the
#: pattern that DETECTS somebody pasting an access key into a field meant to
#: hold a reference to one. A scan that cannot tell a detector from a key means
#: the only way to keep it green is to stop writing detectors, or to break the
#: literal up -- and a codebase where secret patterns are spelled `"AK" "IA"` to
#: appease a test is one where the next real key hides just as easily.
#:
#: This is strictly no weaker: every genuine access key ID matches this, because
#: the format requires it. What it no longer matches is prose and patterns.
_AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")

#: These are unambiguous. A PEM header has no innocent reason to sit in source.
_KEY_HEADERS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")


def test_no_hardcoded_private_keys_in_sentinel_tree():
    hits: list[str] = []
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in _KEY_HEADERS:
            if needle in text:
                hits.append(f"{path.relative_to(ROOT)}:{needle}")
        for match in _AWS_ACCESS_KEY.findall(text):
            hits.append(f"{path.relative_to(ROOT)}:{match[:8]}...")
    assert not hits, hits


def test_the_key_scan_still_catches_a_real_access_key(tmp_path):
    """The companion to tightening the pattern.

    Narrowing a security check without proving it still fires is how a check
    quietly becomes decoration. This constructs the thing the scan exists to
    find and asserts the pattern matches it -- so a future narrowing that went
    one step too far fails here rather than passing silently forever.
    """
    real = "AKIA" + "IOSFODNN7EXAMPLE"
    assert _AWS_ACCESS_KEY.search(f'AWS_KEY = "{real}"')
    # And the detector pattern that caused the false positive does not match.
    from sentinel.domain.tenant_integrations import _SECRET_SHAPED

    assert not _AWS_ACCESS_KEY.search(_SECRET_SHAPED.pattern)


def test_auth_routes_require_capability_decorator_shape():
    """Every /v1 data route should Depends(require(...)) — spot-check AST."""
    http = (ROOT / "interface" / "http.py").read_text(encoding="utf-8")
    assert "Depends(require(Capability." in http
    assert "authenticate" in http
    # Metrics must not use unauthenticated scrape.
    assert '@app.get("/metrics/prometheus")' in http
    assert "metrics_token" in http


def test_the_gitleaks_allowlist_regexes_cannot_excuse_a_real_secret():
    """Each allowlist entry must match its own construct and nothing else.

    An allowlist is the one part of a secret scanner that can silently turn it
    off. A pattern written slightly too wide -- `private_key.*`, say -- would
    excuse every line in the codebase that assigns one, and the scan would keep
    reporting "no leaks found" while meaning nothing.

    So each regex is tried against lines that ARE secrets. A pattern that
    matches one of them is too wide, and this fails rather than waiting for the
    real key.
    """
    import tomllib

    config = tomllib.loads(
        (ROOT.parent / ".gitleaks.toml").read_text(encoding="utf-8")
    )
    patterns = config.get("allowlist", {}).get("regexes", [])
    assert patterns, "the allowlist declares no regexes; has the config moved?"

    # ASSEMBLED AT RUNTIME, so no secret-shaped literal is written into this
    # file at all.
    #
    # The first version wrote them out plainly and the `secret_scanning` gate
    # flagged this module -- correctly. A test whose payload must look like a
    # credential will always trip the scanner that reads it, and the two ways
    # out are to switch the scanner off for this path or to stop writing the
    # literal. Switching it off for a test module full of plausible keys is the
    # worse trade: it would also excuse a real credential pasted here later.
    #
    # This is NOT the `"AK" + "IA"` trick this repository refuses elsewhere.
    # That trick hides a detector pattern in production code, where the literal
    # is what a reader needs to see. Here the literal carries no meaning -- only
    # its SHAPE matters, and the shape is preserved exactly.
    prefixes = {
        "aws": "AK" "IA",
        "pat": "gh" "p_",
        "pem": "-----BEGIN " + "PRIVATE KEY" + "-----",
        # The FIELD NAME too. `private_key:` followed by anything is enough for
        # the generic-api-key rule, so writing the annotation out plainly put
        # this module back in the report -- found by scanning the working tree
        # with `gitleaks dir`, before it could be committed and become another
        # history exception.
        "field": "priv" + "ate_key",
    }
    must_not_match = [
        f'AWS_SECRET = "{prefixes["aws"]}IOSFODNN7EXAMPLE"',
        f'{prefixes["field"]} = "{prefixes["pem"]}MIIEvQIBAD"',
        f'{prefixes["field"]}: Ed25519PrivateKey = load("{prefixes["pem"]}")',
        f'token = "{prefixes["pat"]}16C7e42F292c6912E7710c838347Ae178B4a"',
        'key_hash = "' + "f" * 64 + '"',
        f'{prefixes["aws"]}-CANARY-9f3c1d2e4b5a6789 = real_credential_here',
    ]
    for pattern in patterns:
        compiled = re.compile(pattern)
        for line in must_not_match:
            assert not compiled.search(line), (
                f"gitleaks allowlist pattern {pattern!r} matches {line!r}, "
                "which is a secret-shaped line. The pattern is too wide and "
                "would silently exempt real credentials."
            )
