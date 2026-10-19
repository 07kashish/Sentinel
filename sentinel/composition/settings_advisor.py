"""Explicit model-advisor configuration; tokens are excluded from repr."""
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class AdvisorSettings:
    endpoint: str = ""
    model: str = ""
    token: str = field(default="", repr=False)
    #: Absolute path to a locally signed-in agent CLI (Antigravity `agy`), instead of an HTTP endpoint.
    cli_command: str = ""
    #: HOME of the account that signed in to the CLI; the only thing the child inherits besides PATH.
    cli_home: str = ""

    @classmethod
    def parse(cls, source: Mapping[str, str], *, error_type: type[Exception] = ValueError) -> "AdvisorSettings":
        endpoint = source.get("SENTINEL_ADVISOR_ENDPOINT", "").strip()
        model = source.get("SENTINEL_ADVISOR_MODEL", "").strip()
        token = source.get("SENTINEL_ADVISOR_TOKEN", "").strip()
        cli = source.get("SENTINEL_ADVISOR_CLI_COMMAND", "").strip()
        if cli:
            if endpoint or token:
                raise error_type("Advisor is either a CLI (SENTINEL_ADVISOR_CLI_COMMAND) or an endpoint with a token, not both.")
            if not model or not cli.startswith("/") or any(ch.isspace() for ch in cli + model) or model.startswith("-"):
                raise error_type("Advisor CLI requires an absolute command path and SENTINEL_ADVISOR_MODEL, with no arguments or spaces.")
            return cls("", model, "", cli, (source.get("SENTINEL_ADVISOR_CLI_HOME") or source.get("HOME", "")).strip())
        bits = (bool(endpoint), bool(model), bool(token))
        if any(bits) and not all(bits):
            raise error_type("Advisor requires SENTINEL_ADVISOR_ENDPOINT, SENTINEL_ADVISOR_MODEL and SENTINEL_ADVISOR_TOKEN together.")
        if endpoint:
            try:
                target = urlsplit(endpoint)
                valid = (target.scheme == "https" and bool(target.hostname) and not target.username
                         and not target.password and not target.query and not target.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise error_type("Advisor endpoint requires HTTPS with no userinfo, query or fragment.")
        return cls(endpoint, model, token)
