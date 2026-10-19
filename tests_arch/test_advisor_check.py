"""`sentinel-advisor-check` reports reachability without leaking the credential. No database involved."""
from __future__ import annotations

import io
import json

from sentinel.infrastructure.outbound import OutboundPolicy, OutboundResponse
from sentinel.interface.advisor_check import SYNTHETIC_INCIDENT, main

TOKEN = "synthetic-provider-key-never-print-0000"
ENV = {"SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":admin", "SENTINEL_ADVISOR_ENDPOINT": "https://model.example/v1",
       "SENTINEL_ADVISOR_MODEL": "m-latest", "SENTINEL_ADVISOR_TOKEN": TOKEN}


class _Stub:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self.policy = OutboundPolicy()
        self.calls: list[dict] = []
        self._payload, self._status = payload, status

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return OutboundResponse(status=self._status, headers={}, body=json.dumps(self._payload).encode(), peer="203.0.113.9:443")


def _run(monkeypatch, env, client, *argv):
    for name in list(ENV) + ["SENTINEL_DB_PATH"]:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    out = io.StringIO()
    code = main(list(argv), out=out, client=client)
    return code, out.getvalue()


def test_unconfigured_is_stated_not_faked(monkeypatch):
    code, text = _run(monkeypatch, {"SENTINEL_API_KEYS": ENV["SENTINEL_API_KEYS"]}, None)
    assert code == 3 and "no advisory model is configured" in text


def test_a_live_answer_is_reported_without_the_token_or_full_endpoint(monkeypatch):
    stub = _Stub({"choices": [{"message": {"content": "Check who read the credentials file and rotate it.\nSecond line."}}]})
    code, text = _run(monkeypatch, ENV, stub)
    assert code == 0 and "model.example, model m-latest: answered" in text
    assert "note: [unverified-model-output] Check who read" in text
    assert TOKEN not in text and "/v1" not in text
    assert stub.calls[0]["url"] == "https://model.example/v1/chat/completions"
    sent = json.loads(stub.calls[0]["body"])
    assert SYNTHETIC_INCIDENT["incident_type"] in sent["messages"][1]["content"]
    assert "authority: none" in text


def test_a_failing_provider_is_an_unavailable_exit(monkeypatch):
    code, text = _run(monkeypatch, ENV, _Stub({}, status=500))
    assert code == 1 and "UNAVAILABLE" in text and "HTTP 500" in text and TOKEN not in text


def test_models_are_listed_by_name_only(monkeypatch):
    stub = _Stub({"data": [{"id": "models/gemini-x-pro"}, {"id": "models/gemini-x-flash"}, {"object": "nope"}]})
    code, text = _run(monkeypatch, ENV, stub, "--list-models")
    assert code == 0 and "2 models" in text and "models/gemini-x-flash\n" in text
    assert stub.calls[0]["method"] == "GET" and stub.calls[0]["url"].endswith("/v1/models")
    assert stub.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}" and TOKEN not in text
