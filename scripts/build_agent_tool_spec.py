#!/usr/bin/env python3
"""Build the OpenAPI tool definition that agent platforms import to call Sentinel.

    python scripts/build_agent_tool_spec.py                 # rewrite both files under docs/integrations/ (3.1 and 3.0)
    python scripts/build_agent_tool_spec.py --check         # exit 1 if the committed file is out of date
    python scripts/build_agent_tool_spec.py --server https://sentinel.example.com --out my.json

Custom GPTs (Actions), Amazon Bedrock Agents (action groups), Azure AI Foundry
and Copilot Studio (OpenAPI tools) and Google Vertex AI Agent Builder (OpenAPI
tools) all take the same thing: an OpenAPI 3 document, an HTTPS server and an
API key. So there is ONE document, and it is derived from the running
application rather than written beside it:

* the request bodies are the REAL routes' schemas, narrowed to the fields an
  agent should fill. A field this script names that the route does not have is
  an error, so the document cannot describe a request the server rejects;
* nothing lets the caller assert its own trust: the routes refuse `trustLevel`
  and this document does not offer it;
* descriptions are short and written as instructions to a model, because that
  is who reads them. They are OUR text; nothing from a third party is copied in.

This is a private integration artifact. It is not published anywhere.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DEFAULT_OUT = ROOT / "docs" / "integrations" / "sentinel-agent-tool.openapi.json"
DEFAULT_SERVER = "https://app.joinsentinelai.com"

#: operation -> (path, operationId, summary, description, consequential, fields the agent fills)
OPERATIONS = (
    ("/v1/protect/evaluate", "checkAction", "Ask Sentinel whether an action may proceed",
     "Call BEFORE any action that changes, sends, deletes, deploys or pays. Describe the exact tool, resource and arguments. "
     "Proceed only if decision is allow or warn. On require_approval, tell the user a person must approve; on block, stop.",
     False, ("agentId", "tool", "action", "resource", "destination", "arguments")),
    ("/v1/tools/execute", "executeApprovedAction", "Run an approved action through Sentinel",
     "Run a tool through Sentinel using the authorization token that checkAction returned. Use the SAME tool, resource and "
     "arguments. A 403 means not approved yet, already used, or changed: do not retry with different arguments.",
     True, ("agentId", "tool", "action", "resource", "arguments", "authorization")),
)
FIELD_HELP = {
    "agentId": "A stable name for this assistant, e.g. agent:support-gpt. Always send the same value.",
    "tool": "The name of the tool or API operation you are about to use, e.g. send_email, create_refund, deploy.",
    "action": "The verb: read, create, update, delete, send, pay, deploy.",
    "resource": "What the action touches, as a path, e.g. /orders/1042 or /protected-change/prod/checkout.",
    "destination": "For outbound calls, the URL or host the data is going to.",
    "arguments": "The exact arguments you will pass to the tool. Sentinel decides on these and binds its approval to them.",
    "authorization": "The authorization.token string from checkAction's answer.",
}
DECISION = {
    "type": "object",
    "required": ["decision"],
    "properties": {
        "decision": {"type": "string", "enum": ["allow", "warn", "require_approval", "block"],
                     "description": "allow or warn: proceed. require_approval: wait for a person. block: stop."},
        "reason": {"type": "string", "description": "Why. Tell the user in plain words."},
        "enforced": {"type": "boolean"},
        "matched_rules": {"type": "array", "items": {"type": "string"}},
        "authorization": {
            "type": ["object", "null"],
            "description": "Present when the action may run now or after approval. Pass authorization.token to executeApprovedAction.",
            "properties": {"token": {"type": "string"}, "authorization_id": {"type": "string"}, "expires_at": {"type": "string"},
                           "state": {"type": "string"}},
        },
    },
}
REFUSAL = {"type": "object", "properties": {"detail": {"description": "Why Sentinel refused."}}}


def build(server: str) -> dict:
    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.interface.http import create_app

    container = build_container(Settings.from_environment({"SENTINEL_API_KEYS": "spec:" + "k" * 40 + ":admin"}), verify_schema=False)
    try:
        live = create_app(container).openapi()
    finally:
        container.close()
    paths: dict = {}
    for path, operation_id, summary, description, consequential, fields in OPERATIONS:
        if len(description) > 300:
            raise SystemExit(f"{operation_id}: description is {len(description)} characters; platforms cap it at 300")
        source = live["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[-1]
        model = live["components"]["schemas"][source]
        unknown = [name for name in fields if name not in model["properties"]]
        if unknown or "trustLevel" in fields:
            raise SystemExit(f"{operation_id}: the route's model has no field(s) {unknown}; the document would describe a request it rejects")
        properties = {}
        for name in fields:
            real = dict(model["properties"][name])
            real.pop("title", None)
            real.pop("default", None)
            if "anyOf" in real:  # `str | None` on the route: an agent always sends the string
                real = {k: v for k, v in next(o for o in real["anyOf"] if o.get("type") != "null").items()}
            real["description"] = FIELD_HELP[name]
            properties[name] = real
        required = [name for name in model.get("required", []) if name in fields]
        if operation_id == "executeApprovedAction":
            required.append("authorization")
        elif "tool" not in required:
            required.append("tool")
        responses = {
            "200": {"description": "Sentinel's decision." if operation_id == "checkAction" else "The tool ran once under the approval.",
                    "content": {"application/json": {"schema": DECISION if operation_id == "checkAction" else {
                        "type": "object", "properties": {"tool": {"type": "string"}, "result": {"description": "What the tool returned."},
                                                         "protect": DECISION, "receipt": {"type": ["object", "null"],
                                                         "description": "Proof binding what ran to what was approved."}}}}}},
            "401": {"description": "The API key was rejected. No decision was made: do NOT proceed."},
            "403": {"description": "Refused." if operation_id == "executeApprovedAction" else "Blocked by policy.",
                    "content": {"application/json": {"schema": REFUSAL if operation_id == "executeApprovedAction" else DECISION}}},
        }
        paths[path] = {"post": {
            "operationId": operation_id, "summary": summary, "description": description, "x-openai-isConsequential": consequential,
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": required, "properties": properties, "additionalProperties": False}}}},
            "responses": responses, "security": [{"sentinelKey": []}]}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "Sentinel action gate", "version": "1.0.0",
                 "description": "Ask Sentinel before an AI agent acts. If Sentinel cannot be reached or returns anything but a decision, do not act."},
        "servers": [{"url": server.rstrip("/")}],
        "paths": paths,
        "components": {"securitySchemes": {"sentinelKey": {"type": "http", "scheme": "bearer",
                                                           "description": "A Sentinel API key with the ingest role."}}, "schemas": {}},
    }


def downgrade(spec: dict) -> dict:
    """The same document as OpenAPI 3.0.3, for platforms that do not accept 3.1.

    3.0 has no `"type": [x, "null"]`; it says `nullable: true`. Nothing else in
    this document uses a 3.1-only feature, and this function fails loudly if
    that ever stops being true rather than emitting something half-converted.
    """
    def convert(node):
        if isinstance(node, dict):
            out = {key: convert(value) for key, value in node.items()}
            kind = out.get("type")
            if isinstance(kind, list):
                real = [k for k in kind if k != "null"]
                if len(real) != 1:
                    raise SystemExit(f"cannot express type {kind} in OpenAPI 3.0")
                out["type"] = real[0]
                out["nullable"] = True
            return out
        return [convert(item) for item in node] if isinstance(node, list) else node
    older = convert(spec)
    older["openapi"] = "3.0.3"
    return older


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=DEFAULT_SERVER, help="the HTTPS base URL of the Sentinel the platform will call")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="fail if the committed document differs from what the application yields")
    args = parser.parse_args(argv)
    if not args.server.startswith("https://"):
        print("--server must be https: agent platforms refuse plain HTTP, and the API key would cross the network in the clear", file=sys.stderr)
        return 2
    spec = build(args.server)
    older_path = args.out.with_name(args.out.name.replace(".openapi.json", ".openapi-3.0.json"))
    outputs = {args.out: json.dumps(spec, indent=2) + "\n", older_path: json.dumps(downgrade(spec), indent=2) + "\n"}
    if args.check:
        stale = [str(path) for path, text in outputs.items() if not path.exists() or path.read_text(encoding="utf-8") != text]
        if stale:
            print(f"out of date: {', '.join(stale)}; run scripts/build_agent_tool_spec.py", file=sys.stderr)
            return 1
        print("both documents match the application")
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    for path, text in outputs.items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
