# Governing a Gemini / Antigravity agent with Sentinel

Sentinel has no model of its own. Its decisions are deterministic policy plus a statistical detector that is advisory only; nothing an LLM says reaches the control path. So "linking Gemini to Sentinel" means one thing: **the Gemini agent's actions go through Sentinel's gate**, and a human approves the ones policy says need it. Two ways, both usable today.

## 1. Antigravity (or any MCP host): route tool traffic through the MCP proxy

Antigravity talks to tools over MCP. Enrol the real MCP server with Sentinel once, then point Antigravity at Sentinel instead of the server:

```bash
# on the Sentinel host: enrol the server and pin its tool definitions
# (tools.json is the server's tools/list result, reviewed by a human first)
python -m sentinel.interface.cli mcp-enrol acme https://mcp.example/rpc tools.json
```

Antigravity's MCP configuration (Settings → MCP servers → *Manage*, or the `mcp_config.json` it edits):

```json
{
  "mcpServers": {
    "docs-mcp": {
      "serverUrl": "https://<sentinel-host>/v1/mcp/proxy/docs-mcp",
      "headers": {
        "Authorization": "Bearer <ingest key for the tenant>",
        "X-Sentinel-Agent-Id": "agent:antigravity-gemini",
        "X-Sentinel-Principal": "user:<your email>"
      }
    }
  }
}
```

From then on every `tools/call` Gemini makes is evaluated against the live tool definition and the tenant policy, refused if the server's definitions drifted, and its result inspected before Gemini sees it. A protected change pends in the console until an analyst approves. Requires `SENTINEL_MCP_PROXY_ENABLED=true` and, for progress events, `SENTINEL_MCP_PROXY_STREAMING=true`.

## 2. Your own Gemini code (google-genai): gate each function call

```python
from google import genai
from sentinel.sdk.adapters.gemini import gate_function_call
from sentinel.sdk.remote import SentinelClient

sentinel = SentinelClient(base_url="https://<sentinel-host>", api_key="<ingest key>")
client = genai.Client()  # GEMINI_API_KEY in the environment
response = client.models.generate_content(model="gemini-2.5-pro", contents=prompt, config={"tools": [my_tools]})

for part in response.candidates[0].content.parts:
    if part.function_call:
        gated = gate_function_call(sentinel, part, agent_id="agent:my-gemini-agent", on_unavailable="function_response")
        if gated.approved:
            result = run_tool(gated.name, gated.args)      # only with the arguments the gate saw
        else:
            result = gated.function_response               # the model is told why, and nothing ran
```

`gate_function_call` accepts the REST part (`{"functionCall": {...}}`) and the SDK object, imports nothing from Google, and fails closed on an outage. For a receipt and evidence, execute through Sentinel instead of locally: `sentinel.execute(agent_id=..., tool=gated.name, arguments=gated.args, authorization=gated.response.authorization)`.

## 3. Antigravity CLI as the advisory model

Separate from governing an agent: Sentinel can ask a model for a second opinion on each incident. Set `SENTINEL_ADVISOR_CLI_COMMAND` to the absolute path of a signed-in `agy` and `SENTINEL_ADVISOR_MODEL` to a name from `agy models`. The CLI is run once per incident in print mode — sandboxed, never auto-approving tools, in an empty directory, with HOME and PATH only — and its answer is stored as an `[unverified-model-output]` note. It cannot change priority or any decision. `sentinel-advisor-check` makes one synthetic call and reports whether it answered.

On AWS the CLI needs a host its owner has signed in to: the stack's `brain_host` variable creates one instance that runs the service image as the pipeline replica, reachable only through Session Manager. The module installs no third-party software; the owner places `agy` in `/opt/agy` and signs in with the command the stack outputs.

## What is and is not proven

The adapter is covered by `tests_arch/test_sdk_adapters.py` against a fake transport. No run against the live Gemini API or a real Antigravity session has been recorded; the MCP path is the same proxy that passed the wire tests and the AWS journey with scripted servers. Set `GEMINI_API_KEY` and ask for a recorded run before claiming more.
