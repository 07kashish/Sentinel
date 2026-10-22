# Connecting Sentinel to GPTs and cloud agent platforms

One document does it for all of them: `docs/integrations/sentinel-agent-tool.openapi.json` (OpenAPI 3.1), with an identical 3.0 copy beside it, `sentinel-agent-tool.openapi-3.0.json`, for platforms that need the older format. Custom GPTs, Amazon Bedrock Agents, Azure AI Foundry / Copilot Studio and Google Vertex AI Agent Builder all accept an OpenAPI document, an HTTPS address and an API key. The document is derived from the running application by `scripts/build_agent_tool_spec.py`, and `tests_arch/test_agent_tool_spec.py` fails if it drifts or if a caller following it cannot complete the journey on the real routes.

It gives the assistant two operations:

| Operation | When the assistant calls it | Result |
|---|---|---|
| `checkAction` | Before anything that changes, sends, deletes, deploys or pays | `allow`, `warn`, `require_approval` or `block`, with the reason |
| `executeApprovedAction` | To run a tool through Sentinel under the authorization `checkAction` returned | The tool runs once; a receipt binds what ran to what was approved |

## What must be true first

1. **HTTPS.** Every platform below refuses plain HTTP. The document's server is `https://app.joinsentinelai.com`; that address works only after the two DNS records for it exist (OWNER_ACTIONS 11). Until then nothing here can be connected. For another address: `python scripts/build_agent_tool_spec.py --server https://your-host --out my.json`.
2. **An `ingest` key for the tenant**, one per assistant if you want to tell them apart. An ingest key can ask and execute; it cannot read incidents or approve.
3. **A policy** that says which resources need a human (console → Policy).

## The instruction to give the assistant

Paste this into the assistant's system instructions. It is the part that makes the assistant actually ask.

```
You must call checkAction before any action that changes, sends, deletes, deploys or pays for something.
Describe the exact tool, the resource and the exact arguments you intend to use.
- If decision is "allow" or "warn": proceed with exactly those arguments.
- If decision is "require_approval": do not proceed. Tell the user a person must approve it in Sentinel, and wait.
  When the user says it is approved, call executeApprovedAction with the same tool, resource and arguments and the authorization token.
- If decision is "block": do not proceed. Tell the user why, using the reason.
- If checkAction fails, times out or returns anything else: do not proceed. Never assume it would have been allowed.
Always send the same agentId. Never change the arguments after asking.
```

## Platform by platform

| Platform | Where the document goes | Authentication | Note |
|---|---|---|---|
| **Custom GPT** (ChatGPT) | GPT editor → Configure → Actions → Create new action → paste the JSON | Authentication → API Key → Auth Type **Bearer** → the ingest key | `x-openai-isConsequential` is set: ChatGPT asks the user to confirm `executeApprovedAction`, not `checkAction`. A GPT shared publicly also needs a privacy-policy URL |
| **OpenAI Assistants / Responses API** | Not an Action: use the Python adapter `sentinel/sdk/adapters/openai_agents.py`, or declare two function tools with the same names and call the two endpoints from your code | Your server holds the key | The model never sees the key |
| **Amazon Bedrock Agents** | Agent → Action groups → Add → define with **API schema** → upload the JSON | An action group calls a Lambda function: the Lambda forwards the request to Sentinel with the key from Secrets Manager | Bedrock's schema support is OpenAPI 3.0: upload `sentinel-agent-tool.openapi-3.0.json` instead (same content, generated alongside) |
| **Azure AI Foundry agents** | Agent → Tools → Add → **OpenAPI 3.0 specified tool** → paste the JSON | Connection of type API key, header `Authorization`, value `Bearer <key>` | Use the `-3.0.json` file |
| **Microsoft Copilot Studio** | Tools → Add a tool → REST API → upload the JSON | API key, header `Authorization` | Use the `-3.0.json` file |
| **Google Vertex AI Agent Builder** | Agent → Tools → Create → type **OpenAPI** → paste the document (YAML or JSON) | API key or bearer token in the tool's authentication settings | |
| **Gemini function calling (your own code)** | `sentinel/sdk/adapters/gemini.py` | Your server holds the key | `sentinel.sdk.adapters.gemini` |
| **Anything else that speaks HTTP** (n8n, Zapier, Make, a script) | Two POST requests, shown below | Header `Authorization: Bearer <key>` | |

```bash
curl -s https://app.joinsentinelai.com/v1/protect/evaluate -H "Authorization: Bearer $SENTINEL_INGEST_KEY" -H "Content-Type: application/json" -d '{"agentId":"agent:my-assistant","tool":"create_refund","action":"pay","resource":"/orders/1042","arguments":{"amount":40}}'
```

## What this does and does not give you

* **It gives the assistant a gate to ask, and a way to run approved actions with proof.** Approvals bind to the exact arguments; a changed or repeated execution is refused.
* **It does not force the assistant to ask.** A GPT or cloud agent calls `checkAction` because its instructions say so. Its *other* tools still work if it skips the call. Real enforcement needs the consequential tools to be reachable only through Sentinel's `executeApprovedAction` (the tool registered in Sentinel, the credential held by Sentinel, not by the assistant).
* **`executeApprovedAction` runs tools registered on the Sentinel deployment**: the brokered Kubernetes, GitHub and AWS operations, a demonstration `echo` tool, and **`app_call`** — any HTTPS business application an administrator has registered as a *connected application* (`PUT /v1/apps/<id>` with the destination, the allowed methods and paths, and the credential, which is sealed and never returned). The assistant then calls `app_call` with `{"app": "crm", "method": "POST", "path": "/refunds", "body": {...}}` and resource `app://crm/refunds`; Sentinel presents the credential, so the assistant never holds it. That is the enforcing path: remove the refund action from the assistant, register the CRM in Sentinel, and the only way to refund is through an approval.
* **The agent cannot see whether its request was approved**, by design (an ingest key reads nothing). It learns by trying `executeApprovedAction`: 403 until a person approves.

## What has been verified

| Claim | Evidence |
|---|---|
| The document matches the application and offers no way to assert trust | `tests_arch/test_agent_tool_spec.py` |
| A caller sending only what the document offers completes ask → require approval → refused → approve → execute once → replay and changed arguments refused, on SQLite and PostgreSQL | same file |
| **Imported into ChatGPT, Bedrock, Azure or Vertex** | **Not done.** No account on any of them has been used, and none can connect until HTTPS exists. The per-platform steps above follow each vendor's published procedure; the 3.0 copy exists because of their documented limits, not because an upload failed |

This document and the JSON file are private integration material; nothing here is published to a registry.
