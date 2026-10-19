import assert from "node:assert/strict";
import test from "node:test";

import { SentinelClient, SentinelUnavailable, stopsAction } from "../src/client.ts";

test("decision vocabulary and stopsAction mirror the server", () => {
  assert.equal(stopsAction("allow"), false);
  assert.equal(stopsAction("warn"), false);
  assert.equal(stopsAction("allow_with_redaction"), false);
  assert.equal(stopsAction("require_approval"), true);
  assert.equal(stopsAction("block"), true);
  assert.equal(stopsAction("step_up_auth"), true);
  assert.equal(stopsAction("require_jit_credential"), true);
  assert.equal(stopsAction("contain"), true);
});

test("check parses authorization and posts tool context", async () => {
  const seen: Record<string, unknown> = {};
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.url = String(url);
    seen.body = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        decision: "allow",
        authorization: { token: "tok-1", digest: "d".repeat(64) },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  try {
    const client = new SentinelClient({
      baseUrl: "https://sentinel.example",
      apiKey: "sk-test",
    });
    const response = await client.check({
      agentId: "agent-1",
      tool: "email",
      arguments: { to: "ops@example.com" },
    });

    assert.equal(seen.url, "https://sentinel.example/v1/protect/evaluate");
    assert.equal(response.authorization?.token, "tok-1");
    assert.deepEqual((seen.body as Record<string, unknown>).metadata, {
      tool: "email",
      arguments: { to: "ops@example.com" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("execute sends authorization and fails closed on non-2xx", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("refused", { status: 403 });
  try {
    const client = new SentinelClient({
      baseUrl: "https://sentinel.example",
      apiKey: "sk-test",
    });
    await assert.rejects(
      () => client.execute({ agentId: "agent-1", tool: "email", authorization: "tok" }),
      SentinelUnavailable,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
