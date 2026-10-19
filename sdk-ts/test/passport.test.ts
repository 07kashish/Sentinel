import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytes } from "../src/canonical.ts";
import { verifyPassport } from "../src/passport.ts";

function toBase64(bytes: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

test("passport verifier checks an Ed25519 signature over canonical bytes", async () => {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const passport = {
    schema: "sentinel.passport/v1",
    execution_id: "exec-1",
    tenant_id: "acme",
    occurred_at: "2026-03-01T12:00:00+00:00",
    agent_id: "finance-agent",
    action: "transfer_funds",
    decision: "allowed",
  };
  const signature = await crypto.subtle.sign(
    "Ed25519",
    pair.privateKey,
    canonicalBytes(passport),
  );
  const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);

  const result = await verifyPassport(
    {
      passport,
      signature: {
        algorithm: "ed25519",
        key_id: "audit-key-1",
        signed_at: "2026-03-01T12:00:00+00:00",
        value: toBase64(signature),
      },
    },
    { key_id: "audit-key-1", public_key: toBase64(publicKey) },
  );

  assert.equal(result.verified, true);
  assert.deepEqual(result.findings, []);

  const tampered = await verifyPassport(
    {
      passport: { ...passport, decision: "blocked" },
      signature: {
        algorithm: "ed25519",
        key_id: "audit-key-1",
        signed_at: "2026-03-01T12:00:00+00:00",
        value: toBase64(signature),
      },
    },
    { key_id: "audit-key-1", public_key: toBase64(publicKey) },
  );

  assert.equal(tampered.verified, false);
  assert.equal(tampered.findings[0].code, "modified");
});
