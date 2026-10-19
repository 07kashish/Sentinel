import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { NotCanonical, canonicalBytes, digestOf } from "../src/canonical.ts";

type Vector = {
  name: string;
  document: Record<string, unknown>;
  expect: {
    digest?: string;
    defects?: string[];
    tolerate?: string[];
    attestation_digest?: string;
  };
  parents?: Record<string, unknown>[];
};

function loadVectors(directory: string): Vector[] {
  const found: Vector[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      found.push(...loadVectors(path));
    } else if (entry.endsWith(".json")) {
      found.push(JSON.parse(readFileSync(path, "utf8")) as Vector);
    }
  }
  return found;
}

const vectors = loadVectors(new URL("./fixtures", import.meta.url).pathname);

test("the copied vector corpus is not empty", () => {
  assert.ok(vectors.length >= 14);
});

for (const vector of vectors) {
  test(`execution passport vector: ${vector.name}`, async () => {
    const expectedDefects = new Set(vector.expect.defects ?? []);
    if (expectedDefects.has("not_canonical")) {
      await assert.rejects(() => digestOf(vector.document), NotCanonical);
      return;
    }

    const digest = await digestOf(vector.document);
    if (vector.expect.digest) {
      if (expectedDefects.has("digest_mismatch")) {
        assert.notEqual(digest, vector.expect.digest);
      } else {
        assert.equal(digest, vector.expect.digest);
      }
    }

    if (expectedDefects.has("parent_unverified")) {
      assert.ok(vector.document.previous_passport_digest);
      assert.equal(vector.parents, undefined);
    }

    if (expectedDefects.has("parent_digest_mismatch")) {
      assert.ok(vector.parents?.length);
      const parentDigests = await Promise.all(vector.parents!.map((parent) => digestOf(parent)));
      assert.ok(!parentDigests.includes(String(vector.document.previous_passport_digest)));
    }

    if (expectedDefects.has("attestation_mismatch")) {
      assert.notEqual(digest, vector.expect.attestation_digest);
    }
  });
}

test("canonical bytes sort keys and emit non-ascii as utf8", () => {
  const bytes = canonicalBytes({ z: 1, a: "Аркадий" });
  const text = new TextDecoder().decode(bytes);

  assert.equal(text, '{"a":"Аркадий","z":1}');
  assert.ok(!text.includes("\\u0410"));
});

test("floats and unsafe integers are refused", async () => {
  await assert.rejects(() => digestOf({ risk_score: 96.5 }), NotCanonical);
  await assert.rejects(() => digestOf({ risk_score: 2 ** 53 }), NotCanonical);
});
