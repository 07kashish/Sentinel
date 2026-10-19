// An independent Execution Passport verifier.
//
// WHY THIS EXISTS
// ---------------
// The Python implementation and the conformance corpus were written by the
// same hand, so the corpus passing against Python proves Python is
// self-consistent and nothing else. An ambiguity in the specification only
// surfaces when a second implementation, written from the document rather than
// from the code, disagrees.
//
// NO DEPENDENCIES, DELIBERATELY
// -----------------------------
// Node's built-in `crypto` only. An auditor should not have to install a
// package tree to check a passport -- every package is something else to trust,
// and the point of the format is that verification requires trusting nobody.
// There is also no TypeScript build step, for the same reason: a verifier you
// have to compile is a verifier you have to trust a compiler for.
//
// THE CANONICAL FORM IS REIMPLEMENTED, NOT PORTED
// ------------------------------------------------
// `JSON.stringify` does not sort keys and escapes nothing by default, so it is
// wrong in one direction and right in the other. The serialiser below sorts by
// code point, refuses floats, and emits UTF-8 unescaped -- written from
// README.md section 1, which is how the two implementations end up being a
// test of the specification rather than of each other.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const REQUIRED_FIELDS = [
  'execution_id',
  'tenant_id',
  'occurred_at',
  'agent_id',
  'action',
  'decision',
];

class CanonicalError extends Error {}

// §1 step 1: refuse anything JSON does not represent identically everywhere.
function checkCanonical(value, path = '$') {
  if (typeof value === 'number') {
    // JS has ONE number type, so "is this a float" is a question about the
    // value rather than the type. A non-integer, or anything outside the safe
    // integer range, cannot be relied on to round-trip -- and 2^53 is exactly
    // where JSON parsers start disagreeing with each other.
    if (!Number.isInteger(value)) {
      throw new CanonicalError(
        `${path}: floats are refused. 0.1 + 0.2 does not round-trip, so a ` +
        `score serialising as 96.00000000000001 here and 96.0 elsewhere ` +
        `would produce two signatures for one passport. Use an integer.`
      );
    }
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalError(
        `${path}: ${value} is outside the range integers survive a JSON ` +
        `round trip in. Beyond 2^53 parsers disagree with each other.`
      );
    }
    return;
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkCanonical(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === 'object') {
    for (const key of Object.keys(value)) {
      if (typeof key !== 'string') {
        throw new CanonicalError(`${path}: object keys must be strings`);
      }
      checkCanonical(value[key], `${path}.${key}`);
    }
    return;
  }
  throw new CanonicalError(
    `${path}: ${typeof value} has no canonical JSON form. Convert it at the ` +
    `edge, where the conversion is visible.`
  );
}

// §1 steps 2-4. Not JSON.stringify with a replacer: a replacer cannot control
// key order for nested objects reliably across engines, and key order is the
// entire point.
function canonicalString(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalString).join(',') + ']';
  }
  // Sort by code point. `Array.prototype.sort` on strings already compares by
  // UTF-16 code unit, which differs from code point only for astral-plane
  // characters; comparing explicitly avoids depending on that distinction.
  const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const members = keys.map(
    (key) => JSON.stringify(key) + ':' + canonicalString(value[key])
  );
  return '{' + members.join(',') + '}';
}

export function canonicalBytes(document) {
  checkCanonical(document);
  return Buffer.from(canonicalString(document), 'utf8');
}

export function digestOf(document) {
  return createHash('sha256').update(canonicalBytes(document)).digest('hex');
}

// §3. Every optional input absent yields an explicit unverified finding.
export function verify(document, options = {}) {
  const { claimedDigest, publicKeyPem, parents, expectedPolicyDigest,
          attestationDigest } = options;
  const defects = [];
  let computed = null;

  try {
    computed = digestOf(document);
  } catch (error) {
    if (error instanceof CanonicalError) {
      defects.push({ code: 'not_canonical', detail: error.message });
      return { defects, digest: null, verified: false };
    }
    throw error;
  }

  if (claimedDigest && claimedDigest !== computed) {
    defects.push({
      code: 'digest_mismatch',
      detail:
        `the supplied document does not canonicalise to the digest it claims: ` +
        `claimed ${claimedDigest.slice(0, 16)}…, computed ${computed.slice(0, 16)}…`,
    });
  }

  for (const field of REQUIRED_FIELDS) {
    const value = document[field];
    if (value === undefined || value === null || String(value).trim() === '') {
      defects.push({
        code: 'missing_required_field',
        detail: `${field} is absent or empty, so this document records ` +
                `something rather than attributing it`,
      });
    }
  }

  if (!publicKeyPem) {
    defects.push({
      code: 'signature_unverified',
      detail: 'no public key was supplied, so the signature was NOT checked. ' +
              'This is not a pass.',
    });
  }

  const commitment = document.previous_passport_digest || '';
  if (commitment) {
    if (!parents) {
      defects.push({
        code: 'parent_unverified',
        detail: `this passport commits to parent digest ` +
                `${commitment.slice(0, 16)}… and no parents were supplied`,
      });
    } else {
      const found = parents.find((parent) => {
        try {
          return digestOf(parent) === commitment;
        } catch {
          return false;
        }
      });
      if (!found) {
        defects.push({
          code: 'parent_digest_mismatch',
          detail: `no supplied parent has digest ${commitment.slice(0, 16)}…`,
        });
      }
    }
  }

  if (expectedPolicyDigest) {
    if ((document.policy_digest || '') !== expectedPolicyDigest) {
      defects.push({
        code: 'policy_digest_mismatch',
        detail: 'the policy digest does not match the policy named',
      });
    }
  } else {
    defects.push({
      code: 'policy_unverified',
      detail: 'no expected policy digest was supplied, so the policy this ' +
              'decision claims to follow was NOT checked',
    });
  }

  if (attestationDigest && attestationDigest !== computed) {
    defects.push({
      code: 'attestation_mismatch',
      detail: 'the attestation names a digest other than this passport\'s',
    });
  }

  return { defects, digest: computed, verified: defects.length === 0 };
}

// ── the conformance runner ─────────────────────────────────────────────────

function loadVectors(directory) {
  const found = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      found.push(...loadVectors(path));
    } else if (entry.endsWith('.json')) {
      found.push({ path, ...JSON.parse(readFileSync(path, 'utf8')) });
    }
  }
  return found;
}

function main(argv) {
  const index = argv.indexOf('--vectors');
  if (index === -1) {
    console.error('usage: node verify.mjs --vectors <directory>');
    return 2;
  }
  const vectors = loadVectors(argv[index + 1]);
  if (vectors.length === 0) {
    // An empty corpus passing is the failure this guards against: a runner
    // that finds nothing and exits 0 reads exactly like one that checked
    // everything.
    console.error('no vectors found; refusing to report success over an empty corpus');
    return 2;
  }

  let failures = 0;
  for (const vector of vectors) {
    const result = verify(vector.document, {
      claimedDigest: vector.expect?.digest,
      parents: vector.parents,
      attestationDigest: vector.expect?.attestation_digest,
    });
    const seen = new Set(result.defects.map((d) => d.code));
    const wanted = new Set(vector.expect?.defects ?? []);
    const missing = [...wanted].filter((code) => !seen.has(code));
    const unexpected = [...seen].filter(
      (code) => !wanted.has(code) && !(vector.expect?.tolerate ?? []).includes(code)
    );
    if (missing.length || unexpected.length) {
      failures += 1;
      console.error(`FAIL ${vector.name}`);
      if (missing.length) console.error(`  expected but absent: ${missing.join(', ')}`);
      if (unexpected.length) console.error(`  unexpected: ${unexpected.join(', ')}`);
    } else {
      console.log(`ok   ${vector.name}`);
    }
  }

  console.log(`\n${vectors.length - failures}/${vectors.length} vectors agreed`);
  return failures === 0 ? 0 : 1;
}

// `pathToFileURL`, not a hand-built `file://` string.
//
// The hand-built version was `file://${argv[1].replace(/\\/g, '/')}`, which on
// Windows produces `file://F:/...` against an `import.meta.url` of
// `file:///F:/...` -- three slashes and a drive letter. The guard never
// matched, so the runner executed nothing and exited 0: silence that reads
// exactly like a clean run over the whole corpus.
// `process.argv[1]` is UNDEFINED when this file is imported as a library
// rather than run as a script -- via `node -e "import(...)"`, or by any
// consumer that wants `verify` and not the CLI. Calling `pathToFileURL` on it
// then throws, so the module could not be imported at all: the second half of
// what this file is for, broken by the guard on the first half.
const invokedAs = process.argv[1];
if (invokedAs && import.meta.url === pathToFileURL(invokedAs).href) {
  process.exit(main(process.argv.slice(2)));
}
