import { canonicalBytes, digestOf } from "./canonical.ts";

export type PassportFinding = { code: string; detail: string };

type SignedPassport = {
  passport?: Record<string, unknown>;
  signature?: {
    algorithm?: string;
    key_id?: string;
    signed_at?: string;
    value?: string;
  };
};

function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function verifyPassport(
  payload: SignedPassport,
  key: { key_id: string; public_key: string },
): Promise<{ digest: string | null; findings: PassportFinding[]; verified: boolean }> {
  const findings: PassportFinding[] = [];
  const document = payload.passport;
  const signature = payload.signature;
  if (!document || !signature) {
    return {
      digest: null,
      findings: [{ code: "malformed_envelope", detail: "expected passport and signature" }],
      verified: false,
    };
  }
  if (signature.algorithm !== "ed25519") {
    return {
      digest: null,
      findings: [{ code: "unsupported_algorithm", detail: "expected ed25519" }],
      verified: false,
    };
  }
  if (signature.key_id !== key.key_id) {
    return {
      digest: null,
      findings: [{ code: "wrong_key", detail: "signature key_id does not match" }],
      verified: false,
    };
  }

  let digest: string;
  try {
    digest = await digestOf(document);
  } catch (error) {
    return {
      digest: null,
      findings: [{ code: "uncanonical_document", detail: String(error) }],
      verified: false,
    };
  }

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      fromBase64(key.public_key),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      cryptoKey,
      fromBase64(signature.value ?? ""),
      canonicalBytes(document),
    );
    if (!ok) findings.push({ code: "modified", detail: "signature does not verify" });
  } catch (error) {
    findings.push({ code: "malformed_signature", detail: String(error) });
  }

  return { digest, findings, verified: findings.length === 0 };
}
