export class NotCanonical extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotCanonical";
  }
}

const MAX_EXACT_INT = Number.MAX_SAFE_INTEGER;

function compareByCodePoint(left: string, right: string): number {
  const a = Array.from(left);
  const b = Array.from(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const delta = a[index].codePointAt(0)! - b[index].codePointAt(0)!;
    if (delta !== 0) return delta;
  }
  return a.length - b.length;
}

function checkCanonical(value: unknown, path = "$"): void {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new NotCanonical(`${path}: floats are refused`);
    }
    if (!Number.isSafeInteger(value)) {
      throw new NotCanonical(
        `${path}: ${value} is outside +/-${MAX_EXACT_INT}; use a string`,
      );
    }
    return;
  }
  if (typeof value === "bigint") {
    throw new NotCanonical(`${path}: bigint has no JSON form; use a string`);
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkCanonical(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      checkCanonical(item, `${path}.${key}`);
    }
    return;
  }
  throw new NotCanonical(`${path}: ${typeof value} has no canonical JSON form`);
}

function canonicalString(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalString(item)).join(",")}]`;
  }
  const object = value as Record<string, unknown>;
  const members = Object.keys(object)
    .sort(compareByCodePoint)
    .map((key) => `${JSON.stringify(key)}:${canonicalString(object[key])}`);
  return `{${members.join(",")}}`;
}

export function canonicalBytes(document: Record<string, unknown>): Uint8Array {
  checkCanonical(document);
  return new TextEncoder().encode(canonicalString(document));
}

export async function digestOf(document: Record<string, unknown>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", canonicalBytes(document));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
