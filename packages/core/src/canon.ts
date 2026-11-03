/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Object keys sorted by UTF-16 code units; numbers serialised per ECMAScript Number::toString,
 * which JSON.stringify already does; no whitespace. Undefined properties are dropped (as JSON does).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => (v === undefined ? "null" : canonicalize(v))).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function unb64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
