import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { b64url, canonicalize, hex, unb64url, utf8 } from "./canon.ts";

// noble/ed25519 v3 needs sha512 wired in for the synchronous API.
ed.hashes.sha512 = sha512;

export interface KeyPair {
  kid: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateKeyPair(kid: string): KeyPair {
  const { secretKey, publicKey } = ed.keygen();
  return { kid, publicKey, secretKey };
}

export function keyPairFromSecret(kid: string, secretKey: Uint8Array): KeyPair {
  return { kid, secretKey, publicKey: ed.getPublicKey(secretKey) };
}

export function sign(message: Uint8Array, secretKey: Uint8Array): string {
  return b64url(ed.sign(message, secretKey));
}

export function verify(signature: string, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed.verify(unb64url(signature), message, publicKey);
  } catch {
    return false;
  }
}

/** Sign the JCS form of any JSON value. */
export function signJson(value: unknown, secretKey: Uint8Array): string {
  return sign(utf8(canonicalize(value)), secretKey);
}

export function verifyJson(signature: string, value: unknown, publicKey: Uint8Array): boolean {
  return verify(signature, utf8(canonicalize(value)), publicKey);
}

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return hex(sha256(bytes));
}

/** SHA-256 over the JCS form of a JSON value; used for action hashes and ledger chaining. */
export function hashJson(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 26-character ULID. `nowMs` and `random` are injectable so test vectors are reproducible. */
export function ulid(nowMs = Date.now(), random: () => number = Math.random): string {
  let t = nowMs;
  let time = "";
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  let rand = "";
  for (let i = 0; i < 16; i++) rand += CROCKFORD[Math.floor(random() * 32)];
  return time + rand;
}
