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

// ---- P-256 / ES256 (passkeys) ------------------------------------------------
import { p256 } from "@noble/curves/nist.js";

export function generateP256KeyPair(kid: string): KeyPair {
  const secretKey = p256.utils.randomSecretKey();
  return { kid, secretKey, publicKey: p256.getPublicKey(secretKey, true) };
}

export function p256KeyPairFromSecret(kid: string, secretKey: Uint8Array): KeyPair {
  return { kid, secretKey, publicKey: p256.getPublicKey(secretKey, true) };
}

/** ECDSA P-256 over SHA-256(message); raw r||s, base64url. */
export function signP256(message: Uint8Array, secretKey: Uint8Array): string {
  return b64url(p256.sign(message, secretKey, { prehash: true }));
}

/** Accepts raw r||s (64 bytes) or ASN.1 DER (what browsers' WebAuthn returns). */
export function verifyP256(signature: string | Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    let sig = typeof signature === "string" ? unb64url(signature) : signature;
    if (sig.length !== 64) sig = derToRaw(sig);
    // WebAuthn authenticators do not normalise S; accept high-S signatures (lowS: false), unlike noble's default.
    return p256.verify(sig, message, publicKey, { prehash: true, lowS: false });
  } catch {
    return false;
  }
}

/** ASN.1 DER ECDSA-Sig-Value → raw r||s (32 + 32 bytes). */
export function derToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error("not a DER sequence");
  let i = 2;
  if (der[1] & 0x80) i += der[1] & 0x7f;
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error("expected INTEGER");
    let len = der[i++];
    if (len & 0x80) { const n = len & 0x7f; len = 0; for (let k = 0; k < n; k++) len = (len << 8) | der[i++]; }
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error("integer too long");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt(), s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0); raw.set(s, 32);
  return raw;
}

/** SubjectPublicKeyInfo (as returned by AuthenticatorAttestationResponse.getPublicKey()) → compressed P-256 point. */
export function p256FromSpki(spki: Uint8Array): Uint8Array {
  // P-256 SPKI is 91 bytes: 26-byte header then 0x04 || X || Y.
  const i = spki.indexOf(0x04, spki.length - 65 > 0 ? spki.length - 65 : 0);
  const point = spki.slice(i, i + 65);
  if (point.length !== 65 || point[0] !== 0x04) throw new Error("not a P-256 SPKI");
  return p256.Point.fromBytes(point).toBytes(true);
}
