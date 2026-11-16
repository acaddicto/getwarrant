import { canonicalize, unb64url, utf8, fromUtf8, b64url, hex } from "./canon.ts";
import { verifyJson, verifyP256, sha256Hex } from "./crypto.ts";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Signature } from "./types.ts";

export interface WebAuthnExpectations {
  /** e.g. "https://issuer.example"; checked against clientDataJSON.origin when given. */
  origin?: string;
  /** Relying party id, e.g. "issuer.example"; its SHA-256 is checked against authenticatorData[0..32] when given. */
  rpId?: string;
}

/** The WebAuthn challenge for a payload: base64url(SHA-256(JCS(payload))). */
export function webauthnChallenge(payload: unknown): string {
  return b64url(sha256(utf8(canonicalize(payload))));
}

/**
 * Verify one Signature entry over `payload` with `publicKey`, by its alg:
 *  - EdDSA: Ed25519 over JCS(payload)
 *  - ES256 (plain): ECDSA P-256 / SHA-256 over JCS(payload)
 *  - ES256 (webauthn): challenge binding + ECDSA over authenticatorData || SHA-256(clientDataJSON)
 */
export function verifySignatureEntry(sig: Signature, payload: unknown, publicKey: Uint8Array, expect: WebAuthnExpectations = {}): boolean {
  if (sig.alg === "EdDSA") return !sig.webauthn && verifyJson(sig.value, payload, publicKey);
  if (sig.alg !== "ES256") return false;
  if (!sig.webauthn) return verifyP256(sig.value, utf8(canonicalize(payload)), publicKey);
  try {
    const authData = unb64url(sig.webauthn.authenticatorData);
    const cdjBytes = unb64url(sig.webauthn.clientDataJSON);
    const cdj = JSON.parse(fromUtf8(cdjBytes)) as { type?: string; challenge?: string; origin?: string };
    if (cdj.type !== "webauthn.get") return false;
    if (cdj.challenge !== webauthnChallenge(payload)) return false;
    if (expect.origin && cdj.origin !== expect.origin) return false;
    if (authData.length < 37) return false;
    if ((authData[32] & 0x01) === 0) return false; // user present
    if (expect.rpId && sha256Hex(utf8(expect.rpId)) !== hex(authData.slice(0, 32))) return false;
    const message = new Uint8Array(authData.length + 32);
    message.set(authData, 0);
    message.set(sha256(cdjBytes), authData.length);
    return verifyP256(sig.value, message, publicKey);
  } catch {
    return false;
  }
}
