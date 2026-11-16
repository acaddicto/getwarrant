import { unb64url } from "./canon.ts";
import type { SigAlg } from "./types.ts";

/**
 * Self-describing key ids for principals (counterparties have no directory for them):
 *   key:<base64url 32-byte Ed25519 public key>      → EdDSA
 *   p256:<base64url 33-byte compressed P-256 point> → ES256 (passkeys)
 * Agent and issuer key ids are DID fragments resolved through the issuer or a DID document.
 */
export function publicKeyFromKid(kid: string): { alg: SigAlg; publicKey: Uint8Array } | undefined {
  try {
    if (kid.startsWith("key:")) {
      const b = unb64url(kid.slice(4));
      return b.length === 32 ? { alg: "EdDSA", publicKey: b } : undefined;
    }
    if (kid.startsWith("p256:")) {
      const b = unb64url(kid.slice(5));
      return b.length === 33 && (b[0] === 2 || b[0] === 3) ? { alg: "ES256", publicKey: b } : undefined;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export const kidForEd25519 = (publicKey: Uint8Array, b64url: (b: Uint8Array) => string) => "key:" + b64url(publicKey);
export const kidForP256 = (publicKey: Uint8Array, b64url: (b: Uint8Array) => string) => "p256:" + b64url(publicKey);
