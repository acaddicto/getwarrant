import { signJson, verifyJson, type KeyPair } from "./crypto.ts";
import { DEFAULT_STATUS_TTL_S, MAX_STATUS_TTL_S, type MandateStatus, type SignedStatus } from "./types.ts";

/** Issuer side: sign a status response. Caps ttl at the spec maximum. */
export function issueStatus(status: Omit<MandateStatus, "ttl"> & { ttl?: number }, issuerKey: KeyPair): SignedStatus {
  const s: MandateStatus = { ...status, ttl: Math.min(status.ttl ?? DEFAULT_STATUS_TTL_S, MAX_STATUS_TTL_S) };
  return { status: s, kid: issuerKey.kid, sig: signJson(s, issuerKey.secretKey) };
}

export function verifyStatusSignature(s: SignedStatus, issuerPublicKey: Uint8Array): boolean {
  return verifyJson(s.sig, s.status, issuerPublicKey);
}
