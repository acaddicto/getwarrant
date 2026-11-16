import { b64url, canonicalize, unb64url, utf8 } from "./canon.ts";
import { signJson, signP256, ulid, verifyJson, type KeyPair } from "./crypto.ts";
import { publicKeyFromKid } from "./keys.ts";
import { verifySignatureEntry, type WebAuthnExpectations } from "./sigverify.ts";
import {
  MANDATE_TYP,
  MAX_DEPTH,
  MAX_MANDATE_LIFETIME_S,
  SPEC_VERSION,
  type KeyResolver,
  type Mandate,
  type MandateDraft,
  type RootAssertion,
  type Signature,
} from "./types.ts";

export interface IssueOptions {
  /** Base URL of the issuer, e.g. https://api.getwarrant.dev */
  issuerBase: string;
  principalKey: KeyPair;
  issuerKey: KeyPair;
  /** Override for reproducible ids. */
  id?: string;
  nowMs?: number;
}

export class MandateError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "MandateError";
  }
}

/** The bytes a signature at sig[index] covers: the mandate with sig[] truncated to entries before index. */
export function signingPayload(m: Mandate, index: number): Omit<Mandate, "sig"> & { sig: Signature[] } {
  return { ...m, sig: m.sig.slice(0, index) };
}

export function mandateId(nowMs?: number): string {
  return "wrt_" + ulid(nowMs);
}

/** Structural rules every mandate must satisfy regardless of who signs it. Returns [] when valid. */
export function validateShape(m: Partial<Mandate>): string[] {
  const errs: string[] = [];
  if (m.typ !== MANDATE_TYP) errs.push("typ must be warrant/mandate");
  if (m.ver !== SPEC_VERSION) errs.push(`ver must be ${SPEC_VERSION}`);
  if (!m.id || !/^wrt_[0-9A-HJKMNP-TV-Z]{26}$/.test(m.id)) errs.push("id must be wrt_ + 26-char ULID");
  if (!m.principal?.root || !m.principal?.sub || !m.principal?.key || !m.principal?.assertion)
    errs.push("principal.root, sub, key and assertion are required");
  if (!m.agent?.did?.startsWith("did:")) errs.push("agent.did must be a DID");
  if (!Array.isArray(m.scope?.may) || m.scope!.may.length === 0) errs.push("scope.may must be a non-empty list");
  if (!Array.isArray(m.scope?.counterparties) || m.scope!.counterparties.length === 0)
    errs.push("scope.counterparties must be a non-empty list");
  const L = m.limits ?? {};
  for (const k of ["total", "per_txn", "confirm_over"] as const) {
    const v = L[k];
    if (v !== undefined && (!Number.isInteger(v) || v < 0)) errs.push(`limits.${k} must be a non-negative integer`);
  }
  if ((L.total !== undefined || L.per_txn !== undefined) && !L.ccy) errs.push("limits.ccy is required when spend limits are set");
  if (L.total !== undefined && L.per_txn !== undefined && L.per_txn > L.total) errs.push("limits.per_txn cannot exceed limits.total");
  if (!m.delegation || m.delegation.attenuate !== true) errs.push("delegation.attenuate must be true");
  if (!m.delegation || !Number.isInteger(m.delegation.max_depth) || m.delegation.max_depth < 0 || m.delegation.max_depth > MAX_DEPTH)
    errs.push(`delegation.max_depth must be an integer 0..${MAX_DEPTH}`);
  if (!Number.isInteger(m.nbf) || !Number.isInteger(m.exp)) errs.push("nbf and exp must be integer seconds");
  else {
    if (m.exp! <= m.nbf!) errs.push("exp must be after nbf");
    if (m.exp! - m.nbf! > MAX_MANDATE_LIFETIME_S) errs.push("mandate lifetime cannot exceed 90 days");
  }
  if (!m.revocation?.startsWith("https://") && !m.revocation?.startsWith("http://localhost")) errs.push("revocation must be an https URL");
  if (!m.ledger?.startsWith("https://") && !m.ledger?.startsWith("http://localhost")) errs.push("ledger must be an https URL");
  if (!Array.isArray(m.sig)) errs.push("sig must be an array");
  return errs;
}

/** Build the unsigned hop-1 mandate the principal will be asked to sign. */
export function buildUnsigned(draft: MandateDraft, opts: { issuerBase: string; id?: string; nowMs?: number }): Mandate {
  const id = opts.id ?? mandateId(opts.nowMs);
  const base = opts.issuerBase.replace(/\/$/, "");
  const unsigned: Mandate = {
    typ: MANDATE_TYP,
    ver: SPEC_VERSION,
    id,
    ...draft,
    revocation: `${base}/r/${id}`,
    ledger: `${base}/l/${id}`,
    sig: [],
  };
  if (unsigned.parent !== undefined) throw new MandateError("malformed", "hop-1 mandates have no parent; use delegate()");
  const errs = validateShape(unsigned);
  if (errs.length) throw new MandateError("malformed", errs.join("; "));
  return unsigned;
}

/**
 * Attach the principal's signature (EdDSA, ES256 or ES256 via WebAuthn) after verifying it against principal.key,
 * then co-sign as issuer over it. This is what an issuer calls when the signature arrives from a browser.
 */
export function coSign(unsigned: Mandate, principalSig: Omit<Signature, "by" | "kid"> & { kid?: string }, issuerKey: KeyPair, expect: WebAuthnExpectations = {}): Mandate {
  if (unsigned.sig.length) throw new MandateError("malformed", "coSign expects an unsigned mandate");
  const sig: Signature = { by: "principal", alg: principalSig.alg, kid: principalSig.kid ?? unsigned.principal.key, value: principalSig.value, ...(principalSig.webauthn ? { webauthn: principalSig.webauthn } : {}) };
  if (sig.kid !== unsigned.principal.key) throw new MandateError("bad_signature", "signature kid must equal principal.key");
  const pk = publicKeyFromKid(sig.kid);
  if (!pk) throw new MandateError("malformed", "principal.key must be key:<ed25519> or p256:<compressed point>");
  if (pk.alg !== sig.alg) throw new MandateError("bad_signature", `principal.key is ${pk.alg}, signature is ${sig.alg}`);
  if (!verifySignatureEntry(sig, signingPayload(unsigned, 0), pk.publicKey, expect)) throw new MandateError("bad_signature", "principal signature does not verify over the mandate");
  const withPrincipal: Mandate = { ...unsigned, sig: [sig] };
  const issuerSig: Signature = { by: "issuer", alg: "EdDSA", kid: issuerKey.kid, value: signJson(signingPayload(withPrincipal, 1), issuerKey.secretKey) };
  return { ...withPrincipal, sig: [sig, issuerSig] };
}

/** Build and sign a hop-1 mandate with a software Ed25519 principal key: principal signs first, issuer co-signs. */
export function issueMandate(draft: MandateDraft, opts: IssueOptions): Mandate {
  const unsigned = buildUnsigned(draft, opts);
  if (unsigned.principal.key !== opts.principalKey.kid) throw new MandateError("malformed", "principal.key must match the signing key id");
  const pk = publicKeyFromKid(opts.principalKey.kid);
  const value = pk?.alg === "ES256" ? signP256(utf8(canonicalize(signingPayload(unsigned, 0))), opts.principalKey.secretKey) : signJson(signingPayload(unsigned, 0), opts.principalKey.secretKey);
  const alg = pk?.alg ?? "EdDSA";
  return coSign(unsigned, { alg, value }, opts.issuerKey);
}

/** Verify every signature in sig[] in order. Returns the index of the first bad one, or -1. */
export function firstBadSignature(m: Mandate, resolve: KeyResolver, expect: WebAuthnExpectations = {}): number {
  if (m.sig.length < 2) return 0;
  if (m.sig[0].by !== "principal" || m.sig[1].by !== "issuer") return 0;
  for (let i = 0; i < m.sig.length; i++) {
    const s = m.sig[i];
    if (i >= 2 && s.by !== "agent") return i;
    if (i >= 1 && s.alg !== "EdDSA") return i; // issuer and agent hops are Ed25519 in v0.1
    const pk = resolve(s.kid);
    if (!pk) return i;
    if (!verifySignatureEntry(s, signingPayload(m, i), pk, i === 0 ? expect : {})) return i;
  }
  return -1;
}

/** Compact wire form: "wrt." + base64url(JCS JSON). */
export function encodeMandate(m: Mandate): string {
  return "wrt." + b64url(utf8(canonicalize(m)));
}

export function decodeMandate(token: string): Mandate {
  if (!token.startsWith("wrt.")) throw new MandateError("malformed", "not a warrant mandate token");
  let m: Mandate;
  try {
    m = JSON.parse(new TextDecoder().decode(unb64url(token.slice(4))));
  } catch {
    throw new MandateError("malformed", "mandate token is not valid base64url JSON");
  }
  const errs = validateShape(m);
  if (errs.length) throw new MandateError("malformed", errs.join("; "));
  return m;
}

// ---- Root assertions -------------------------------------------------------

/** Token form: base64url(JCS assertion) + "." + base64url(signature). */
export function issueRootAssertion(a: RootAssertion, rootKey: KeyPair): string {
  return b64url(utf8(canonicalize(a))) + "." + signJson(a, rootKey.secretKey);
}

export function parseRootAssertion(token: string): { assertion: RootAssertion; signature: string } | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  try {
    const assertion = JSON.parse(new TextDecoder().decode(unb64url(token.slice(0, dot)))) as RootAssertion;
    return { assertion, signature: token.slice(dot + 1) };
  } catch {
    return null;
  }
}

export function verifyRootAssertion(token: string, rootPublicKey: Uint8Array): RootAssertion | null {
  const parsed = parseRootAssertion(token);
  if (!parsed) return null;
  return verifyJson(parsed.signature, parsed.assertion, rootPublicKey) ? parsed.assertion : null;
}
