/**
 * Warrant protocol v0.1 — core types.
 * Field names and semantics follow the Warrant Protocol Specification.
 * Amounts are integers in minor units (cents, paise). Times are Unix seconds unless named *Ms.
 */

export const SPEC_VERSION = "0.1";
export const MANDATE_TYP = "warrant/mandate";
export const MAX_MANDATE_LIFETIME_S = 90 * 24 * 3600;
export const MAX_DEPTH = 4;
export const MAX_STATUS_TTL_S = 300;
export const DEFAULT_STATUS_TTL_S = 30;
export const CLOCK_SKEW_S = 60;
export const CONFIRM_TIMEOUT_S = 15 * 60;

export type AssuranceLevel = "low" | "substantial" | "high";

export interface Principal {
  /** Identity root identifier, e.g. "eudi-wallet", "aadhaar", "okta:acme.com", "passkey-only". */
  root: string;
  /** Pairwise pseudonymous subject from the root. Never a raw national ID. */
  sub: string;
  /** Key id that signs hop 0 (principal signature). */
  key: string;
  /** Opaque, root-signed assertion that `sub` was verified. Encoded as a RootAssertion token. */
  assertion: string;
  /** Present when the principal is an organisation acting through an employee. */
  org?: { id: string; role: string };
}

export interface AgentRef {
  did: string;
  runtime?: string;
}

export interface Scope {
  may: string[];
  may_not?: string[];
  counterparties: string[];
}

export interface Limits {
  ccy?: string;
  total?: number;
  per_txn?: number;
  confirm_over?: number;
  confirm_on?: string[];
  /** e.g. "20/1h". Enforced by the verifier only when a rate window is supplied. */
  rate?: string;
}

export interface Delegation {
  max_depth: number;
  attenuate: true;
}

export type SignerRole = "principal" | "issuer" | "agent";

export interface Signature {
  by: SignerRole;
  alg: "EdDSA";
  kid: string;
  /** Agent hops only. */
  did?: string;
  /** Agent hops only: when the hop signed. */
  iat?: number;
  /** base64url Ed25519 signature over the JCS payload with sig[] truncated to the entries before this one. */
  value: string;
}

export interface Mandate {
  typ: typeof MANDATE_TYP;
  ver: string;
  id: string;
  parent?: string;
  principal: Principal;
  agent: AgentRef;
  scope: Scope;
  limits: Limits;
  delegation: Delegation;
  nbf: number;
  exp: number;
  revocation: string;
  ledger: string;
  sig: Signature[];
}

/** Everything the principal consents to. The issuer fills id, sig and service URLs. */
export type MandateDraft = Omit<Mandate, "typ" | "ver" | "id" | "sig" | "revocation" | "ledger">;

/** What a root asserts about a principal. Signed by the root's key. */
export interface RootAssertion {
  root: string;
  sub: string;
  /** The issuer this pairwise subject is scoped to. */
  aud: string;
  level: AssuranceLevel;
  iat: number;
  exp: number;
}

export type MandateStatusValue = "active" | "revoked" | "expired" | "suspended";

export interface MandateStatus {
  id: string;
  status: MandateStatusValue;
  /** Running spend across the whole tree, minor units. */
  spent: number;
  asof: number;
  ttl: number;
  reason?: string;
}

export interface Action {
  type: string;
  amount?: number;
  ccy?: string;
  counterparty: string;
  /** SHA-256 hex of the counterparty's canonical description of the action. */
  hash: string;
  /** Key id of the acting agent's signing key; MUST be a fragment of the acting mandate's agent DID. */
  kid: string;
  /** base64url Ed25519 signature by the acting agent over the UTF-8 bytes of `hash`. */
  sig: string;
}

export interface SignedStatus {
  status: MandateStatus;
  kid: string;
  sig: string;
}

export type Decision = "allow" | "confirm" | "deny";

export type DenyReason =
  | "bad_signature"
  | "bad_chain"
  | "principal_unverified"
  | "revoked"
  | "expired"
  | "stale"
  | "not_yet_valid"
  | "widened"
  | "out_of_scope"
  | "over_limit"
  | "malformed";

export interface CheckResult {
  step: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  name: string;
  ok: boolean;
  detail: string;
}

export interface Verdict {
  decision: Decision;
  mandate: string;
  root: string;
  hop: number;
  reason: DenyReason | null;
  checks: CheckResult[];
  /** Effective (intersected) scope and limits at the acting hop. */
  effective?: { scope: Scope; limits: Limits; nbf: number; exp: number };
  ttl: number;
}

export interface LedgerRecord {
  ref: string;
  prev: string | null;
  mandate: { id: string; root: string };
  hop: number;
  agent: string;
  counterparty: string;
  action: { type: string; amount?: number; ccy?: string; hash: string };
  decision: Decision;
  reason: DenyReason | null;
  confirm?: { ref: string; reply?: "allow" | "deny"; at?: number };
  status_asof: number;
  at: number;
  sig: { agent: string; verifier?: string; issuer?: string };
}

/** Resolves a key id (or DID key fragment) to a raw Ed25519 public key. */
export type KeyResolver = (kid: string) => Uint8Array | undefined;
