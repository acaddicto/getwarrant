/**
 * The Tripwise scenario from the spec, built deterministically so the same fixture
 * backs the tests and the published test vectors.
 */
import { keyPairFromSecret, type KeyPair } from "../src/crypto.js";
import { issueMandate, issueRootAssertion } from "../src/mandate.js";
import { delegate } from "../src/delegate.js";
import { issueStatus } from "../src/status.js";
import { signAction } from "../src/verify.js";
import type { Action, KeyResolver, Mandate, MandateDraft, SignedStatus } from "../src/types.js";

// Deterministic 32-byte seeds (test only — never reuse).
const seed = (n: number) => new Uint8Array(32).map((_, i) => (i * 7 + n * 13) % 256);

export const ISSUER_ID = "did:web:warrant.example";
export const ROOT_ID = "eudi-wallet";
export const T0 = 1793613000; // 2026-11-02T07:50:00Z
export const T0_MS = T0 * 1000;

export const keys = {
  principal: keyPairFromSecret("passkey:c2a7", seed(1)),
  issuer: keyPairFromSecret(`${ISSUER_ID}#k1`, seed(2)),
  root: keyPairFromSecret("eudi-wallet:signer-1", seed(3)),
  tripwise: keyPairFromSecret("did:web:agents.tripwise.com#k1", seed(4)),
  farescout: keyPairFromSecret("did:web:farescout.ai#k1", seed(5)),
  rogue: keyPairFromSecret("did:web:rogue.example#k1", seed(6)),
  airline: keyPairFromSecret("did:web:singaporeair.com#verifier", seed(7)),
};

export const resolver: KeyResolver = (kid) => Object.values(keys).find((k: KeyPair) => k.kid === kid)?.publicKey;

export const assertion = issueRootAssertion(
  { root: ROOT_ID, sub: "pw_7f31c2a9", aud: ISSUER_ID, level: "high", iat: T0 - 86400 * 49, exp: T0 + 86400 * 365 },
  keys.root,
);

export const draft: MandateDraft = {
  principal: { root: ROOT_ID, sub: "pw_7f31c2a9", key: keys.principal.kid, assertion },
  agent: { did: "did:web:agents.tripwise.com", runtime: "attest:2026.11.1" },
  scope: {
    may: ["travel:search", "travel:book_flight", "travel:book_hotel", "travel:cancel_own_booking"],
    may_not: ["payments:change_method", "travel:book_for_others", "identity:share_documents"],
    counterparties: ["iata:*", "api:booking.com", "api:expedia.com"],
  },
  limits: { ccy: "USD", total: 150000, per_txn: 60000, confirm_over: 50000, confirm_on: ["travel:cancel_own_booking"] },
  delegation: { max_depth: 2, attenuate: true },
  nbf: T0,
  exp: T0 + 7 * 86400,
};

// Crockford base32 has no I, L, O, U.
export const TRIPWISE_ID = "wrt_01JBQ8Z7K4TRPWSE0000000000";
export const FARESCOUT_ID = "wrt_01JBQ9F3M2FARESCT000000000";

export function buildTripwise(): Mandate {
  return issueMandate(draft, { issuerBase: "https://warrant.example", principalKey: keys.principal, issuerKey: keys.issuer, id: TRIPWISE_ID });
}

export function buildFarescout(parent: Mandate): Mandate {
  return delegate(parent, {
    agentKey: keys.tripwise,
    id: FARESCOUT_ID,
    nowMs: T0_MS + 60_000,
    child: {
      agent: { did: "did:web:farescout.ai" },
      scope: { may: ["travel:book_flight"], may_not: draft.scope.may_not, counterparties: ["iata:*"] },
      limits: { ccy: "USD", total: 60000, per_txn: 60000, confirm_over: 50000, confirm_on: draft.limits.confirm_on },
    },
  });
}

export function status(over: Partial<SignedStatus["status"]> = {}, asof = T0 + 120): SignedStatus {
  return issueStatus({ id: TRIPWISE_ID, status: "active", spent: 0, asof, ttl: 30, ...over }, keys.issuer);
}

export function action(partial: Partial<Action> & { by?: KeyPair } = {}): Action {
  const by = partial.by ?? keys.farescout;
  const hash = partial.hash ?? "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce";
  const { kid, sig } = signAction(hash, by);
  const { by: _omit, ...rest } = partial;
  return { type: "travel:book_flight", amount: 47800, ccy: "USD", counterparty: "iata:SQ", hash, kid, sig, ...rest };
}

export const NOW = T0 + 130;
export const trustedRoots = { [ROOT_ID]: { publicKey: keys.root.publicKey } };
