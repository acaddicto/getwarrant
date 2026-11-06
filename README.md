# Warrant

Signed, scoped, revocable authority for AI agents.

A **mandate** is a letter of authority a human or organisation hands an agent: what it may do, what it may not, how much it may spend, until when, and whether it may hand work to other agents. Any API, merchant or agent that receives an action can verify the mandate in one call and gets back `allow`, `confirm` or `deny`. Every decision lands in a hash-chained ledger.

Warrant sits between agent identity (DIDs) and payment rails (AP2, Agent Pay). It does not verify humans; it binds to whoever already has (EU wallet, Aadhaar, a KYC vendor, your IdP).

```
principal ──signs──▶ mandate ──▶ agent ──sub-mandate──▶ sub-agent ──presents chain──▶ counterparty ──verify──▶ allow | confirm | deny
```

## Packages

| Package | What |
| --- | --- |
| [`packages/core`](packages/core) | `@getwarrant/core` — issue, delegate, verify, ledger. Pure TypeScript, Ed25519, no network. |
| [`packages/issuer`](packages/issuer) | The hosted issuer: consent flow, co-signing, status, revocation, ledger, confirms, hosted verifier. Supabase Edge Function + Postgres. Live at `https://vvnvwrefyrrapjhmpajr.supabase.co/functions/v1/warrant`. |
| [`packages/node`](packages/node) | `@getwarrant/node` — Verifier client, Express middleware, MCP tool guard, AgentClient. |
| [`packages/python`](packages/python) | `warrant-fastapi` — FastAPI dependency over the hosted verifier. |
| [`demo`](demo) | Tripwise books a trip: Express airline, FastAPI hotel, two agents, a scripted principal, the live issuer. |
| `vectors/` | Conformance vectors: mandates, chains, actions, statuses and the verdict a verifier MUST return. |

Spec: *Warrant Protocol Specification v0.1* (to be published as `SPEC.md`).

## Wire format for counterparties

```
Warrant-Mandate:           <hop-1 token>[,<sub-mandate token>...]
Warrant-Action-Signature:  <kid>:<base64url Ed25519 signature over SHA-256(JCS(request body))>
Warrant-Confirm:           <confirm ref>     only when repeating an action the principal has confirmed
```

Responses: `200` and the route runs on `allow`; `202 { confirm_ref, poll }` on `confirm`; `403 { error: <reason>, checks }` on `deny`. The reasons are the spec's: `bad_signature`, `bad_chain`, `principal_unverified`, `revoked`, `expired`, `stale`, `widened`, `out_of_scope`, `over_limit`.

## Quick look

```ts
import { generateKeyPair, issueRootAssertion, issueMandate, delegate, issueStatus, signAction, verifyAction } from "@getwarrant/core";

// Keys: the principal's passkey, the issuer, an identity root, two agents.
const principal = generateKeyPair("passkey:c2a7");
const issuer    = generateKeyPair("did:web:warrant.example#k1");
const root      = generateKeyPair("eudi-wallet:signer-1");
const tripwise  = generateKeyPair("did:web:agents.tripwise.com#k1");
const farescout = generateKeyPair("did:web:farescout.ai#k1");

// 1. The principal consents; the issuer co-signs.
const now = Math.floor(Date.now() / 1000);
const assertion = issueRootAssertion({ root: "eudi-wallet", sub: "pw_7f31", aud: "did:web:warrant.example", level: "high", iat: now, exp: now + 86400 * 365 }, root);
const mandate = issueMandate({
  principal: { root: "eudi-wallet", sub: "pw_7f31", key: principal.kid, assertion },
  agent: { did: "did:web:agents.tripwise.com" },
  scope: { may: ["travel:search", "travel:book_flight", "travel:book_hotel"], may_not: ["payments:change_method"], counterparties: ["iata:*", "api:booking.com"] },
  limits: { ccy: "USD", total: 150000, per_txn: 60000, confirm_over: 50000 },
  delegation: { max_depth: 2, attenuate: true },
  nbf: now, exp: now + 7 * 86400,
}, { issuerBase: "https://warrant.example", principalKey: principal, issuerKey: issuer });

// 2. Tripwise hands flight booking to FareScout, narrower on every axis.
const sub = delegate(mandate, { agentKey: tripwise, child: {
  agent: { did: "did:web:farescout.ai" },
  scope: { may: ["travel:book_flight"], may_not: ["payments:change_method"], counterparties: ["iata:*"] },
  limits: { ccy: "USD", total: 60000, per_txn: 60000, confirm_over: 50000 },
}});

// 3. An airline verifies FareScout's $478 booking.
const hash = "…sha256 of the cart…";
const verdict = verifyAction(
  { chain: [mandate, sub], action: { type: "travel:book_flight", amount: 47800, ccy: "USD", counterparty: "iata:SQ", hash, ...signAction(hash, farescout) }, status: issueStatus({ id: mandate.id, status: "active", spent: 0, asof: now }, issuer) },
  { now, keys: kid => ({ [principal.kid]: principal, [issuer.kid]: issuer, [tripwise.kid]: tripwise, [farescout.kid]: farescout })[kid]?.publicKey, trustedRoots: { "eudi-wallet": { publicKey: root.publicKey } } },
);
verdict.decision; // "allow"
```

Lower `per_txn` to 40000 before issuing and the same booking returns `deny · over_limit`. Raise the amount to 54000 and it returns `confirm`.

## Status

v0.1, pre-release. The API will change. Nothing here has been audited.

## Licence

Apache-2.0.
