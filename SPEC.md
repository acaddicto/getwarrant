# Warrant Protocol Specification

Draft v0.1 · 10 Nov 2026 · Ashan Clent · the editable original lives as a Claude doc; this file is its export.

## Status and scope

Draft v0.1, implemented in [acaddicto/getwarrant](https://github.com/acaddicto/getwarrant) (core library, hosted issuer, Node and FastAPI drop-ins, demo). This spec defines how a human or organisation grants an AI agent a signed, scoped, revocable authority to act, and how any counterparty verifies that authority before acting on it. It is written so that a third party can implement an issuer, a verifier or an agent SDK from it alone.

In scope:

- The mandate object: fields, encoding, signatures.
- Delegation from agent to sub-agent, and the attenuation rule that governs it.
- Revocation and how a verifier learns of it.
- The verifier decision: allow, confirm, deny.
- The ledger record each verified action produces.
- Binding a mandate to a verified human or organisation through an external identity root.

Out of scope, left to the layers Warrant sits on:

- Agent identity itself. Agents are identified by W3C DIDs; key management and DID resolution follow the DID Core spec.
- Payment settlement. A mandate authorises spend; a payment network moves money. Warrant mandates are designed to be presented alongside an AP2 cart mandate or a Mastercard Agent Pay token, not to replace them.
- Human identity proofing. Warrant consumes an identity assertion from a root (EU Digital Identity Wallet, Aadhaar, a KYC vendor, an enterprise IdP); it never performs KYC.
- Agent-to-agent transport. Mandates travel as a header or field inside A2A, MCP or plain HTTPS.

The prototype at [Warrant Prototype](https://claude.ai/artifact/VC73wcB5PkP7zJytrynZJR) shows the consent, ledger and verifier flows this spec formalises.

Keywords MUST, SHOULD and MAY are used as in RFC 2119.

## Terms

| Term | Meaning |
| --- | --- |
| Principal | The human or organisation on whose behalf an agent acts and who is accountable for its actions. Identified through an identity root. |
| Agent | Software that acts for a principal. Identified by a DID and a signing key. |
| Operator | The organisation that runs an agent. Named in the agent's DID document. |
| Mandate | A signed statement by a principal that a named agent may perform a bounded set of actions, within limits, until an expiry. The unit this spec defines. |
| Scope | The `may`, `may_not` and `counterparties` lists of a mandate. |
| Limits | Numeric and categorical ceilings on a mandate: total spend, per-transaction spend, confirm thresholds, rate. |
| Hop | One link in a delegation chain. Hop 0 is the principal's signature over the mandate; hop 1 is the first agent; hop n is a sub-agent. |
| Sub-mandate | A mandate an agent issues to a sub-agent under its own mandate. Always narrower than its parent. |
| Counterparty | Whoever receives an action from an agent and must decide whether to honour it: an API, a merchant, a booking system, another agent. |
| Verifier | The component that checks a presented mandate against a proposed action and returns allow, confirm or deny. Runs in the counterparty, or as a hosted service the counterparty calls. |
| Issuer | The service that holds principal consent, co-signs mandates, serves revocation status and keeps the ledger. Warrant is an issuer; the protocol allows others. |
| Ledger | The append-only record of actions verified under a mandate, signed by the acting agent and countersigned by the verifier. |
| Identity root | An external system that vouches for who the principal is: a government wallet, a KYC vendor, an enterprise IdP. |

## The mandate object

A mandate is a JWS-signed JSON object with media type `application/warrant-mandate+jwt`. The payload is canonicalised with RFC 8785 (JCS) before signing. Two signatures are required: the principal's and the issuer's. Verifiers MUST reject a mandate missing either.

### Fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `typ` | string | yes | Always `warrant/mandate` |
| `ver` | string | yes | Spec version, `0.1` |
| `id` | string | yes | `wrt_` + 26-char ULID. Globally unique. |
| `parent` | string | for sub-mandates | `id` of the mandate this one is delegated under. Absent at hop 1. |
| `principal.root` | string | yes | Identity root identifier, e.g. `eudi-wallet`, `aadhaar`, `persona`, `okta:acme.com` |
| `principal.sub` | string | yes | Pairwise pseudonymous subject from the root. Never a raw national ID. |
| `principal.key` | string | yes | Public key or passkey credential ID that signs hop 0 |
| `principal.assertion` | string | yes | Opaque, root-signed assertion that `sub` was verified, with its own expiry |
| `agent.did` | string | yes | DID of the agent receiving the mandate |
| `agent.runtime` | string | no | Attestation of the agent's build or runtime, if the operator provides one |
| `scope.may` | string\[\] | yes | Action identifiers the agent may perform. Namespaced, e.g. `travel:book_flight` |
| `scope.may_not` | string\[\] | no | Actions explicitly refused. Wins over `may` and over any wildcard. |
| `scope.counterparties` | string\[\] | yes | Who may honour the mandate: DIDs, `api:` hosts, registry patterns such as `iata:*`. `*` is allowed but SHOULD be discouraged in consent UI. |
| `limits.ccy` | string | if spend | ISO 4217 currency for all amounts |
| `limits.total` | integer | if spend | Ceiling across the mandate's life, minor units |
| `limits.per_txn` | integer | if spend | Ceiling per single action, minor units |
| `limits.confirm_over` | integer | no | Above this amount the verifier returns `confirm`, not `allow` |
| `limits.confirm_on` | string\[\] | no | Actions that always return `confirm` regardless of amount |
| `limits.rate` | string | no | Max actions per window, e.g. `20/1h` |
| `delegation.max_depth` | integer | yes | 0 forbids sub-mandates. Each sub-mandate carries `parent.max_depth - 1`. |
| `delegation.attenuate` | boolean | yes | Always `true` in v0.1; reserved for future modes |
| `nbf`, `exp` | integer | yes | Unix seconds. `exp - nbf` MUST NOT exceed 90 days. |
| `revocation` | URL | yes | Status endpoint for this mandate (see Revocation) |
| `ledger` | URL | yes | Where verifiers post ledger records |
| `sig[]` | object\[\] | yes | Ordered signatures: `[principal, issuer]` at hop 1; sub-mandates append the delegating agent |

### Rules

- Amounts are integers in minor units (cents, paise). Verifiers MUST NOT accept floats.
- `may_not` is evaluated before `may`. An action in both is refused.
- A mandate with no `limits.total` grants no spending authority. Any action carrying an amount is refused under it.
- `principal.sub` MUST be pairwise per issuer so that two counterparties cannot correlate a principal across mandates. The issuer holds the mapping to the root subject and releases it only through the dispute process.
- The consent UI MUST show the principal the final values of `scope`, `limits`, `exp` and `delegation` before signing. The principal's signature covers exactly those values; the agent cannot request more after the fact.

### Example

```json
{
  "typ": "warrant/mandate",
  "ver": "0.1",
  "id": "wrt_01JBQ8Z7K4TRIPWISE",
  "principal": {
    "root": "eudi-wallet",
    "sub": "pw_7f31c2a9",
    "key": "passkey:c2a7…",
    "assertion": "eyJhbGciOi…"
  },
  "agent": { "did": "did:web:agents.tripwise.com", "runtime": "attest:2026.11.1" },
  "scope": {
    "may": ["travel:search", "travel:book_flight", "travel:book_hotel", "travel:cancel_own_booking"],
    "may_not": ["payments:change_method", "travel:book_for_others", "identity:share_documents"],
    "counterparties": ["iata:*", "api:booking.com", "api:expedia.com"]
  },
  "limits": { "ccy": "USD", "total": 150000, "per_txn": 60000, "confirm_over": 50000, "confirm_on": ["travel:cancel_own_booking"] },
  "delegation": { "max_depth": 2, "attenuate": true },
  "nbf": 1793613000,
  "exp": 1794217800,
  "revocation": "https://warrant.example/r/wrt_01JBQ8Z7K4TRIPWISE",
  "ledger": "https://warrant.example/l/wrt_01JBQ8Z7K4TRIPWISE",
  "sig": [
    { "by": "principal", "alg": "ES256", "kid": "passkey:c2a7…", "value": "…" },
    { "by": "issuer", "alg": "EdDSA", "kid": "did:web:warrant.example#k1", "value": "…" }
  ]
}
```

## Delegation chain

An agent holding a mandate MAY issue a sub-mandate to another agent if `delegation.max_depth` is greater than 0. A sub-mandate is a full mandate object whose `parent` names the mandate it derives from and whose `sig[]` appends the delegating agent's signature after the principal's and issuer's. The verifier re-checks the whole chain, not only the last hop.

### Attenuation rule

A sub-mandate MUST be equal to or narrower than its parent on every axis. The verifier computes the effective mandate at hop n as the intersection of hops 1 to n and refuses the presentation if any hop widens any field:

```
Principal · hop 0 ──mandate──▶ Tripwise · hop 1 ──sub-mandate──▶ FareScout · hop 2
EU wallet · passkey            search · book flight            book flight only
signs scope and limits         book hotel · cancel own         $600 total · $600/txn
holds the kill switch          $1,500 total · $600/txn         depth 1 · exp 9 Nov
                               depth 2 · exp 9 Nov             no new counterparties
                                                                      │ presents the full chain
                                                                      ▼
                                                               Singapore Airlines
                                                               verifies hops 0, 1, 2
                                                               then the action itself
```

FareScout's sub-mandate drops hotel booking and cancellation, keeps the per-transaction cap, and loses one level of depth. The airline verifies all three signatures before it looks at the booking.

| Field | Rule at hop n |
| --- | --- |
| `scope.may` | Subset of parent `may` |
| `scope.may_not` | Superset of parent `may_not` (a hop can add refusals, never remove them) |
| `scope.counterparties` | Subset of parent, pattern by pattern. `iata:SQ` under `iata:*` is fine; `api:expedia.com` under `api:booking.com` is not. |
| `limits.total` | Less than or equal to parent `total` minus what the parent has already spent at issue time. The issuer tracks spend across the tree so that siblings cannot together exceed the root. |
| `limits.per_txn` | Less than or equal to parent |
| `limits.confirm_over` | Less than or equal to parent. A hop can lower the threshold, never raise it. |
| `limits.confirm_on` | Superset of parent |
| `delegation.max_depth` | Exactly parent minus 1 |
| `nbf` | Greater than or equal to parent `nbf` |
| `exp` | Less than or equal to parent `exp` |
| `principal` | Identical to parent. A sub-agent never acts for a different principal. |
| `revocation`, `ledger` | Identical to parent. Revocation and the ledger are per tree, not per hop. |

### Hop records

A sub-mandate's `sig[]` starts with a byte-for-byte copy of its parent's `sig[]`, then appends one hop record signed by the delegating agent: `{ by: 'agent', did, alg, kid, iat, value }`. `kid` MUST be a fragment of the parent's `agent.did`. The hop signature covers the JCS canonical form of the sub-mandate with `sig[]` truncated to the copied entries, so it binds the child's terms to the exact parent chain it was issued under. The principal and issuer never sign a sub-mandate directly; their signatures bind hop 1, and the copy requirement is what ties each hop to them.

A verifier therefore checks a chain in three passes: hop 1's principal and issuer signatures over hop 1; for each sub-mandate, that its leading `sig[]` entries equal its parent's exactly and that `parent` names the hop before it; then each hop record against the delegating agent's key. A chain that passes is tamper-evident end to end: changing any hop's terms breaks that hop's signature, and swapping a parent breaks the copied entries.

Depth is capped at 4 in v0.1 regardless of what a principal sets. Deeper chains have no demonstrated use and make the confirm path slow.

### Confirm requests through the chain

When a verifier returns `confirm` for an action at hop n, the confirmation request goes to the principal through the issuer, not back up the agent chain. The principal's signed reply names the mandate `id`, the hop, the action hash and the amount. Agents in between see the outcome, never the principal's channel.

## Revocation

A principal, the issuer, or any agent in the chain can revoke. Revocation applies to a mandate and every sub-mandate beneath it; it never applies upward. Once revoked, a mandate stays revoked.

### Who may revoke what

| Actor | May revoke |
| --- | --- |
| Principal | The root mandate and therefore the whole tree |
| Issuer | Any mandate it co-signed, on compromise, dispute or policy breach. Issuer revocations carry a reason code. |
| Agent at hop n | Any sub-mandate it issued, and its own mandate (an agent may resign authority) |
| Counterparty | Nothing. A counterparty refuses actions; it does not revoke mandates. |

### Status endpoint

The `revocation` URL answers `GET` with a short signed status:

```json
{ "id": "wrt_01JBQ8Z7K4TRIPWISE", "status": "active", "spent": 47800, "asof": 1793613900, "ttl": 30, "sig": "…" }
```

`status` is one of `active`, `revoked`, `expired`, `suspended`. `spent` is the running total across the tree in minor units, so a verifier can enforce `limits.total` without its own state. `ttl` is how many seconds the verifier MAY cache the answer.

### Freshness rules

- A verifier MUST hold a status response no older than `ttl` seconds before returning `allow`. Default `ttl` is 30; issuers MAY set it lower for high-value mandates and MUST NOT set it above 300.
- If the status endpoint is unreachable, the verifier MUST return `deny` for any action carrying an amount, and MAY return `allow` for zero-amount, reversible actions (search, read) if the cached status is under 24 hours old.
- Issuers SHOULD also publish a signed revocation list (all ids revoked in the last 7 days) at a well-known path, so that high-volume counterparties can check locally and poll once.
- Issuers SHOULD push revocation to counterparties that appear in the ledger of the revoked tree, so an in-flight session is cut rather than left to time out.

Revocation therefore reaches a counterparty no later than its cached status expires: for up to `ttl` seconds after a revoke, a verifier holding a fresh-enough status will still pass check 3. This is by design and is the price of a verifier that works when the issuer is slow. Counterparties that cannot tolerate the window set a lower `ttl` with the issuer or subscribe to revocation push; high-value actions SHOULD fetch status uncached.

### Effect on in-flight actions

An action the verifier already answered `allow` for, and the counterparty already executed, stands; revocation is not a chargeback. An action in `confirm` state is cancelled. The ledger records the revocation with its actor, reason and the ids of every sub-mandate it took down.

## Verifier decision

The verifier takes a presented mandate chain and a proposed action and returns exactly one of `allow`, `confirm` or `deny`. Checks run in a fixed order and the first failure ends evaluation with that failure's reason code. The verifier is deterministic: the same chain, action and status response always give the same answer.

### Inputs

| Input | Content |
| --- | --- |
| `chain` | The mandate at hop 1 and every sub-mandate down to the acting agent, each as a compact JWS |
| `action.type` | Namespaced action identifier, matched against `scope` |
| `action.amount` | Integer minor units and currency, if any |
| `action.counterparty` | The verifier's own identifier, matched against `scope.counterparties` |
| `action.hash` | SHA-256 of the counterparty's canonical description of the action (cart, booking, message). Goes into the ledger and into any confirm request. |
| `action.sig` | The acting agent's signature over `action.hash`, with the key named in its hop record |
| `status` | The issuer's current status response, fetched by the verifier (see Revocation) |

### Ordered checks

1. Every signature in every hop verifies, and each hop's `parent` matches the id of the hop before it. Fail: `bad_signature`.
2. `principal.assertion` is signed by a root the verifier trusts and has not expired. Fail: `principal_unverified`.
3. `status` is `active`, `asof` is within `ttl`, and now is between `nbf` and `exp` at every hop. Fail: `revoked`, `expired` or `stale`.
4. Each hop is equal to or narrower than its parent on every field in the attenuation table. Fail: `widened`.
5. `action.type` is not in any hop's `may_not`, is in the effective `may`, and `action.counterparty` matches the effective `counterparties`. Fail: `out_of_scope`.
6. If an amount is present: it is at or under effective `per_txn`; `status.spent` plus the amount is at or under effective `total`; the rate window has room. Fail: `over_limit`.
7. If the amount is above effective `confirm_over`, or `action.type` is in any hop's `confirm_on`: return `confirm`. Otherwise return `allow`.

The verifier writes a ledger record for every outcome, including denials.

```
1  Signatures valid, chain intact        ──fail──▶ deny · bad_signature
2  Principal assertion current           ──fail──▶ deny · principal_unverified
3  Status active, fresh within ttl       ──fail──▶ deny · revoked | expired | stale
4  Each hop narrower than its parent     ──fail──▶ deny · widened
5  Action and counterparty in scope      ──fail──▶ deny · out_of_scope
6  Amount within per_txn, total, rate    ──fail──▶ deny · over_limit
7  Over confirm threshold?  ── yes ──▶ confirm (held for the principal)
          │ no
          ▼
        allow (ledger record written)
```

Checks 1 to 6 can only deny. Check 7 never denies; it routes a valid action to the principal when the amount or the action type asks for a human.

### Response

```json
{ "decision": "allow", "mandate": "wrt_01JBQ8Z7K4TRIPWISE", "hop": 2, "reason": null,
  "ledger_ref": "led_01JBQ9F3…", "ttl": 30, "sig": "…" }
```

For `confirm` the response also carries `confirm_ref`, which the counterparty polls or subscribes to. The principal's signed reply flips it to `allow` or `deny`; after 15 minutes without a reply it expires to `deny`. `ttl` is how long the counterparty MAY act on an `allow` before it must verify again.

### Confirmed actions

A `confirm` is bound to one action hash. Once the principal replies `allow`, the agent repeats the identical action and presents the confirm reference alongside the chain. The verifier MUST then treat the action as confirmed: it runs checks 1 to 5 as usual, runs check 6 with the action's amount excluded from `status.spent` (the principal's reply already added it), and returns `allow` at check 7 without consulting the threshold. No new ledger record is written; the principal's reply is the record. A confirm reference presented with a different action hash, a different acting mandate, or in any state other than `allow` is ignored and the action is verified as if no confirm existed.

Without this rule a confirmed action would re-trip the threshold on every retry and, once the reply bumped `spent`, be counted twice against `limits.total`.

### Hosted verification

An issuer MAY expose the verifier as a service: the counterparty sends the chain, the action and its own identifier; the issuer runs the seven checks with its own keys and accepted roots, signs the ledger record as verifier and issuer, and returns the verdict. A counterparty using the hosted verifier trusts the issuer's decision; one running the checks itself trusts only the issuer's status and keys. Both are conformant. The hosted form exists so that thin clients and languages without a native implementation can participate.

## Ledger record

Every verifier decision produces one ledger record, posted to the mandate's `ledger` URL. The ledger is append-only and hash-chained per mandate tree, so a record cannot be removed or reordered without breaking every record after it. It is the artefact a principal, counterparty, insurer or regulator uses to establish who authorised what.

### Fields

| Field | Content |
| --- | --- |
| `ref` | `led_` + ULID |
| `prev` | Hash of the previous record in this tree, or null for the first |
| `mandate` | Mandate id at the acting hop, plus the root id |
| `hop` | Depth of the acting agent |
| `agent` | DID of the acting agent |
| `counterparty` | Identifier of the verifier's operator |
| `action` | `type`, `amount`, `ccy`, `hash` as presented |
| `decision` | `allow`, `confirm`, `deny` and the reason code |
| `confirm` | For confirm outcomes: `confirm_ref`, the principal's reply, and when it arrived |
| `status_asof` | The `asof` of the status response the verifier relied on |
| `at` | Verifier clock, Unix milliseconds |
| `sig.agent` | The acting agent's signature over `action.hash` |
| `sig.verifier` | The verifier's signature over the whole record |
| `sig.issuer` | Added by the issuer when it accepts the record into the chain |

### What the ledger does not hold

The ledger stores the action hash, never the action's content. A cart, an itinerary or a message body stays with the counterparty. In a dispute, the counterparty produces the content and anyone can check it against the hash. This keeps the issuer out of the data path and keeps the ledger small enough to retain for years.

### Dispute export

A principal or counterparty MAY request a signed export for one mandate tree: every record in order, the mandates at each hop, the status responses relied on, and the issuer's chain-head signature. The export is a single JSON file that a third party can verify offline with the issuer's and roots' public keys. The issuer releases the principal's root subject only to the parties in the export, and logs that release in the same ledger.

### Retention

Issuers MUST retain records for at least 7 years after a mandate's `exp`. Counterparties SHOULD keep the `ledger_ref` with their own transaction record.

## Identity roots

Warrant does not verify humans. It binds a mandate to an assertion from a root that already has, and lets each counterparty decide which roots it trusts. This is what keeps the protocol global: a Chennai merchant can accept a mandate rooted in Aadhaar, a Berlin one a mandate rooted in the EU wallet, and a US API one rooted in a KYC vendor, all with the same verifier code.

### Root contract

A root is anything that can produce a `principal.assertion` with these properties:

- Signed by a key the root publishes (JWKS or DID document).
- Names a pairwise subject for this issuer, not a global identifier.
- States the assurance level reached, using the same three-level scale as eIDAS and NIST 800-63: `low`, `substantial`, `high`.
- Carries its own `exp`. Assertions SHOULD outlive the mandates built on them by at least the status `ttl`.
- Discloses nothing else by default. Name, date of birth, nationality and address are not in the assertion; a counterparty that needs one asks for a separate selective-disclosure credential.

### Roots planned for v0.1

| Root id | Kind | Assurance | Notes |
| --- | --- | --- | --- |
| `eudi-wallet` | Government wallet (EU) | high | OpenID4VP presentation of the PID credential |
| `aadhaar` | Government ID (India) | substantial | Via a licensed AUA; Warrant never touches the Aadhaar number |
| `persona`, `stripe-identity` | KYC vendor | substantial | For markets with no government wallet |
| `okta:<domain>`, `entra:<tenant>` | Enterprise IdP | substantial | Principal is an employee acting for the organisation; the organisation is the accountable party |
| `passkey-only` | Device credential | low | Permits read-only and zero-amount mandates only. Counterparties SHOULD refuse it for spend. |

### Organisations as principals

When the principal is a company, `principal.root` is its IdP and `principal.sub` is the employee who approved the mandate. The mandate also carries `principal.org` with the organisation's legal identifier (LEI or national registry number) and the approving role. Counterparties see the organisation; the issuer holds which employee clicked approve and releases it only in a dispute export.

### Counterparty policy

A verifier is configured with the roots it accepts and the minimum assurance per action type. A hotel API might accept any root at `substantial` for bookings under $1,000 and require `high` above it. The policy is the counterparty's; the protocol only makes the root and level visible.

## HTTP binding

Transport is out of scope, but every implementation so far uses HTTP, so the binding is fixed here to keep them interoperable.

| Header | Sent by | Content |
| --- | --- | --- |
| `Warrant-Mandate` | agent | The chain, hop 1 first, as `wrt.` tokens separated by commas |
| `Warrant-Action-Signature` | agent | `<kid>:<base64url Ed25519 signature>` over the UTF-8 bytes of the action hash |
| `Warrant-Confirm` | agent | A confirm reference, only when repeating an action the principal has confirmed |

The action hash is SHA-256 over the JCS form of the request body unless the counterparty documents another description. The counterparty hashes the same bytes; a body changed after signing fails check 1 as `bad_signature`.

| Verdict | Response |
| --- | --- |
| allow | The request proceeds. `Warrant-Decision: allow` and `Warrant-Ledger-Ref` on the response. |
| confirm | `202` with `{ decision: "confirm", confirm_ref, poll }`. The request is not executed. |
| deny | `403` with `{ error: <reason code>, message, checks }`. |
| headers missing | `401` with `mandate_required` or `signature_required`. |

For MCP tools the same three values travel inside the tool arguments as `_warrant: { mandate, kid, sig, confirm? }`, and the hash covers the arguments without `_warrant`.

## Security considerations

| Threat | Mitigation in v0.1 |
| --- | --- |
| Agent compromised by prompt injection, asked to exceed its mandate | The verifier enforces scope and limits at the counterparty; the agent's intent is irrelevant. `may_not` and `confirm_over` are the principal's firebreaks. |
| Stolen mandate replayed by another agent | A mandate is useless without the acting agent's key: every action is signed with the key in the hop record. Counterparties MUST check `action.sig`. |
| Sub-agent tries to widen scope | Check 4 recomputes attenuation over the whole chain on every verification. |
| Two sub-agents each spend the parent's full total | `status.spent` is tracked per tree at the issuer; check 6 uses it. |
| Principal's passkey stolen | Mandates are the blast radius: an attacker can issue new ones, not raise existing ones. Roots at `high` assurance SHOULD require a fresh root presentation for mandates above a configurable amount. |
| Issuer compromised | Issuer signatures alone are not enough; the principal's signature is also required, and the issuer cannot forge it. The issuer can revoke falsely; that is visible in the ledger and is the main reason the ledger is hash-chained. |
| Issuer unavailable | Verifiers fail closed for spend and fail open briefly for zero-amount actions. Issuers SHOULD run status endpoints as static signed objects behind a CDN. |
| Counterparty lies about what was executed | The ledger holds the action hash signed by the agent before execution; the counterparty cannot later substitute a different action. |
| Correlation of a principal across counterparties | Pairwise subjects per issuer; the assertion discloses no attributes. |
| Clock skew | Verifiers MUST allow 60 seconds of skew on `nbf`, `exp` and `asof`, and no more. |

## Open questions

- [ ] Should `confirm` be answerable by a delegated approver (a manager, a co-signer) rather than only the original principal? Enterprise buyers will ask.
- [ ] Whether to express the mandate as a W3C Verifiable Credential instead of a bare JWS, for alignment with AP2 and the EU wallet. Likely yes for v0.2; the field set does not change.
- [ ] Rate limits across a tree versus per hop.
- [ ] A standard action-type registry, or namespaces owned by counterparties. Start with counterparties owning their namespaces.
- [ ] Liability text to attach to a mandate so that a signed mandate reads as an authorisation under the principal's local law. Needs counsel in at least EU, US and India.
- [ ] Whether to allow a `max_depth` above 2 before someone demonstrates a need.
- [ ] Revocation push: how counterparties subscribe, and whether a verifier that ignores a push it was sent remains conformant.
- [ ] WebAuthn principal keys: an ES256 signature path for hop 0 so that the principal's key is a real passkey rather than a software Ed25519 key.

## Sources

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 7515 JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [HDP: Human Delegation Provenance in Agentic AI Systems](https://arxiv.org/pdf/2604.04522)
- [AI Identity: Standards, Gaps](https://arxiv.org/pdf/2604.23280)
- [Human-Anchored Intent-Bound Delegation (NIST NCCoE response)](https://www.thefai.org/posts/human-anchored-intent-bound-delegation-for-ai-agents)
- [OpenA2A Agent Identity Protocol (IETF draft)](https://datatracker.ietf.org/doc/draft-fane-opena2a-aip/)
