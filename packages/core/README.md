# @getwarrant/core

The reference implementation of the Warrant protocol: mandates for AI agents that a counterparty can verify without trusting the agent.

Pure TypeScript. Ed25519 via `@noble/ed25519`. No I/O: fetching status, resolving DID keys and storing the ledger are the caller's job, which keeps `verifyAction` a pure function.

## API

| Function | Role | Does |
| --- | --- | --- |
| `issueMandate(draft, { issuerBase, principalKey, issuerKey })` | issuer | Builds a hop-1 mandate, validates shape, signs as principal then issuer |
| `delegate(parent, { agentKey, child })` | agent | Issues a sub-mandate; throws `widened` if the child is broader on any axis |
| `verifyAction({ chain, action, status }, ctx)` | counterparty | The seven ordered checks; returns `allow`, `confirm` or `deny` with a reason and per-check detail |
| `signAction(hash, agentKey)` | agent | Signs the action hash the counterparty will verify |
| `issueStatus(status, issuerKey)` / `verifyStatusSignature` | issuer / counterparty | Signed status responses for the revocation endpoint |
| `checkAttenuation(parent, child)` / `effective(chain)` | any | The attenuation table and the chain intersection |
| `buildRecord`, `signRecordAsVerifier`, `signRecordAsIssuer`, `verifyLedger` | counterparty / issuer | Hash-chained ledger records |
| `encodeMandate` / `decodeMandate` | any | Wire form `wrt.<base64url JCS JSON>` |
| `issueRootAssertion` / `verifyRootAssertion` | identity root | What a root says about a principal |

## Verifier context

```ts
verifyAction(input, {
  now,                       // unix seconds; inject for determinism
  keys: kid => publicKey,    // resolves principal, issuer and agent key ids
  trustedRoots: { "eudi-wallet": { publicKey } },
  issuerId: "did:web:warrant.example",   // optional: assertions must be scoped to this issuer
  minLevel: action => "substantial",     // optional: default requires "substantial" for any spend
  recentActionCount: 3,                  // optional: enables limits.rate
});
```

## Signature chain

Hop 1 carries `[principal, issuer]`. A sub-mandate copies its parent's `sig[]` byte for byte and appends the delegating agent's signature over the child with `sig[]` truncated to the copied entries. The verifier checks hop 1's signatures, then that every sub-mandate's leading signatures equal its parent's, then each agent hop, then the action signature by the acting agent.

## Tests and vectors

```
npm test          # 32 tests: shape, attenuation table, each of the seven checks, ledger chaining
npm run vectors   # regenerates ../../vectors/v0.1.json
```

Other implementations should load `vectors/v0.1.json`, reconstruct the context from `context.keys` and `context.trusted_roots`, and assert `expect.decision`, `expect.reason` and `expect.failed_step` for every case.

## Not in this package

Transport (how the chain travels in HTTP, A2A or MCP), key management, DID resolution, the hosted issuer and the confirm channel to the principal. Those are the next packages.
