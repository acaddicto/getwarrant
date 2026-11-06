# Demo: Tripwise books a trip under a mandate

Two counterparties, two agents, one principal, the live issuer.

| Part | Runs as | Verifies how |
| --- | --- | --- |
| `airline.ts` | Express on :4010, `iata:SQ` | Locally, with `@getwarrant/node`: its own key, its own trusted roots |
| `hotel.py` | FastAPI on :4020, `api:booking.com` | Through the issuer's hosted verifier, with `warrant-fastapi` |
| `agent.ts` | Tripwise and FareScout | `AgentClient`: request, delegate, sign actions |
| scripted principal (in `agent.ts`) | the human, automated | approves the consent with a lower per-booking cap, answers the confirm, revokes |

```
cd demo && npm install && pip install -e ../packages/python && npm run demo
```

What you will see, in order: the mandate request and consent URL; the principal approving with a $550 cap instead of the $600 asked; delegation to FareScout; FareScout's $478 flight booked at hop 2; FareScout refused a hotel (out of scope for its sub-mandate); Tripwise's $540 hotel hold answered 202 and held for the principal; the principal confirming; the identical request repeated with `Warrant-Confirm` and accepted; a replay of the tokens with a forged signature refused; the principal revoking; the next booking attempt refused once the airline's 30-second status cache expires.

Set `PER_TXN_CAP=40000` to watch the flight itself get refused at the airline (`over_limit`), which is the point of the whole thing.

The demo talks to the production issuer and leaves its mandates there, revoked. The `demo-wallet` root it signs in with is a development root; it will not exist on a real deployment.
