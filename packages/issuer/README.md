# @getwarrant/issuer

The hosted issuer: holds principal consent, co-signs mandates, serves status and the revocation list, keeps the hash-chained ledger, routes confirms to the principal, and cascades revocation. One Supabase Edge Function plus a Postgres schema.

Production instance: `https://vvnvwrefyrrapjhmpajr.supabase.co/functions/v1/warrant` (project `warrant`, ap-south-1). `api.getwarrant.dev` will front it.

## Layout

```
supabase/migrations/0001_init.sql        schema warrant.*: roots, agent_keys, requests, mandates, ledger, confirmations, revocations
supabase/functions/warrant/index.ts      the API (routes listed at the top of the file)
supabase/functions/warrant/deno.json     import map: @getwarrant/core pinned to a GitHub commit
supabase/functions/warrant/deno.local.json  same map but core from ../../../../core/src for local `deno check`
scripts/e2e.ts                           full Tripwise walk against a deployed instance
```

## Setup (once per project)

1. Apply `0001_init.sql`.
2. Expose the schema to PostgREST: `alter role authenticator set pgrst.db_schemas = 'public, graphql_public, warrant'; notify pgrst, 'reload config'; notify pgrst, 'reload schema';` (the second notify matters; without it queries return empty until the cache refreshes).
3. Set the function secret `WARRANT_ISSUER_SECRET` to 32 random bytes, base64url (`node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`). The issuer key pair is derived from it; rotating it changes the issuer `kid`. Optional: `WARRANT_ISSUER_DID`, `WARRANT_PUBLIC_BASE`, `WARRANT_CONSENT_BASE`; they default to the project's own host.
4. Seed at least one identity root. For development there is a `demo-wallet` root whose private key the e2e script derives from a fixed seed; remove it before anything real touches the instance:

```sql
insert into warrant.roots (id, kid, public_key, kind, max_level)
values ('demo-wallet', 'demo-wallet:signer-1', 'DjMMTKMkqRgLxEZGFJxLuNqF9Q2G6_iXil3RoIEiXus', 'device', 'high');
```

5. Deploy `supabase/functions/warrant` with `verify_jwt: false` (the function authenticates principals and agents itself).

## Run the walk-through

```
WARRANT_BASE=https://<ref>.supabase.co/functions/v1/warrant npx tsx scripts/e2e.ts
```

It registers two agents, files a request, approves it as a principal who lowers `per_txn`, registers a sub-mandate, has an airline verify and log a booking, trips a confirm on a hotel hold, answers it, checks spend, pulls the signed export, revokes, and confirms the verifier now denies. Every assertion is an API contract.

## Auth model (v0.1)

| Caller | How |
| --- | --- |
| Principal | `Authorization: Warrant-Principal <root assertion token>`. The assertion is the login; its `aud` must be this issuer. |
| Agent | Signs each request body with a key registered at `POST /agents`. Registration is open in v0.1. |
| Counterparty | No auth to post ledger records; the record must carry the acting agent's signature over the action hash and the verifier's signature over the record. |

## Principal keys and the consent page

Principals sign with a passkey. `GET /consent/:request_id` serves the consent page: sign in with an identity root (the development root `demo-wallet` while nothing real is connected), create a passkey (`POST /passkeys/options`, `navigator.credentials.create`, `POST /passkeys`), review and narrow the terms, approve. `prepare` returns the WebAuthn `challenge` (base64url SHA-256 of the JCS payload) and the principal's credential ids; `approve` takes `{ sig: { alg: "ES256", value, webauthn: { authenticatorData, clientDataJSON } } }` and the issuer verifies origin, rp id, challenge and signature before co-signing. Confirm replies take the same shape.

`principal.key` is self-describing: `p256:<compressed point>` for passkeys, `key:<Ed25519 public key>` for software keys (scripts, tests). Counterparties need no directory for either.

The relying party id and origin default to the host the function is served from; set `WARRANT_RP_ID` and `WARRANT_WEBAUTHN_ORIGIN` when a custom domain fronts it.

## Not here yet

A principal dashboard (list, ledger, revoke) in the browser, DID resolution instead of registered agent keys, push notifications to counterparties on revocation, rate limits on open endpoints.
