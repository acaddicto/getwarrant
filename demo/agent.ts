/**
 * Tripwise: asks the principal for a mandate, delegates flights to FareScout, books with the airline (Express)
 * and the hotel (FastAPI). A scripted principal approves the consent and answers the confirm, so the whole
 * story runs unattended. Replace `scriptedPrincipal` with a real consent UI and you have the product.
 */
import { decodeMandate, issueRootAssertion, signJson, type Mandate } from "@getwarrant/core";
import { AgentClient } from "@getwarrant/node";
import { AIRLINE_PORT, HOTEL_PORT, ISSUER, keys } from "./config.ts";

const say = (who: string, msg: string) => console.log(`${who.padEnd(9)} ${msg}`);
const now = () => Math.floor(Date.now() / 1000);
const airline = `http://127.0.0.1:${AIRLINE_PORT}`, hotel = `http://127.0.0.1:${HOTEL_PORT}`;

// --- the principal, scripted ---------------------------------------------------------
async function scriptedPrincipal() {
  const disco = await (await fetch(`${ISSUER}/.well-known/warrant.json`)).json();
  const assertion = issueRootAssertion({ root: "demo-wallet", sub: "pw_demo_" + Date.now().toString(36), aud: disco.issuer, level: "high", iat: now(), exp: now() + 3600 }, keys.demoRoot);
  const auth = { authorization: `Warrant-Principal ${assertion}`, "content-type": "application/json" };
  const call = async (path: string, body: unknown) => { const r = await fetch(ISSUER + path, { method: "POST", headers: auth, body: JSON.stringify(body) }); const j = await r.json(); if (!r.ok) throw new Error(`${path}: ${j.error} ${j.message ?? ""}`); return j; };
  return {
    async approve(requestId: string, perTxnCap: number) {
      const prep = await call(`/requests/${requestId}/prepare`, { key: keys.principal.kid, limits: { per_txn: perTxnCap } });
      const sig = signJson(JSON.parse(prep.payload_to_sign), keys.principal.secretKey);
      const ok = await call(`/requests/${requestId}/approve`, { sig });
      return ok.mandate as Mandate;
    },
    async confirm(ref: string, mandateId: string, reply: "allow" | "deny") {
      const c = await (await fetch(`${ISSUER}/confirm/${ref}`)).json();
      const body = { confirm: ref, mandate: mandateId, action_hash: c.action_hash, amount: c.amount, reply };
      await call(`/confirm/${ref}/reply`, { reply, sig: signJson(body, keys.principal.secretKey) });
    },
    async revoke(id: string) { return call(`/mandates/${id}/revoke`, { reason: "demo finished" }); },
  };
}

// --- the agents ------------------------------------------------------------------------
const tripwise = new AgentClient(keys.tripwise, ISSUER, { operator: "Tripwise Inc.", runtime: "attest:2026.11.1" });
const farescout = new AgentClient(keys.farescout, ISSUER, { operator: "FareScout" });
await tripwise.register(); await farescout.register();
say("tripwise", "registered keys for Tripwise and FareScout");

const req = await tripwise.requestMandate({
  purpose: "Book your Singapore trip, 14–18 Nov",
  scope: { may: ["travel:search", "travel:book_flight", "travel:book_hotel", "travel:cancel_own_booking"], may_not: ["payments:change_method", "travel:book_for_others", "identity:share_documents"], counterparties: ["iata:*", "api:booking.com", "api:expedia.com"] },
  limits: { ccy: "USD", total: 150000, per_txn: 60000, confirm_over: 50000, confirm_on: ["travel:cancel_own_booking"] },
  delegation: { max_depth: 2, attenuate: true },
  nbf: now(), exp: now() + 7 * 86400,
});
say("tripwise", `asked for a mandate → consent ${req.consent_url}`);

const principal = await scriptedPrincipal();
const cap = Number(process.env.PER_TXN_CAP ?? 55000);
const mandate = await principal.approve(req.request_id, cap);
say("principal", `approved with per-booking cap $${cap / 100} (agent asked $600) → ${mandate.id}`);
const got = await tripwise.awaitMandate(req.request_id, { timeoutMs: 10000 });
if (!got) throw new Error("no mandate");
say("tripwise", `holds ${got.mandate.id}, signed by principal + issuer`);

const sub = await tripwise.delegate(got.mandate, {
  agent: { did: farescout.did },
  scope: { may: ["travel:book_flight"], may_not: got.mandate.scope.may_not, counterparties: ["iata:*"] },
  limits: { ccy: "USD", total: Math.min(cap, 60000), per_txn: Math.min(cap, 60000), confirm_over: 50000, confirm_on: got.mandate.limits.confirm_on },
});
say("tripwise", `delegated flights to FareScout → ${sub.mandate.id} (book_flight only, ≤ $${Math.min(cap, 60000) / 100})`);

// FareScout books with the airline (Express middleware, local verifier).
const flights = (await (await fetch(`${airline}/flights`)).json()).flights;
const out = flights[0];
let body = { flight: out.no, amount: out.fare, ccy: "USD" };
let r = await fetch(`${airline}/book`, { method: "POST", headers: { "content-type": "application/json", ...farescout.headers([got.token, sub.token], body) }, body: JSON.stringify(body) });
let j = await r.json();
say("farescout", `POST /book ${out.no} $${out.fare / 100} → ${r.status} ${r.ok ? `PNR ${j.pnr} · hop ${j.hop} · ledger ${j.ledger}` : `${j.error}: ${j.message}`}`);

// FareScout oversteps: tries a hotel. Denied at the hotel API, out of scope for the sub-mandate.
body = { hotel: "Hotel G Singapore", amount: 38000, ccy: "USD" };
r = await fetch(`${hotel}/hold`, { method: "POST", headers: { "content-type": "application/json", ...farescout.headers([got.token, sub.token], body) }, body: JSON.stringify(body) });
j = await r.json();
say("farescout", `POST /hold (hotel) → ${r.status} ${j.detail?.error ?? j.error}: ${j.detail?.message ?? j.message ?? ""}`);

// Tripwise holds the hotel itself: $540 is above the $500 confirm threshold → 202, principal answers, retry succeeds.
body = { hotel: "Hotel Jen Orchardgateway", amount: 54000, ccy: "USD" };
r = await fetch(`${hotel}/hold`, { method: "POST", headers: { "content-type": "application/json", ...tripwise.headers([got.token], body) }, body: JSON.stringify(body) });
j = await r.json();
say("tripwise", `POST /hold $540 → ${r.status} ${j.detail?.error ?? j.error ?? ""} ${j.detail?.confirm_ref ?? ""}`);
if (r.status === 202) {
  const ref = j.detail?.confirm_ref ?? j.confirm_ref;
  await principal.confirm(ref, got.mandate.id, "allow");
  say("principal", `confirmed ${ref}`);
  r = await fetch(`${hotel}/hold`, { method: "POST", headers: { "content-type": "application/json", "warrant-confirm": ref, ...tripwise.headers([got.token], body) }, body: JSON.stringify(body) });
  j = await r.json();
  say("tripwise", `POST /hold again with Warrant-Confirm → ${r.status} ${r.ok ? `held ${j.held} · hop ${j.hop}` : `${j.detail?.error}: ${j.detail?.message}`}`);
}

// Someone with a stolen token but no agent key: denied at signature.
body = { flight: out.no, amount: out.fare, ccy: "USD" };
r = await fetch(`${airline}/book`, { method: "POST", headers: { "content-type": "application/json", "warrant-mandate": got.token + "," + sub.token, "warrant-action-signature": "did:web:farescout.ai#k1:AAAA" }, body: JSON.stringify(body) });
say("attacker", `replays the tokens with a forged signature → ${r.status} ${(await r.json()).error}`);

// Principal pulls the plug. FareScout's next attempt is refused.
const rev = await principal.revoke(got.mandate.id);
say("principal", `revoked ${rev.revoked.length} mandates`);
say("airline", "its cached status is good for up to 30s (the issuer's ttl); waiting it out…");
await new Promise((res) => setTimeout(res, 27_000));
r = await fetch(`${airline}/book`, { method: "POST", headers: { "content-type": "application/json", ...farescout.headers([got.token, sub.token], body) }, body: JSON.stringify(body) });
say("farescout", `POST /book after revocation → ${r.status} ${(await r.json()).error}`);

const status = await (await fetch(`${ISSUER}/r/${got.mandate.id}`)).json();
say("issuer", `tree ${got.mandate.id}: ${status.status.status}, spent $${status.status.spent / 100}`);
