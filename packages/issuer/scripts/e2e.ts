/**
 * End-to-end walk of the hosted issuer with the Tripwise scenario.
 *
 *   WARRANT_BASE=https://<ref>.supabase.co/functions/v1/warrant npx tsx scripts/e2e.ts
 *
 * Needs a "demo-wallet" root seeded with the public key derived from DEMO_ROOT_SEED (see README).
 */
import {
  buildRecord, canonicalize, decodeMandate, delegate, keyPairFromSecret, issueRootAssertion, signAction, signJson, signRecordAsVerifier,
  verifyAction, verifyJson, unb64url, b64url, sha256Hex, recordHash, type Mandate, type SignedStatus, type Action,
} from "../../core/src/index.ts";

const BASE = (process.env.WARRANT_BASE ?? "").replace(/\/$/, "");
if (!BASE) throw new Error("set WARRANT_BASE");
const seed = (n: number) => new Uint8Array(32).map((_, i) => (i * 11 + n * 29) % 256);
export const DEMO_ROOT_SEED = seed(100);

const root = keyPairFromSecret("demo-wallet:signer-1", DEMO_ROOT_SEED);
const principal = keyPairFromSecret("", seed(1));
principal.kid = "key:" + b64url(principal.publicKey);
const tripwise = keyPairFromSecret("did:web:agents.tripwise.com#k1", seed(4));
const farescout = keyPairFromSecret("did:web:farescout.ai#k1", seed(5));
const airline = keyPairFromSecret("did:web:singaporeair.com#verifier", seed(7));
const hotel = keyPairFromSecret("did:web:booking.com#verifier", seed(8));

let step = 0;
const log = (m: string) => console.log(`${String(++step).padStart(2)}. ${m}`);
const assert = (c: unknown, m: string) => { if (!c) throw new Error("ASSERT " + m); };
async function api(method: string, path: string, body?: unknown, auth?: string) {
  const res = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${JSON.stringify(j)}`);
  return j;
}

const now = () => Math.floor(Date.now() / 1000);
const disco = await api("GET", "/.well-known/warrant.json");
log(`issuer ${disco.issuer}, key ${disco.keys[0].kid}`);
const issuerPk = unb64url(disco.keys[0].public_key);
const roots = await api("GET", "/roots");
assert(roots.roots.some((r: any) => r.id === "demo-wallet" && r.public_key === b64url(root.publicKey)), "demo-wallet root seeded with the expected key");

// Agents register their keys (stand-in for DID resolution).
for (const k of [tripwise, farescout]) await api("POST", "/agents", { did: k.kid.split("#")[0], kid: k.kid, public_key: b64url(k.publicKey), operator: k === tripwise ? "Tripwise Inc." : "FareScout" });
log("agent keys registered");

// Tripwise asks for a mandate.
const draft = {
  purpose: "Book your Singapore trip, 14–18 Nov",
  scope: { may: ["travel:search", "travel:book_flight", "travel:book_hotel", "travel:cancel_own_booking"], may_not: ["payments:change_method", "travel:book_for_others", "identity:share_documents"], counterparties: ["iata:*", "api:booking.com", "api:expedia.com"] },
  limits: { ccy: "USD", total: 150000, per_txn: 60000, confirm_over: 50000, confirm_on: ["travel:cancel_own_booking"] },
  delegation: { max_depth: 2, attenuate: true },
  nbf: now(), exp: now() + 7 * 86400,
};
const agentRef = { did: "did:web:agents.tripwise.com", kid: tripwise.kid, runtime: "attest:2026.11.1" };
const reqRes = await api("POST", "/requests", { agent: agentRef, draft, sig: signJson({ agent: agentRef, draft }, tripwise.secretKey) });
log(`request ${reqRes.request_id} → consent ${reqRes.consent_url}`);
const shown = await api("GET", `/requests/${reqRes.request_id}`);
assert(shown.agent.operator === "Tripwise Inc.", "consent screen sees the operator");

// Principal: root assertion is the login; lowers per_txn to $500 and approves.
const assertion = issueRootAssertion({ root: "demo-wallet", sub: "pw_e2e_" + Date.now().toString(36), aud: disco.issuer, level: "high", iat: now(), exp: now() + 86400 }, root);
const AUTH = `Warrant-Principal ${assertion}`;
const prep = await api("POST", `/requests/${reqRes.request_id}/prepare`, { key: principal.kid, limits: { per_txn: 50000 } }, AUTH);
assert(prep.unsigned.limits.per_txn === 50000 && prep.unsigned.limits.total === 150000, "principal narrowed per_txn only");
const approved = await api("POST", `/requests/${reqRes.request_id}/approve`, { sig: signJson(JSON.parse(prep.payload_to_sign), principal.secretKey) }, AUTH);
const mandate: Mandate = decodeMandate(approved.token);
log(`mandate ${mandate.id} issued · sig by ${mandate.sig.map((s) => s.by).join(", ")}`);
assert(verifyJson(mandate.sig[1].value, { ...mandate, sig: [mandate.sig[0]] }, issuerPk), "issuer co-signature verifies against the published key");
const polled = await api("GET", `/requests/${reqRes.request_id}/token`);
assert(polled.token === approved.token, "agent can collect the token by polling");

// Tripwise delegates flight booking to FareScout and registers the sub-mandate.
const sub = delegate(mandate, { agentKey: tripwise, child: { agent: { did: "did:web:farescout.ai" }, scope: { may: ["travel:book_flight"], may_not: mandate.scope.may_not, counterparties: ["iata:*"] }, limits: { ccy: "USD", total: 50000, per_txn: 50000, confirm_over: 50000, confirm_on: mandate.limits.confirm_on } } });
const { encodeMandate } = await import("../../core/src/index.ts");
const subRes = await api("POST", "/mandates", { token: encodeMandate(sub) });
log(`sub-mandate ${sub.id} registered at hop ${subRes.hop}`);
// A widened sub-mandate is refused by the issuer too.
const wide = { ...sub, limits: { ...sub.limits, per_txn: 60000, total: 60000 } };
await api("POST", "/mandates", { token: encodeMandate(wide) }).then(() => assert(false, "widened sub-mandate must be refused"), (e) => assert(/widened|bad_signature/.test(String(e)), "widened sub-mandate refused: " + e.message.slice(0, 80)));

// Counterparty side: airline verifies FareScout's $478 booking.
const keys = (kid: string) => ({ [principal.kid]: principal.publicKey, [disco.keys[0].kid]: issuerPk, [tripwise.kid]: tripwise.publicKey, [farescout.kid]: farescout.publicKey, [airline.kid]: airline.publicKey, [hotel.kid]: hotel.publicKey })[kid];
const ctx = { now: now(), keys, trustedRoots: { "demo-wallet": { publicKey: root.publicKey } }, issuerId: disco.issuer };
const status1: SignedStatus = await api("GET", `/r/${sub.id}`);
assert(status1.status.id === mandate.id && status1.status.status === "active", "status keyed by tree root, active");
const flightHash = sha256Hex(canonicalize({ flight: "SQ529", date: "2026-11-14", fare: 47800 }));
const flight: Action = { type: "travel:book_flight", amount: 47800, ccy: "USD", counterparty: "iata:SQ", hash: flightHash, ...signAction(flightHash, farescout) };
const v1 = verifyAction({ chain: [mandate, sub], action: flight, status: status1 }, { ...ctx, now: now() });
assert(v1.decision === "allow", "flight allowed: " + JSON.stringify(v1.checks.at(-1)));
const r1 = signRecordAsVerifier(buildRecord({ verdict: v1, chain: [mandate, sub], action: flight, status: status1, counterparty: "iata:SQ", prev: null }), airline);
const l1 = await api("POST", `/l/${mandate.id}`, r1);
log(`ledger seq ${l1.seq} · allow · issuer countersigned`);
const status2: SignedStatus = await api("GET", `/r/${mandate.id}`);
assert(status2.status.spent === 47800, "spent bumped to 47800, got " + status2.status.spent);

// Hotel: $540 hold trips the confirm threshold.
const hotelHash = sha256Hex(canonicalize({ hotel: "Hotel Jen Orchardgateway", nights: 4, total: 54000 }));
const hold: Action = { type: "travel:book_hotel", amount: 54000, ccy: "USD", counterparty: "api:booking.com", hash: hotelHash, ...signAction(hotelHash, tripwise) };
const v2 = verifyAction({ chain: [mandate], action: hold, status: status2 }, { ...ctx, now: now() });
assert(v2.decision === "confirm", "hotel hold needs confirm");
// prev must be the issuer-countersigned hash of record 1.
const r2 = signRecordAsVerifier(buildRecord({ verdict: v2, chain: [mandate], action: hold, status: status2, counterparty: "api:booking.com", prev: l1.hash }), hotel);
const l2 = await api("POST", `/l/${mandate.id}`, r2);
log(`ledger seq ${l2.seq} · confirm ${l2.confirm_ref} · polling ${l2.poll}`);
let c = await api("GET", `/confirm/${l2.confirm_ref}`);
assert(c.decision === "confirm" && c.state === "pending", "confirm pending");
// Wrong prev is rejected.
await api("POST", `/l/${mandate.id}`, { ...r2, ref: "led_" + r2.ref.slice(4, 8) + "X".repeat(22), prev: null }).then(() => assert(false, "bad prev accepted"), (e) => assert(/prev_mismatch|malformed|duplicate/.test(String(e)), "bad prev refused"));
// Principal approves.
const replyBody = { confirm: l2.confirm_ref, mandate: mandate.id, action_hash: hotelHash, amount: 54000, reply: "allow" };
await api("POST", `/confirm/${l2.confirm_ref}/reply`, { reply: "allow", sig: signJson(replyBody, principal.secretKey) }, AUTH);
c = await api("GET", `/confirm/${l2.confirm_ref}`);
assert(c.decision === "allow", "confirm resolved to allow");
const status3: SignedStatus = await api("GET", `/r/${mandate.id}`);
assert(status3.status.spent === 47800 + 54000, "spent includes the confirmed hold, got " + status3.status.spent);
log(`principal confirmed · spent now ${status3.status.spent}`);

// Principal views.
const list = await api("GET", "/mandates", undefined, AUTH);
assert(list.mandates.length === 2, "principal sees both hops");
const detail = await api("GET", `/mandates/${mandate.id}`, undefined, AUTH);
assert(detail.children.length === 1 && detail.ledger_count >= 3, "detail shows child and ledger");
const exp = await api("GET", `/mandates/${mandate.id}/export`, undefined, AUTH);
const { sig: exportSig, ...exportBody } = exp;
assert(verifyJson(exportSig.value, exportBody, issuerPk), "export signature verifies");
assert(exp.ledger.length >= 3 && exp.chain_head, "export carries the ledger and chain head");
log(`export: ${exp.mandates.length} mandates, ${exp.ledger.length} records, head ${String(exp.chain_head).slice(0, 12)}…`);

// Revoke: cascades to FareScout; verifier then denies.
const rev = await api("POST", `/mandates/${mandate.id}/revoke`, { reason: "trip cancelled" }, AUTH);
assert(rev.revoked.includes(mandate.id) && rev.revoked.includes(sub.id), "both hops revoked");
const status4: SignedStatus = await api("GET", `/r/${sub.id}`);
assert(status4.status.status === "revoked", "status reports revoked");
const v3 = verifyAction({ chain: [mandate, sub], action: flight, status: status4 }, { ...ctx, now: now() });
assert(v3.decision === "deny" && v3.reason === "revoked", "verifier denies after revocation");
const rl = await api("GET", "/revocations");
assert(rl.revoked.some((r: any) => r.id === sub.id), "revocation list carries the sub-mandate");
log(`revoked ${rev.revoked.length} mandates · verifier now returns deny · revocation list has ${rl.revoked.length} entries`);

assert(recordHash(r1) === l1.hash, "issuer and verifier agree on the record hash");
console.log("\nall good");
