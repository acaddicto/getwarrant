/**
 * Emits vectors/v0.1.json: deterministic mandates, chains, actions, statuses and the verdicts
 * a conforming verifier MUST return for each. Other implementations run these to prove conformance.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { encodeMandate } from "../src/mandate.js";
import { verifyAction } from "../src/verify.js";
import { b64url } from "../src/canon.js";
import { action, buildFarescout, buildTripwise, ISSUER_ID, keys, NOW, resolver, status, trustedRoots } from "../test/fixture.js";

const tripwise = buildTripwise();
const farescout = buildFarescout(tripwise);
const ctx = { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID };

const cases = [
  { name: "hop2_allow", chain: [tripwise, farescout], action: action(), status: status() },
  { name: "hop1_allow_hotel", chain: [tripwise], action: action({ by: keys.tripwise, type: "travel:book_hotel", counterparty: "api:booking.com" }), status: status() },
  { name: "hop2_confirm_over_threshold", chain: [tripwise, farescout], action: action({ amount: 54000 }), status: status() },
  { name: "hop1_confirm_on_cancel", chain: [tripwise], action: action({ by: keys.tripwise, type: "travel:cancel_own_booking", amount: 0 }), status: status() },
  { name: "deny_bad_signature_rogue_agent", chain: [tripwise, farescout], action: action({ by: keys.rogue }), status: status() },
  { name: "deny_revoked", chain: [tripwise, farescout], action: action(), status: status({ status: "revoked", reason: "principal" }) },
  { name: "deny_stale_status", chain: [tripwise, farescout], action: action(), status: status({}, NOW - 200) },
  { name: "deny_out_of_scope_may_not", chain: [tripwise], action: action({ by: keys.tripwise, type: "payments:change_method", amount: undefined, ccy: undefined }), status: status() },
  { name: "deny_out_of_scope_subagent_hotel", chain: [tripwise, farescout], action: action({ type: "travel:book_hotel", counterparty: "api:booking.com" }), status: status() },
  { name: "deny_over_limit_per_txn", chain: [tripwise, farescout], action: action({ amount: 60001 }), status: status() },
  { name: "deny_over_limit_tree_total", chain: [tripwise, farescout], action: action(), status: status({ spent: 20000 }) },
];

const out = {
  spec: "warrant/0.1",
  generated_by: "@getwarrant/core",
  context: {
    now: NOW,
    issuer_id: ISSUER_ID,
    trusted_roots: { "eudi-wallet": { public_key: b64url(keys.root.publicKey) } },
    keys: Object.fromEntries(Object.values(keys).map((k) => [k.kid, b64url(k.publicKey)])),
  },
  mandates: { tripwise, farescout, tripwise_token: encodeMandate(tripwise), farescout_token: encodeMandate(farescout) },
  cases: cases.map((c) => {
    const verdict = verifyAction({ chain: c.chain, action: c.action, status: c.status }, ctx);
    return {
      name: c.name,
      chain: c.chain.map((m) => m.id),
      action: c.action,
      status: c.status,
      expect: { decision: verdict.decision, reason: verdict.reason, failed_step: verdict.checks.find((k) => !k.ok)?.step ?? null },
    };
  }),
};

mkdirSync(new URL("../../../vectors/", import.meta.url), { recursive: true });
writeFileSync(new URL("../../../vectors/v0.1.json", import.meta.url), JSON.stringify(out, null, 2));
console.log(`wrote ${out.cases.length} cases`);
for (const c of out.cases) console.log(`  ${c.name.padEnd(36)} ${c.expect.decision}${c.expect.reason ? " · " + c.expect.reason : ""}`);
