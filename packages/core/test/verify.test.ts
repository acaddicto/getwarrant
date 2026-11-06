import { describe, expect, it } from "vitest";
import { verifyAction } from "../src/verify.ts";
import { decodeMandate, encodeMandate, issueMandate, validateShape } from "../src/mandate.ts";
import { delegate } from "../src/delegate.ts";
import { checkAttenuation, effective } from "../src/attenuate.ts";
import { canonicalize } from "../src/canon.ts";
import { buildRecord, recordHash, resolveConfirm, signRecordAsIssuer, signRecordAsVerifier, verifyLedger } from "../src/ledger.ts";
import { issueStatus } from "../src/status.ts";
import { action, buildFarescout, buildTripwise, draft, ISSUER_ID, keys, NOW, resolver, status, T0, T0_MS, trustedRoots } from "./fixture.ts";
import type { Mandate } from "../src/types.ts";

const tripwise = buildTripwise();
const farescout = buildFarescout(tripwise);
const ctx = { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID };
const run = (over: Partial<Parameters<typeof verifyAction>[0]> = {}, c = ctx) =>
  verifyAction({ chain: [tripwise, farescout], action: action(), status: status(), ...over }, c);

describe("canonicalisation", () => {
  it("sorts keys and drops undefined", () => {
    expect(canonicalize({ b: 1, a: [1, { d: undefined, c: "x" }] })).toBe('{"a":[1,{"c":"x"}],"b":1}');
  });
});

describe("mandate issue and encode", () => {
  it("produces a shape-valid mandate with principal then issuer signatures", () => {
    expect(validateShape(tripwise)).toEqual([]);
    expect(tripwise.sig.map((s) => s.by)).toEqual(["principal", "issuer"]);
    expect(tripwise.revocation).toBe(`https://warrant.example/r/${tripwise.id}`);
  });
  it("round-trips through the wire form", () => {
    const token = encodeMandate(tripwise);
    expect(token.startsWith("wrt.")).toBe(true);
    expect(decodeMandate(token)).toEqual(tripwise);
  });
  it("rejects a lifetime over 90 days and float amounts", () => {
    expect(() => issueMandate({ ...draft, exp: T0 + 91 * 86400 }, { issuerBase: "https://x", principalKey: keys.principal, issuerKey: keys.issuer })).toThrow(/90 days/);
    expect(() => issueMandate({ ...draft, limits: { ...draft.limits, per_txn: 12.5 } }, { issuerBase: "https://x", principalKey: keys.principal, issuerKey: keys.issuer })).toThrow(/integer/);
  });
});

describe("delegation and attenuation", () => {
  it("sub-mandate copies parent signatures and appends the delegating agent's", () => {
    expect(farescout.sig.slice(0, 2)).toEqual(tripwise.sig);
    expect(farescout.sig[2]).toMatchObject({ by: "agent", did: "did:web:agents.tripwise.com", kid: keys.tripwise.kid });
    expect(farescout.delegation.max_depth).toBe(1);
    expect(checkAttenuation(tripwise, farescout)).toEqual([]);
  });
  it("refuses every kind of widening", () => {
    const widen = (patch: (c: Mandate) => void) => {
      const c = structuredClone(farescout);
      patch(c);
      return checkAttenuation(tripwise, c);
    };
    expect(widen((c) => c.scope.may.push("payments:refund"))[0]).toMatch(/scope.may/);
    expect(widen((c) => (c.scope.may_not = []))[0]).toMatch(/may_not: child dropped/);
    expect(widen((c) => c.scope.counterparties.push("api:expedia.co.uk"))[0]).toMatch(/counterparties/);
    expect(widen((c) => (c.limits.per_txn = 70000))[0]).toMatch(/per_txn/);
    expect(widen((c) => (c.limits.total = 200000))[0]).toMatch(/total/);
    expect(widen((c) => (c.limits.confirm_over = 90000))[0]).toMatch(/confirm_over/);
    expect(widen((c) => (c.limits.confirm_on = []))[0]).toMatch(/confirm_on/);
    expect(widen((c) => (c.delegation.max_depth = 2))[0]).toMatch(/max_depth/);
    expect(widen((c) => (c.exp = tripwise.exp + 1))[0]).toMatch(/exp/);
    expect(widen((c) => (c.principal = { ...c.principal, sub: "someone_else" }))[0]).toMatch(/principal/);
  });
  it("delegate() throws on widening and on depth 0", async () => {
    expect(() => delegate(tripwise, { agentKey: keys.tripwise, child: { agent: { did: "did:web:farescout.ai" }, scope: { may: ["payments:refund"], counterparties: ["*"] }, limits: {} } })).toThrow(/widened|scope/);
    // farescout has max_depth 1: one more level is allowed, and that level gets max_depth 0.
    const deeper = delegate(farescout, { agentKey: keys.farescout, child: { agent: { did: "did:web:deeper.ai" }, scope: farescout.scope, limits: farescout.limits } });
    expect(deeper.delegation.max_depth).toBe(0);
    const { keyPairFromSecret } = await import("../src/crypto.ts");
    const deeperKey = keyPairFromSecret("did:web:deeper.ai#k1", new Uint8Array(32).fill(9));
    expect(() => delegate(deeper, { agentKey: deeperKey, child: { agent: { did: "did:web:deepest.ai" }, scope: deeper.scope, limits: deeper.limits } })).toThrow(/max_depth 0/);
  });
  it("delegate() refuses a key that does not belong to the parent's agent", () => {
    expect(() => delegate(tripwise, { agentKey: keys.rogue, child: { agent: { did: "did:web:farescout.ai" }, scope: farescout.scope, limits: farescout.limits } })).toThrow(/does not belong/);
  });
  it("effective() is the intersection", () => {
    const eff = effective([tripwise, farescout]);
    expect(eff.scope.may).toEqual(["travel:book_flight"]);
    expect(eff.limits.total).toBe(60000);
    expect(eff.scope.counterparties).toEqual(["iata:*"]);
  });
});

describe("verifier: happy paths", () => {
  it("allows an in-scope booking under the confirm threshold at hop 2", () => {
    const v = run();
    expect(v.decision).toBe("allow");
    expect(v.hop).toBe(2);
    expect(v.checks.every((c) => c.ok)).toBe(true);
    expect(v.checks.length).toBe(7);
  });
  it("allows at hop 1 with Tripwise acting directly", () => {
    const v = run({ chain: [tripwise], action: action({ by: keys.tripwise, type: "travel:book_hotel", counterparty: "api:booking.com" }) });
    expect(v.decision).toBe("allow");
  });
  it("returns confirm above the threshold", () => {
    expect(run({ action: action({ amount: 54000 }) }).decision).toBe("confirm");
  });
  it("returns confirm for a confirm_on action regardless of amount", () => {
    const v = run({ chain: [tripwise], action: action({ by: keys.tripwise, type: "travel:cancel_own_booking", amount: 0 }) });
    expect(v.decision).toBe("confirm");
  });
  it("is deterministic", () => {
    expect(run()).toEqual(run());
  });
});

describe("verifier: the seven checks fail in order", () => {
  it("1 bad_signature: tampered scope", () => {
    const t = structuredClone(farescout);
    t.scope.may.push("travel:book_hotel");
    const v = run({ chain: [tripwise, t] });
    expect(v).toMatchObject({ decision: "deny", reason: "bad_signature" });
    expect(v.checks.at(-1)?.step).toBe(1);
  });
  it("1 bad_signature: unknown agent presents the chain", () => {
    expect(run({ action: action({ by: keys.rogue }) }).reason).toBe("bad_signature");
  });
  it("1 bad_chain: sub-mandate whose parent is not the hop before", () => {
    const orphan = { ...farescout, parent: "wrt_01JBQ9F3M2XXXXXXXXXXXXXXXX" };
    expect(run({ chain: [tripwise, orphan] }).reason).toBe("bad_chain");
  });
  it("2 principal_unverified: untrusted root", () => {
    expect(run({}, { ...ctx, trustedRoots: {} }).reason).toBe("principal_unverified");
  });
  it("2 principal_unverified: assurance too low for spend", async () => {
    const { issueRootAssertion } = await import("../src/mandate.ts");
    const low = issueRootAssertion({ root: "eudi-wallet", sub: "pw_7f31c2a9", aud: ISSUER_ID, level: "low", iat: T0, exp: T0 + 86400 }, keys.root);
    const m = issueMandate({ ...draft, principal: { ...draft.principal, assertion: low } }, { issuerBase: "https://warrant.example", principalKey: keys.principal, issuerKey: keys.issuer, id: tripwise.id });
    const spend = verifyAction({ chain: [m], action: action({ by: keys.tripwise }), status: status() }, ctx);
    expect(spend.reason).toBe("principal_unverified");
    const read = verifyAction({ chain: [m], action: action({ by: keys.tripwise, type: "travel:search", amount: undefined, ccy: undefined }), status: status() }, ctx);
    expect(read.decision).toBe("allow");
  });
  it("3 revoked", () => {
    expect(run({ status: status({ status: "revoked", reason: "principal" }) }).reason).toBe("revoked");
  });
  it("3 stale: status older than ttl + skew", () => {
    expect(run({ status: status({}, NOW - 200) }).reason).toBe("stale");
  });
  it("3 stale: status signed by someone other than the issuer", () => {
    const forged = issueStatus({ id: tripwise.id, status: "active", spent: 0, asof: NOW, ttl: 30 }, keys.rogue);
    expect(run({ status: forged }).reason).toBe("stale");
  });
  it("3 expired / not_yet_valid by clock", () => {
    expect(run({ status: status({}, tripwise.exp + 500) }, { ...ctx, now: tripwise.exp + 500 }).reason).toBe("expired");
    expect(run({ status: status({}, T0 - 500) }, { ...ctx, now: T0 - 500 }).reason).toBe("not_yet_valid");
  });
  it("4 widened: a correctly signed sub-mandate that widens (issuer bug) is still refused", async () => {
    // Build a child that passes signing but breaks attenuation by signing it ourselves.
    const wide = structuredClone(farescout);
    wide.limits.per_txn = 70000;
    wide.limits.total = 70000;
    wide.sig = wide.sig.slice(0, 2);
    const signed = { ...wide, sig: [...wide.sig, { ...farescout.sig[2], value: "" }] };
    // Re-sign with Tripwise's key so check 1 passes.
    const { signJson } = await import("../src/crypto.ts");
    const { signingPayload } = await import("../src/mandate.ts");
    signed.sig[2] = { ...signed.sig[2], value: signJson(signingPayload(signed as Mandate, 2), keys.tripwise.secretKey) };
    const v = run({ chain: [tripwise, signed as Mandate] });
    expect(v.reason).toBe("widened");
    expect(v.checks.at(-1)?.step).toBe(4);
  });
  it("5 out_of_scope: may_not wins", () => {
    expect(run({ chain: [tripwise], action: action({ by: keys.tripwise, type: "payments:change_method", amount: undefined, ccy: undefined }) }).reason).toBe("out_of_scope");
  });
  it("5 out_of_scope: sub-agent tries an action only its parent may do", () => {
    expect(run({ action: action({ type: "travel:book_hotel", counterparty: "api:booking.com" }) }).reason).toBe("out_of_scope");
  });
  it("5 out_of_scope: wrong counterparty", () => {
    expect(run({ action: action({ counterparty: "api:ryanair.com" }) }).reason).toBe("out_of_scope");
  });
  it("6 over_limit: per_txn", () => {
    expect(run({ action: action({ amount: 60001 }) }).reason).toBe("over_limit");
  });
  it("6 over_limit: tree total already spent", () => {
    expect(run({ status: status({ spent: 20000 }) }).reason).toBe("over_limit"); // 20000 + 47800 > 60000 effective
  });
  it("6 over_limit: wrong currency", () => {
    expect(run({ action: action({ ccy: "EUR" }) }).reason).toBe("over_limit");
  });
  it("6 over_limit: no spending authority", () => {
    const readOnly = issueMandate({ ...draft, limits: {} }, { issuerBase: "https://warrant.example", principalKey: keys.principal, issuerKey: keys.issuer, id: tripwise.id });
    const v = verifyAction({ chain: [readOnly], action: action({ by: keys.tripwise }), status: status() }, ctx);
    expect(v.reason).toBe("over_limit");
  });
});

describe("ledger", () => {
  it("builds a hash-chained, verifiable ledger and resolves a confirm", () => {
    const v1 = run();
    const r1 = signRecordAsIssuer(signRecordAsVerifier(buildRecord({ verdict: v1, chain: [tripwise, farescout], action: action(), status: status(), counterparty: "iata:SQ", prev: null, atMs: T0_MS + 130_000 }), keys.airline), keys.issuer);
    const v2 = run({ action: action({ amount: 54000 }) });
    const r2 = signRecordAsVerifier(buildRecord({ verdict: v2, chain: [tripwise, farescout], action: action({ amount: 54000 }), status: status(), counterparty: "iata:SQ", prev: recordHash(r1), atMs: T0_MS + 140_000 }), keys.airline);
    expect(r2.confirm?.ref).toMatch(/^cfm_/);
    const r2done = resolveConfirm(r2, "allow", T0_MS + 200_000);
    expect(verifyLedger([r1, r2], resolver)).toBeNull();
    expect(verifyLedger([r2, r1], resolver)).toMatch(/prev/);
    const tampered = structuredClone(r1);
    tampered.action.amount = 1;
    expect(verifyLedger([tampered, r2], resolver)).toMatch(/signature/);
    expect(r2done.confirm?.reply).toBe("allow");
  });
});
