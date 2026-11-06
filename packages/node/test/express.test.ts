import { describe, expect, it, beforeAll, afterAll } from "vitest";
import express from "express";
import type { Server } from "node:http";
import { b64url, hashJson, issueStatus, keyPairFromSecret, recordHash, type LedgerRecord } from "@getwarrant/core";
import { buildFarescout, buildTripwise, keys, ISSUER_ID, NOW } from "../../core/test/fixture.ts";
import { IssuerClient, Verifier, warrantExpress, AgentClient, guardTool, warrantArgs } from "../src/index.ts";

const tripwise = buildTripwise();
const farescout = buildFarescout(tripwise);
const ledger: LedgerRecord[] = [];
let revoked = false;
const confirms = new Map<string, "allow" | "confirm" | "deny">();

// A fake issuer: just enough routes for the verifier path.
const fakeFetch: typeof fetch = async (input, init) => {
  const url = new URL(String(input));
  const p = url.pathname;
  const j = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  if (p.endsWith("/.well-known/warrant.json")) return j(200, { issuer: ISSUER_ID, spec: "warrant/0.1", keys: [{ kid: keys.issuer.kid, alg: "EdDSA", public_key: b64url(keys.issuer.publicKey) }], endpoints: {} });
  if (p.includes("/r/")) return j(200, issueStatus({ id: tripwise.id, status: revoked ? "revoked" : "active", spent: ledger.filter((r) => r.decision === "allow").reduce((a, r) => a + (r.action.amount ?? 0), 0), asof: NOW, ttl: 30 }, keys.issuer));
  if (p.includes("/agents/")) {
    const did = decodeURIComponent(p.split("/agents/")[1]);
    const k = Object.values(keys).find((k) => k.kid.startsWith(did + "#"));
    return k ? j(200, { did, keys: [{ kid: k.kid, public_key: b64url(k.publicKey) }] }) : j(404, { error: "not_found" });
  }
  if (p.includes("/l/")) {
    const rec = JSON.parse(String(init?.body)) as LedgerRecord;
    const prev = ledger.length ? recordHash(ledger[ledger.length - 1]) : null;
    if (rec.prev !== prev) return j(409, { error: "prev_mismatch", message: `expected prev ${prev}` });
    ledger.push(rec);
    const out: any = { ref: rec.ref, seq: ledger.length, hash: recordHash(rec), issuer_sig: "x" };
    if (rec.decision === "confirm") { out.confirm_ref = rec.confirm!.ref; out.poll = "/confirm/" + rec.confirm!.ref; confirms.set(rec.confirm!.ref, "confirm"); }
    return j(201, out);
  }
  if (p.includes("/confirm/")) { const ref = p.split("/confirm/")[1]; return j(200, { decision: confirms.get(ref) ?? "deny", state: confirms.get(ref) ?? "deny" }); }
  return j(404, { error: "no_route", message: p });
};

const issuer = new IssuerClient("https://issuer.test", { fetch: fakeFetch });
const verifier = new Verifier({ issuer, counterparty: "iata:SQ", key: keys.airline, trustedRoots: { "eudi-wallet": keys.root.publicKey }, now: () => NOW, keys: (kid) => (kid === keys.principal.kid ? keys.principal.publicKey : undefined) });
const farescoutAgent = new AgentClient(keys.farescout, "https://issuer.test", { fetch: fakeFetch });
const tripwiseAgent = new AgentClient(keys.tripwise, "https://issuer.test", { fetch: fakeFetch });

let server: Server; let base: string;
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  const w = warrantExpress(verifier);
  app.post("/book", w.require({ action: "travel:book_flight" }), (req, res) => res.json({ booked: true, ledger: (req as any).warrant.ledger.ref }));
  app.post("/hold", w.require({ action: "travel:book_hotel" }), (_req, res) => res.json({ held: true }));
  await new Promise<void>((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${(server.address() as any).port}`;
});
afterAll(() => server.close());

const post = (path: string, body: unknown, headers: Record<string, string>) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

describe("express middleware", () => {
  it("401 without headers", async () => {
    const r = await post("/book", {}, {});
    expect(r.status).toBe(401);
  });
  it("allows an in-scope booking and posts a ledger record", async () => {
    const body = { flight: "SQ529", amount: 47800, ccy: "USD" };
    const r = await post("/book", body, farescoutAgent.headers([tripwise, farescout], body));
    expect(r.status).toBe(200);
    expect(r.headers.get("warrant-decision")).toBe("allow");
    expect(ledger.length).toBe(1);
    expect(ledger[0].counterparty).toBe("iata:SQ");
  });
  it("403 out_of_scope when the sub-agent books a hotel", async () => {
    const body = { hotel: "Jen", amount: 20000, ccy: "USD" };
    const r = await post("/hold", body, farescoutAgent.headers([tripwise, farescout], body));
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe("out_of_scope");
    expect(ledger.at(-1)?.decision).toBe("deny");
  });
  it("403 bad_signature when the body is altered after signing", async () => {
    const body = { flight: "SQ529", amount: 47800, ccy: "USD" };
    const h = farescoutAgent.headers([tripwise, farescout], body);
    const r = await post("/book", { ...body, amount: 1 }, h);
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe("bad_signature");
  });
  it("202 confirm above the threshold, with a confirm ref", async () => {
    const body = { hotel: "Jen", amount: 54000, ccy: "USD" };
    const r = await post("/hold", body, tripwiseAgent.headers([tripwise], body));
    expect(r.status).toBe(202);
    const j = await r.json();
    expect(j.confirm_ref).toMatch(/^cfm_/);
  });
  it("403 revoked once the issuer says so", async () => {
    revoked = true; issuer.forgetStatus(tripwise.id);
    const body = { flight: "SQ529", amount: 100, ccy: "USD" };
    const r = await post("/book", body, farescoutAgent.headers([tripwise, farescout], body));
    expect((await r.json()).error).toBe("revoked");
    revoked = false; issuer.forgetStatus(tripwise.id);
  });
});

describe("mcp guard", () => {
  it("runs the handler on allow and throws a typed error on deny", async () => {
    const tool = guardTool(verifier, { action: "travel:book_flight", amount: (a: any) => ({ amount: a.fare, ccy: "USD" }) }, async (args) => ({ pnr: "ABC123", for: args.flight }));
    const args = { flight: "SQ529", fare: 12000 }; // 47800 already spent in the tree; 12000 keeps FareScout under its 60000 total
    const ok = await tool({ ...args, _warrant: warrantArgs([tripwise, farescout], args, (h) => farescoutAgent.sign(h)) });
    expect(ok.pnr).toBe("ABC123");
    const bad = { flight: "SQ529", fare: 70000 };
    await expect(tool({ ...bad, _warrant: warrantArgs([tripwise, farescout], bad, (h) => farescoutAgent.sign(h)) })).rejects.toMatchObject({ code: "over_limit" });
  });
});
