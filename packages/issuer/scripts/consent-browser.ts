/**
 * Drives the real consent page in headless Chromium with a virtual authenticator (CDP WebAuthn), against a live issuer.
 *
 *   WARRANT_BASE=https://<ref>.supabase.co/functions/v1/warrant npx tsx scripts/consent-browser.ts
 *
 * Steps: an agent files a request → the page is opened from localhost (allowed in development mode) → demo-wallet sign-in →
 * passkey created → per-transaction cap lowered → approved with the passkey → the agent collects a mandate whose hop 0 is
 * an ES256/WebAuthn signature → a counterparty verifies it with the core verifier (no issuer trust needed for hop 0).
 */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { chromium } from "playwright";
import { b64url, decodeMandate, keyPairFromSecret, signJson, verifyAction, signAction, sha256Hex, canonicalize, unb64url, type Mandate } from "../../core/src/index.ts";
import { AgentClient } from "../../node/src/index.ts";

const BASE = (process.env.WARRANT_BASE ?? "").replace(/\/$/, "");
if (!BASE) throw new Error("set WARRANT_BASE");
const seed = (n: number) => new Uint8Array(32).map((_, i) => (i * 11 + n * 29) % 256);
const demoRoot = keyPairFromSecret("demo-wallet:signer-1", seed(100));
const tripwiseKey = keyPairFromSecret("did:web:agents.tripwise.com#k1", seed(4));
const log = (m: string) => console.log("  " + m);

// 1. Serve the exported consent page on localhost.
const html = readFileSync(new URL("../web/consent.html", import.meta.url));
const server = createServer((_req, res) => { res.setHeader("content-type", "text/html; charset=utf-8"); res.end(html); });
await new Promise<void>((r) => server.listen(4455, r));
const PAGE = `http://localhost:4455/consent.html`;

// 2. The agent asks for a mandate.
const tripwise = new AgentClient(tripwiseKey, BASE, { operator: "Tripwise Inc.", runtime: "attest:2026.11.1" });
await tripwise.register();
const now = Math.floor(Date.now() / 1000);
const req = await tripwise.requestMandate({
  purpose: "Book your Singapore trip, 14–18 Nov",
  scope: { may: ["travel:search", "travel:book_flight", "travel:book_hotel", "travel:cancel_own_booking"], may_not: ["payments:change_method", "travel:book_for_others", "identity:share_documents"], counterparties: ["iata:*", "api:booking.com", "api:expedia.com"] },
  limits: { ccy: "USD", total: 150000, per_txn: 60000, confirm_over: 50000, confirm_on: ["travel:cancel_own_booking"] },
  delegation: { max_depth: 2, attenuate: true },
  nbf: now, exp: now + 7 * 86400,
});
log(`request ${req.request_id}`);

// 3. The principal, in a browser with a virtual authenticator.
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
page.on("pageerror", (e) => console.error("page error:", e.message));
const failed: string[] = [];
page.on("response", (r) => { if (r.status() >= 400) failed.push(`${r.status()} ${r.request().method()} ${r.url().replace(BASE, "")}`); });

await page.goto(`${PAGE}?issuer=${encodeURIComponent(BASE)}&request=${req.request_id}`);
await page.waitForSelector("#demoBtn");
log("page loaded: " + (await page.textContent("#title"))!.trim().slice(0, 70));
await page.fill("#demoName", "Ashan " + Date.now().toString(36));
await page.click("#demoBtn");
await page.waitForSelector("#pkBtn");
log("signed in with demo-wallet; no passkey yet");
await page.click("#pkBtn");
await page.waitForSelector("#approve", { timeout: 20000 });
const creds = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
log(`passkey created in the virtual authenticator (${creds.credentials.length} credential) and registered with the issuer`);
log("summary: " + (await page.textContent("#summary"))!.replace(/\s+/g, " ").trim().slice(0, 140) + "…");
await page.click("#toggle");
await page.fill("#per_txn", "550");
await page.dispatchEvent("#per_txn", "input");
log("per-transaction cap lowered to $550 (agent asked $600)");
await page.click("#approve");
try {
  await page.waitForSelector("text=Mandate issued", { timeout: 30000 });
} catch (e) {
  console.error("approve did not complete. page error text:", await page.textContent(".err").catch(() => "(none)"));
  console.error("approve button:", await page.textContent("#approve").catch(() => "(gone)"));
  console.error("HTTP failures:", failed);
  throw e;
}
const signedBy = await page.textContent("dd:has-text('principal')");
log("page shows: Mandate issued · " + signedBy?.trim());
await browser.close();
server.close();
if (failed.length) { console.error("HTTP failures during the flow:", failed); process.exit(1); }

// 4. The agent collects the token; a counterparty verifies hop 0 locally.
const got = await tripwise.awaitMandate(req.request_id, { timeoutMs: 10000 });
if (!got) throw new Error("agent did not get the mandate");
const m: Mandate = got.mandate;
if (m.sig[0].alg !== "ES256" || !m.sig[0].webauthn || !m.principal.key.startsWith("p256:")) throw new Error("hop 0 is not a passkey signature: " + JSON.stringify(m.sig[0]));
if (m.limits.per_txn !== 55000) throw new Error("per_txn not lowered: " + m.limits.per_txn);
log(`agent holds ${m.id} · principal.key ${m.principal.key.slice(0, 16)}… · sig[0] ${m.sig[0].alg} via WebAuthn · per_txn ${m.limits.per_txn}`);

const disco = await (await fetch(`${BASE}/.well-known/warrant.json`)).json();
const status = await (await fetch(`${BASE}/r/${m.id}`)).json();
const hash = sha256Hex(canonicalize({ flight: "SQ529", fare: 47800 }));
const verdict = verifyAction(
  { chain: [m], action: { type: "travel:book_flight", amount: 47800, ccy: "USD", counterparty: "iata:SQ", hash, ...signAction(hash, tripwiseKey) }, status },
  { now: Math.floor(Date.now() / 1000), keys: (kid) => ({ [disco.keys[0].kid]: unb64url(disco.keys[0].public_key), [tripwiseKey.kid]: tripwiseKey.publicKey })[kid], trustedRoots: { "demo-wallet": { publicKey: demoRoot.publicKey } }, issuerId: disco.issuer, webauthn: { origin: "http://localhost:4455", rpId: "localhost" } },
);
if (verdict.decision !== "allow") throw new Error("counterparty verdict " + verdict.decision + " " + verdict.reason + " " + JSON.stringify(verdict.checks.at(-1)));
log(`counterparty verifies the passkey-signed chain locally → ${verdict.decision} (${verdict.checks[0].detail})`);
const over = verifyAction({ chain: [m], action: { type: "travel:book_flight", amount: 56000, ccy: "USD", counterparty: "iata:SQ", hash, ...signAction(hash, tripwiseKey) }, status }, { now: Math.floor(Date.now() / 1000), keys: (kid) => ({ [disco.keys[0].kid]: unb64url(disco.keys[0].public_key), [tripwiseKey.kid]: tripwiseKey.publicKey })[kid], trustedRoots: { "demo-wallet": { publicKey: demoRoot.publicKey } }, issuerId: disco.issuer });
log(`$560 booking → ${over.decision} · ${over.reason} (the cap the principal set in the browser holds)`);
console.log("\nall good");
void b64url; void signJson; void decodeMandate;
