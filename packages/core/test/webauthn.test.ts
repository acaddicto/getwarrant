import { describe, expect, it } from "vitest";
import * as p256mod from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64url, canonicalize, utf8 } from "../src/canon.ts";
import { generateP256KeyPair, p256KeyPairFromSecret, signP256, derToRaw, p256FromSpki } from "../src/crypto.ts";
import { buildUnsigned, coSign, issueMandate, signingPayload } from "../src/mandate.ts";
import { publicKeyFromKid } from "../src/keys.ts";
import { verifySignatureEntry, webauthnChallenge } from "../src/sigverify.ts";
import { verifyAction } from "../src/verify.ts";
import { action, draft, ISSUER_ID, keys, NOW, resolver, status, trustedRoots, TRIPWISE_ID } from "./fixture.ts";
import type { Signature } from "../src/types.ts";

const RP = "vvnvwrefyrrapjhmpajr.supabase.co", ORIGIN = `https://${RP}`;
const passkey = p256KeyPairFromSecret("", new Uint8Array(32).map((_, i) => (i * 3 + 7) % 256));
passkey.kid = "p256:" + b64url(passkey.publicKey);

/** What a browser's navigator.credentials.get() would hand back for `payload`, signed by `passkey`. */
function webauthnSign(payload: unknown, opts: { origin?: string; rp?: string; type?: string; der?: boolean; up?: boolean } = {}): Omit<Signature, "by" | "kid"> {
  const authData = new Uint8Array(37);
  authData.set(sha256(utf8(opts.rp ?? RP)), 0);
  authData[32] = opts.up === false ? 0x00 : 0x05; // UP + UV
  const cdj = utf8(JSON.stringify({ type: opts.type ?? "webauthn.get", challenge: webauthnChallenge(payload), origin: opts.origin ?? ORIGIN, crossOrigin: false }));
  const msg = new Uint8Array(authData.length + 32);
  msg.set(authData); msg.set(sha256(cdj), authData.length);
  let value = signP256(msg, passkey.secretKey);
  if (opts.der) value = b64url(rawToDer(Buffer.from(value, "base64url")));
  return { alg: "ES256", value, webauthn: { authenticatorData: b64url(authData), clientDataJSON: b64url(cdj) } };
}

function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; let v = b.slice(i); if (v[0] & 0x80) v = new Uint8Array([0, ...v]); return new Uint8Array([0x02, v.length, ...v]); };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

const p256Draft = { ...draft, principal: { ...draft.principal, key: passkey.kid } };
const issue = (sig: Omit<Signature, "by" | "kid">, expect = {}) => coSign(buildUnsigned(p256Draft, { issuerBase: "https://warrant.example", id: TRIPWISE_ID }), sig, keys.issuer, expect);

describe("key ids", () => {
  it("parses self-describing principal keys", () => {
    expect(publicKeyFromKid(keys.principal.kid)?.alg).toBe("EdDSA");
    expect(publicKeyFromKid(passkey.kid)).toMatchObject({ alg: "ES256" });
    expect(publicKeyFromKid("passkey:c2a7")).toBeUndefined();
  });
  it("extracts a compressed point from SPKI and DER signatures to raw", () => {
    const spkiHeader = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
    const { p256 } = p256mod;
    const uncompressed = p256.Point.fromBytes(passkey.publicKey).toBytes(false);
    expect(p256FromSpki(new Uint8Array([...spkiHeader, ...uncompressed]))).toEqual(passkey.publicKey);
    const raw = new Uint8Array(64).map((_, i) => (i * 5 + 1) % 256);
    expect(derToRaw(rawToDer(raw))).toEqual(raw);
  });
});

describe("ES256 principals", () => {
  it("plain ES256 over the payload issues and verifies through the whole verifier", () => {
    const m = issueMandate(p256Draft, { issuerBase: "https://warrant.example", principalKey: passkey, issuerKey: keys.issuer, id: TRIPWISE_ID });
    expect(m.sig[0]).toMatchObject({ alg: "ES256", kid: passkey.kid });
    const v = verifyAction({ chain: [m], action: action({ by: keys.tripwise }), status: status() }, { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID });
    expect(v.decision).toBe("allow");
  });
  it("a passkey (WebAuthn) signature binds through the challenge", () => {
    const unsigned = buildUnsigned(p256Draft, { issuerBase: "https://warrant.example", id: TRIPWISE_ID });
    const sig = webauthnSign(signingPayload(unsigned, 0));
    const m = issue(sig, { origin: ORIGIN, rpId: RP });
    expect(m.sig[0].webauthn).toBeDefined();
    // Counterparty with no origin expectations still verifies hop 0.
    const v = verifyAction({ chain: [m], action: action({ by: keys.tripwise }), status: status() }, { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID });
    expect(v.decision).toBe("allow");
    // And one that pins the issuer's origin does too.
    const v2 = verifyAction({ chain: [m], action: action({ by: keys.tripwise }), status: status() }, { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID, webauthn: { origin: ORIGIN, rpId: RP } });
    expect(v2.decision).toBe("allow");
  });
  it("accepts the browser's DER-encoded signature", () => {
    const unsigned = buildUnsigned(p256Draft, { issuerBase: "https://warrant.example", id: TRIPWISE_ID });
    expect(() => issue(webauthnSign(signingPayload(unsigned, 0), { der: true }), { origin: ORIGIN, rpId: RP })).not.toThrow();
  });
  it("refuses a passkey signature over a different payload, wrong origin, wrong rp, wrong type, or without user presence", () => {
    const unsigned = buildUnsigned(p256Draft, { issuerBase: "https://warrant.example", id: TRIPWISE_ID });
    const payload = signingPayload(unsigned, 0);
    const other = { ...payload, limits: { ...payload.limits, per_txn: 999999 } };
    expect(() => issue(webauthnSign(other))).toThrow(/does not verify/);
    expect(() => issue(webauthnSign(payload, { origin: "https://evil.example" }), { origin: ORIGIN })).toThrow(/does not verify/);
    expect(() => issue(webauthnSign(payload, { rp: "evil.example" }), { rpId: RP })).toThrow(/does not verify/);
    expect(() => issue(webauthnSign(payload, { type: "webauthn.create" }))).toThrow(/does not verify/);
    expect(() => issue(webauthnSign(payload, { up: false }))).toThrow(/does not verify/);
    // An EdDSA-labelled signature with a p256 key is refused before any crypto runs.
    expect(() => issue({ alg: "EdDSA", value: "AAAA" })).toThrow(/principal.key is ES256/);
  });
  it("tampering with the issued mandate breaks hop 0 for counterparties", () => {
    const unsigned = buildUnsigned(p256Draft, { issuerBase: "https://warrant.example", id: TRIPWISE_ID });
    const m = issue(webauthnSign(signingPayload(unsigned, 0)));
    const t = structuredClone(m); t.limits.per_txn = 61000;
    const v = verifyAction({ chain: [t], action: action({ by: keys.tripwise }), status: status() }, { now: NOW, keys: resolver, trustedRoots, issuerId: ISSUER_ID });
    expect(v.reason).toBe("bad_signature");
  });
  it("verifySignatureEntry works for confirm replies (arbitrary payloads)", () => {
    const reply = { confirm: "cfm_x", mandate: TRIPWISE_ID, action_hash: "ab".repeat(32), amount: 54000, reply: "allow" };
    const sig = webauthnSign(reply);
    expect(verifySignatureEntry({ by: "principal", kid: passkey.kid, ...sig }, reply, passkey.publicKey, { origin: ORIGIN })).toBe(true);
    expect(verifySignatureEntry({ by: "principal", kid: passkey.kid, ...sig }, { ...reply, reply: "deny" }, passkey.publicKey)).toBe(false);
    expect(canonicalize(reply)).toContain('"reply":"allow"');
    expect(generateP256KeyPair("x").publicKey.length).toBe(33);
  });
});
