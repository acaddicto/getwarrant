// Warrant issuer v0.1 — a single Supabase Edge Function that serves the issuer API.
// Routes are relative to the function's public base, e.g. https://<ref>.supabase.co/functions/v1/warrant
//
//   GET  /.well-known/warrant.json         issuer identity, keys, endpoints
//   GET  /roots                            identity roots this issuer accepts
//   POST /agents                           register an agent signing key   { did, kid, public_key, operator? }
//   GET  /agents/:did                      an agent's registered public keys (counterparties resolve kids here in v0.1)
//   POST /verify                           hosted verifier: { chain: [tokens], action, counterparty, confirm? } → verdict, ledger ref
//   POST /requests                         agent asks for a mandate         { agent, draft, sig }
//   GET  /requests/:id                     consent UI loads the request
//   POST /requests/:id/prepare             principal fixes final terms → payload to sign      (principal auth)
//   POST /requests/:id/approve             principal submits signature → mandate issued       (principal auth)
//   POST /requests/:id/decline                                                                 (principal auth)
//   POST /mandates                         agent registers a sub-mandate it issued            { token }
//   GET  /mandates                         principal's mandates                                (principal auth)
//   GET  /mandates/:id                     one mandate with status and ledger summary          (principal auth)
//   GET  /mandates/:id/ledger                                                                   (principal auth)
//   GET  /mandates/:id/export              signed dispute export                               (principal auth)
//   POST /mandates/:id/revoke              { reason? }                                         (principal auth, or agent sig)
//   GET  /r/:id                            signed status for a tree (any id in the tree)
//   GET  /revocations                      signed list of ids revoked in the last 7 days
//   POST /l/:id                            verifier posts a ledger record for a tree
//   GET  /confirm/:ref                     counterparty polls a confirm
//   POST /confirm/:ref/reply               principal answers { reply: "allow"|"deny", sig }     (principal auth)
//
// Auth: principals authenticate with `Authorization: Warrant-Principal <root assertion token>`.
// Agents sign their requests with a registered key. Counterparty and status routes are public.

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
// "@getwarrant/core" is mapped in deno.json to packages/core/src/index.ts on GitHub, pinned to a commit.
import {
  b64url,
  canonicalize,
  checkAttenuation,
  decodeMandate,
  encodeMandate,
  hashJson,
  issueStatus,
  keyPairFromSecret,
  mandateId,
  parseRootAssertion,
  recordHash,
  signJson,
  signRecordAsIssuer,
  signingPayload,
  ulid,
  unb64url,
  validateShape,
  verifyJson,
  verify as verifyRaw,
  verifyAction,
  buildRecord,
  signRecordAsVerifier,
  MAX_DEPTH,
  type Action,
  type KeyPair,
  type LedgerRecord,
  type Mandate,
  type MandateDraft,
  type RootAssertion,
  type Signature,
} from "@getwarrant/core";

// ---------- config ----------------------------------------------------------
const env = (k: string, required = true) => {
  const v = Deno.env.get(k);
  if (!v && required) throw new Error(`missing env ${k}`);
  return v ?? "";
};
// Only WARRANT_ISSUER_SECRET is mandatory (32 random bytes, base64url). The rest default to this project's own host
// until a custom domain (api.getwarrant.dev) is in front of the function.
const SUPA_HOST = new URL(env("SUPABASE_URL")).host;
const ISSUER_DID = env("WARRANT_ISSUER_DID", false) || `did:web:${SUPA_HOST}`;
const PUBLIC_BASE = (env("WARRANT_PUBLIC_BASE", false) || `https://${SUPA_HOST}/functions/v1/warrant`).replace(/\/$/, "");
const ISSUER_KEY: KeyPair = keyPairFromSecret(`${ISSUER_DID}#k1`, unb64url(env("WARRANT_ISSUER_SECRET")));
const CONSENT_BASE = env("WARRANT_CONSENT_BASE", false) || `${PUBLIC_BASE}/consent`;

const db = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), { db: { schema: "warrant" }, auth: { persistSession: false } });

// ---------- helpers ---------------------------------------------------------
class HttpError extends Error {
  constructor(public status: number, public code: string, message?: string) {
    super(message ?? code);
  }
}
const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "access-control-allow-origin": "*", ...extra } });
const nowS = () => Math.floor(Date.now() / 1000);
const iso = (s: number) => new Date(s * 1000).toISOString();

async function body<T = any>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T;
  } catch {
    throw new HttpError(400, "bad_json");
  }
}

function principalKeyBytes(kid: string): Uint8Array | undefined {
  if (!kid.startsWith("key:")) return undefined;
  try {
    const b = unb64url(kid.slice(4));
    return b.length === 32 ? b : undefined;
  } catch {
    return undefined;
  }
}

async function trustedRoot(rootId: string) {
  const { data } = await db.from("roots").select("*").eq("id", rootId).maybeSingle();
  return data;
}

interface PrincipalCtx {
  root: string;
  sub: string;
  level: RootAssertion["level"];
  assertionToken: string;
}
async function requirePrincipal(req: Request): Promise<PrincipalCtx> {
  const h = req.headers.get("authorization") ?? "";
  const m = /^Warrant-Principal\s+(\S+)$/i.exec(h);
  if (!m) throw new HttpError(401, "principal_required", "Authorization: Warrant-Principal <assertion>");
  const parsed = parseRootAssertion(m[1]);
  if (!parsed) throw new HttpError(401, "principal_unverified", "assertion unparseable");
  const root = await trustedRoot(parsed.assertion.root);
  if (!root) throw new HttpError(401, "principal_unverified", `root ${parsed.assertion.root} not accepted`);
  if (!verifyJson(parsed.signature, parsed.assertion, unb64url(root.public_key))) throw new HttpError(401, "principal_unverified", "bad assertion signature");
  if (parsed.assertion.aud !== ISSUER_DID) throw new HttpError(401, "principal_unverified", `assertion audience ${parsed.assertion.aud} is not ${ISSUER_DID}`);
  if (parsed.assertion.exp < nowS()) throw new HttpError(401, "principal_unverified", "assertion expired");
  return { root: parsed.assertion.root, sub: parsed.assertion.sub, level: parsed.assertion.level, assertionToken: m[1] };
}

async function agentKey(kid: string) {
  const { data } = await db.from("agent_keys").select("*").eq("kid", kid).maybeSingle();
  return data;
}

async function loadMandate(id: string) {
  const { data } = await db.from("mandates").select("*").eq("id", id).maybeSingle();
  if (!data) throw new HttpError(404, "not_found", `mandate ${id}`);
  return data;
}

async function treeStatus(rootRow: any) {
  const expired = rootRow.status === "active" && new Date(rootRow.exp).getTime() < Date.now();
  const status = issueStatus(
    { id: rootRow.id, status: expired ? "expired" : rootRow.status, spent: Number(rootRow.spent), asof: nowS(), ttl: 30, reason: rootRow.revoke_reason ?? undefined },
    ISSUER_KEY,
  );
  return status;
}

// Countersign a verifier's record, append it to the tree's chain, bump spend, open a confirmation if needed.
async function appendRecord(rec: LedgerRecord, rootId: string) {
  const signed = signRecordAsIssuer(rec, ISSUER_KEY);
  const hash = recordHash(signed);
  const bump = rec.decision === "allow" && rec.action.amount !== undefined;
  const { data: seq, error } = await db.rpc("append_ledger", {
    p_ref: rec.ref, p_root_id: rootId, p_mandate_id: rec.mandate.id, p_prev: rec.prev, p_hash: hash,
    p_decision: rec.decision, p_reason: rec.reason, p_amount: rec.action.amount ?? null, p_counterparty: rec.counterparty,
    p_record: signed, p_at: new Date(rec.at).toISOString(), p_bump_spend: bump,
  });
  if (error) {
    if (error.message.includes("prev_mismatch")) {
      const { data: last } = await db.from("ledger").select("hash").eq("root_id", rootId).order("seq", { ascending: false }).limit(1).maybeSingle();
      throw new HttpError(409, "prev_mismatch", `expected prev ${last?.hash ?? null}`);
    }
    if (error.code === "23505") throw new HttpError(409, "duplicate_ref");
    throw new HttpError(500, "db", error.message);
  }
  if (rec.decision === "confirm") {
    const ref = rec.confirm?.ref ?? "cfm_" + ulid();
    await db.from("confirmations").insert({ ref, root_id: rootId, mandate_id: rec.mandate.id, ledger_ref: rec.ref, action_type: rec.action.type, amount: rec.action.amount ?? null, counterparty: rec.counterparty, action_hash: rec.action.hash, expires_at: new Date(Date.now() + 15 * 60_000).toISOString() });
    return { ref: rec.ref, seq, hash, issuer_sig: signed.sig.issuer, confirm_ref: ref, poll: `${PUBLIC_BASE}/confirm/${ref}` };
  }
  return { ref: rec.ref, seq, hash, issuer_sig: signed.sig.issuer };
}

async function lastHash(rootId: string): Promise<string | null> {
  const { data } = await db.from("ledger").select("hash").eq("root_id", rootId).order("seq", { ascending: false }).limit(1).maybeSingle();
  return data?.hash ?? null;
}

// ---------- routes ----------------------------------------------------------
async function route(req: Request, path: string): Promise<Response> {
  const method = req.method;
  const seg = path.split("/").filter(Boolean);

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET,POST,OPTIONS" } });

  // --- discovery ---
  if (method === "GET" && path === "/.well-known/warrant.json") {
    return json(200, {
      issuer: ISSUER_DID,
      spec: "warrant/0.1",
      keys: [{ kid: ISSUER_KEY.kid, alg: "EdDSA", public_key: b64url(ISSUER_KEY.publicKey) }],
      endpoints: { requests: `${PUBLIC_BASE}/requests`, mandates: `${PUBLIC_BASE}/mandates`, verify: `${PUBLIC_BASE}/verify`, agents: `${PUBLIC_BASE}/agents/{did}`, status: `${PUBLIC_BASE}/r/{id}`, ledger: `${PUBLIC_BASE}/l/{id}`, revocations: `${PUBLIC_BASE}/revocations`, confirm: `${PUBLIC_BASE}/confirm/{ref}`, consent: `${CONSENT_BASE}/{request_id}` },
      principal_auth: "Authorization: Warrant-Principal <root assertion token>",
    });
  }
  if (method === "GET" && path === "/roots") {
    const { data } = await db.from("roots").select("id, kid, public_key, kind, max_level");
    return json(200, { roots: data ?? [] });
  }

  // --- agents ---
  if (method === "POST" && path === "/agents") {
    const b = await body<{ did: string; kid: string; public_key: string; operator?: string }>(req);
    if (!b.did?.startsWith("did:") || !b.kid?.startsWith(b.did + "#")) throw new HttpError(400, "malformed", "kid must be <did>#<fragment>");
    let pk: Uint8Array;
    try { pk = unb64url(b.public_key); } catch { throw new HttpError(400, "malformed", "public_key must be base64url"); }
    if (pk.length !== 32) throw new HttpError(400, "malformed", "public_key must be 32 raw Ed25519 bytes");
    const { error } = await db.from("agent_keys").upsert({ did: b.did, kid: b.kid, public_key: b.public_key, operator: b.operator ?? null });
    if (error) throw new HttpError(500, "db", error.message);
    return json(201, { did: b.did, kid: b.kid });
  }
  if (method === "GET" && seg[0] === "agents" && seg.length === 2) {
    const did = decodeURIComponent(seg[1]);
    const { data } = await db.from("agent_keys").select("kid, public_key, operator").eq("did", did);
    if (!data?.length) throw new HttpError(404, "not_found", `no keys registered for ${did}`);
    return json(200, { did, operator: data[0].operator, keys: data.map((k) => ({ kid: k.kid, alg: "EdDSA", public_key: k.public_key })) }, { "cache-control": "public, max-age=300" });
  }

  // --- mandate requests ---
  if (method === "POST" && path === "/requests") {
    const b = await body<{ agent: { did: string; kid: string; runtime?: string }; draft: Omit<MandateDraft, "principal" | "agent"> & { purpose?: string }; sig: string }>(req);
    const key = b.agent?.kid ? await agentKey(b.agent.kid) : null;
    if (!key || key.did !== b.agent.did) throw new HttpError(401, "agent_unknown", "register the agent key at POST /agents first");
    if (!verifyJson(b.sig, { agent: b.agent, draft: b.draft }, unb64url(key.public_key))) throw new HttpError(401, "bad_signature", "sig must cover {agent, draft}");
    const d = b.draft;
    if (!Array.isArray(d?.scope?.may) || !Array.isArray(d?.scope?.counterparties)) throw new HttpError(400, "malformed", "draft.scope.may and counterparties are required");
    if (!d.delegation || d.delegation.attenuate !== true || !Number.isInteger(d.delegation.max_depth) || d.delegation.max_depth < 0 || d.delegation.max_depth > MAX_DEPTH) throw new HttpError(400, "malformed", "draft.delegation");
    const id = "req_" + ulid();
    const { error } = await db.from("requests").insert({ id, agent_did: b.agent.did, draft: { ...d, agent: b.agent } });
    if (error) throw new HttpError(500, "db", error.message);
    return json(201, { request_id: id, consent_url: `${CONSENT_BASE}/${id}`, expires_in: 900 });
  }
  if (method === "GET" && seg[0] === "requests" && seg.length === 2) {
    const { data } = await db.from("requests").select("id, agent_did, draft, state, created_at, expires_at").eq("id", seg[1]).maybeSingle();
    if (!data) throw new HttpError(404, "not_found");
    const { data: agent } = await db.from("agent_keys").select("did, operator").eq("did", data.agent_did).limit(1).maybeSingle();
    const { count } = await db.from("mandates").select("id", { count: "exact", head: true }).eq("agent_did", data.agent_did);
    return json(200, { ...data, agent: { did: data.agent_did, operator: agent?.operator ?? null, mandates_issued: count ?? 0 }, issuer: ISSUER_DID });
  }
  if (method === "POST" && seg[0] === "requests" && seg[2] === "prepare") {
    const p = await requirePrincipal(req);
    const { data: r } = await db.from("requests").select("*").eq("id", seg[1]).maybeSingle();
    if (!r) throw new HttpError(404, "not_found");
    if (r.state !== "pending" && r.state !== "prepared") throw new HttpError(409, "request_closed", r.state);
    if (new Date(r.expires_at).getTime() < Date.now()) throw new HttpError(410, "request_expired");
    const b = await body<{ key: string; limits?: Partial<Mandate["limits"]>; exp?: number; max_depth?: number; may?: string[] }>(req);
    if (!principalKeyBytes(b.key)) throw new HttpError(400, "malformed", "key must be key:<base64url 32-byte Ed25519 public key>");
    const d = r.draft;
    const t = nowS();
    // The principal may only narrow what the agent asked for.
    const limits = { ...d.limits };
    for (const k of ["total", "per_txn", "confirm_over"] as const) {
      const v = b.limits?.[k];
      if (v === undefined) continue;
      if (!Number.isInteger(v) || v < 0) throw new HttpError(400, "malformed", `limits.${k}`);
      if (d.limits?.[k] !== undefined && v > d.limits[k]) throw new HttpError(400, "widened", `limits.${k} above what the agent asked for`);
      limits[k] = v;
    }
    const may = b.may ? d.scope.may.filter((a: string) => b.may!.includes(a)) : d.scope.may;
    if (may.length === 0) throw new HttpError(400, "malformed", "scope.may cannot be empty");
    const exp = Math.min(b.exp ?? d.exp ?? t + 7 * 86400, d.exp ?? Infinity, t + 90 * 86400);
    const max_depth = Math.min(b.max_depth ?? d.delegation.max_depth, d.delegation.max_depth);
    const id = r.mandate_id ?? mandateId();
    const unsigned: Mandate = {
      typ: "warrant/mandate",
      ver: "0.1",
      id,
      principal: { root: p.root, sub: p.sub, key: b.key, assertion: p.assertionToken },
      agent: { did: d.agent.did, ...(d.agent.runtime ? { runtime: d.agent.runtime } : {}) },
      scope: { may, ...(d.scope.may_not?.length ? { may_not: d.scope.may_not } : {}), counterparties: d.scope.counterparties },
      limits,
      delegation: { max_depth, attenuate: true },
      nbf: Math.max(d.nbf ?? t, t - 60),
      exp,
      revocation: `${PUBLIC_BASE}/r/${id}`,
      ledger: `${PUBLIC_BASE}/l/${id}`,
      sig: [],
    };
    const errs = validateShape(unsigned);
    if (errs.length) throw new HttpError(400, "malformed", errs.join("; "));
    const { error } = await db.from("requests").update({ state: "prepared", unsigned, mandate_id: id, principal_sub: p.sub }).eq("id", r.id);
    if (error) throw new HttpError(500, "db", error.message);
    return json(200, { request_id: r.id, mandate_id: id, unsigned, payload_to_sign: canonicalize(signingPayload(unsigned, 0)), alg: "EdDSA" });
  }
  if (method === "POST" && seg[0] === "requests" && seg[2] === "approve") {
    const p = await requirePrincipal(req);
    const { data: r } = await db.from("requests").select("*").eq("id", seg[1]).maybeSingle();
    if (!r) throw new HttpError(404, "not_found");
    if (r.state !== "prepared") throw new HttpError(409, "not_prepared", "call /prepare first");
    if (r.principal_sub !== p.sub) throw new HttpError(403, "wrong_principal");
    const b = await body<{ sig: string }>(req);
    const unsigned = r.unsigned as Mandate;
    const pk = principalKeyBytes(unsigned.principal.key)!;
    if (!verifyJson(b.sig, signingPayload(unsigned, 0), pk)) throw new HttpError(400, "bad_signature", "principal signature does not verify over payload_to_sign");
    const principalSig: Signature = { by: "principal", alg: "EdDSA", kid: unsigned.principal.key, value: b.sig };
    const withP: Mandate = { ...unsigned, sig: [principalSig] };
    const issuerSig: Signature = { by: "issuer", alg: "EdDSA", kid: ISSUER_KEY.kid, value: signJson(signingPayload(withP, 1), ISSUER_KEY.secretKey) };
    const mandate: Mandate = { ...withP, sig: [principalSig, issuerSig] };
    const token = encodeMandate(mandate);
    const { error } = await db.from("mandates").insert({
      id: mandate.id, root_id: mandate.id, parent_id: null, hop: 1, agent_did: mandate.agent.did,
      principal_root: p.root, principal_sub: p.sub, principal_org: mandate.principal.org?.id ?? null,
      ccy: mandate.limits.ccy ?? null, total_limit: mandate.limits.total ?? null,
      nbf: iso(mandate.nbf), exp: iso(mandate.exp), mandate, token,
    });
    if (error) throw new HttpError(500, "db", error.message);
    await db.from("requests").update({ state: "approved", decided_at: new Date().toISOString() }).eq("id", r.id);
    return json(201, { mandate_id: mandate.id, token, mandate });
  }
  if (method === "POST" && seg[0] === "requests" && seg[2] === "decline") {
    await requirePrincipal(req);
    const { error } = await db.from("requests").update({ state: "declined", decided_at: new Date().toISOString() }).eq("id", seg[1]).in("state", ["pending", "prepared"]);
    if (error) throw new HttpError(500, "db", error.message);
    return json(200, { request_id: seg[1], state: "declined" });
  }
  // Agents poll the request to collect the token once approved.
  if (method === "GET" && seg[0] === "requests" && seg[2] === "token") {
    const { data: r } = await db.from("requests").select("state, mandate_id").eq("id", seg[1]).maybeSingle();
    if (!r) throw new HttpError(404, "not_found");
    if (r.state !== "approved") return json(200, { state: r.state });
    const m = await loadMandate(r.mandate_id);
    return json(200, { state: "approved", mandate_id: m.id, token: m.token });
  }

  // --- sub-mandates ---
  if (method === "POST" && path === "/mandates") {
    const b = await body<{ token: string }>(req);
    let sub: Mandate;
    try { sub = decodeMandate(b.token); } catch (e) { throw new HttpError(400, "malformed", (e as Error).message); }
    if (!sub.parent) throw new HttpError(400, "malformed", "hop-1 mandates are issued through /requests");
    const parentRow = await loadMandate(sub.parent);
    const parent = parentRow.mandate as Mandate;
    if (parentRow.status !== "active") throw new HttpError(409, "revoked", "parent is not active");
    if (parentRow.hop >= MAX_DEPTH + 1) throw new HttpError(400, "widened", "max depth reached");
    const v = checkAttenuation(parent, sub, Number((await loadMandate(parentRow.root_id)).spent));
    if (v.length) throw new HttpError(400, "widened", v.join("; "));
    if (sub.sig.length !== parent.sig.length + 1) throw new HttpError(400, "bad_chain");
    for (let i = 0; i < parent.sig.length; i++) if (canonicalize(sub.sig[i]) !== canonicalize(parent.sig[i])) throw new HttpError(400, "bad_chain", `signature ${i} differs from parent`);
    const hop = sub.sig[sub.sig.length - 1];
    if (hop.by !== "agent" || hop.did !== parent.agent.did || !hop.kid.startsWith(parent.agent.did + "#")) throw new HttpError(400, "bad_signature", `hop must be signed by ${parent.agent.did}`);
    const key = await agentKey(hop.kid);
    if (!key) throw new HttpError(401, "agent_unknown", `register ${hop.kid} at POST /agents`);
    if (!verifyJson(hop.value, signingPayload(sub, sub.sig.length - 1), unb64url(key.public_key))) throw new HttpError(400, "bad_signature");
    const { error } = await db.from("mandates").insert({
      id: sub.id, root_id: parentRow.root_id, parent_id: parent.id, hop: parentRow.hop + 1, agent_did: sub.agent.did,
      principal_root: sub.principal.root, principal_sub: sub.principal.sub, principal_org: sub.principal.org?.id ?? null,
      ccy: sub.limits.ccy ?? null, total_limit: sub.limits.total ?? null, nbf: iso(sub.nbf), exp: iso(sub.exp), mandate: sub, token: encodeMandate(sub),
    });
    if (error) throw new HttpError(error.code === "23505" ? 409 : 500, "db", error.message);
    return json(201, { mandate_id: sub.id, root_id: parentRow.root_id, hop: parentRow.hop + 1 });
  }

  // --- principal views ---
  if (method === "GET" && path === "/mandates") {
    const p = await requirePrincipal(req);
    const { data } = await db.from("mandates").select("id, root_id, parent_id, hop, agent_did, status, spent, ccy, total_limit, nbf, exp, created_at, revoked_at").eq("principal_root", p.root).eq("principal_sub", p.sub).order("created_at", { ascending: false });
    return json(200, { mandates: data ?? [] });
  }
  if (method === "GET" && seg[0] === "mandates" && seg.length >= 2) {
    const p = await requirePrincipal(req);
    const row = await loadMandate(seg[1]);
    if (row.principal_root !== p.root || row.principal_sub !== p.sub) throw new HttpError(403, "forbidden");
    const root = row.root_id === row.id ? row : await loadMandate(row.root_id);
    if (seg[2] === "ledger") {
      const { data } = await db.from("ledger").select("ref, seq, prev, hash, decision, reason, amount, counterparty, record, at").eq("root_id", row.root_id).order("seq", { ascending: false }).limit(200);
      return json(200, { root_id: row.root_id, records: data ?? [] });
    }
    if (seg[2] === "export") {
      const { data: tree } = await db.from("mandates").select("id, parent_id, hop, agent_did, status, mandate, token").eq("root_id", row.root_id).order("hop");
      const { data: records } = await db.from("ledger").select("record, hash, seq").eq("root_id", row.root_id).order("seq");
      const { data: revs } = await db.from("revocations").select("*").eq("root_id", row.root_id);
      const head = records?.length ? records[records.length - 1].hash : null;
      const exportBody = { issuer: ISSUER_DID, root_id: row.root_id, generated_at: nowS(), principal: { root: row.principal_root, sub: row.principal_sub }, mandates: tree, ledger: records?.map((r) => r.record) ?? [], chain_head: head, revocations: revs ?? [] };
      return json(200, { ...exportBody, sig: { kid: ISSUER_KEY.kid, value: signJson(exportBody, ISSUER_KEY.secretKey) } });
    }
    if (seg.length === 2) {
      const { data: children } = await db.from("mandates").select("id, agent_did, hop, status").eq("parent_id", row.id);
      const { data: pending } = await db.from("confirmations").select("ref, action_type, amount, counterparty, created_at, expires_at").eq("root_id", row.root_id).eq("state", "pending");
      const { count } = await db.from("ledger").select("ref", { count: "exact", head: true }).eq("root_id", row.root_id);
      return json(200, { ...row, status_signed: await treeStatus(root), children: children ?? [], pending_confirmations: pending ?? [], ledger_count: count ?? 0 });
    }
  }
  if (method === "POST" && seg[0] === "mandates" && seg[2] === "revoke") {
    const row = await loadMandate(seg[1]);
    const b = await body<{ reason?: string; agent?: { kid: string; sig: string } }>(req).catch(() => ({} as any));
    let by: string;
    if (b.agent) {
      // An agent may revoke a mandate it holds or one it issued.
      const key = await agentKey(b.agent.kid);
      if (!key) throw new HttpError(401, "agent_unknown");
      if (!verifyJson(b.agent.sig, { revoke: row.id }, unb64url(key.public_key))) throw new HttpError(401, "bad_signature", "sig must cover {revoke: <id>}");
      const parentDid = row.parent_id ? (await loadMandate(row.parent_id)).agent_did : null;
      if (key.did !== row.agent_did && key.did !== parentDid) throw new HttpError(403, "forbidden", "agent neither holds nor issued this mandate");
      by = `agent:${key.did}`;
    } else {
      const p = await requirePrincipal(req);
      if (row.principal_root !== p.root || row.principal_sub !== p.sub) throw new HttpError(403, "forbidden");
      by = "principal";
    }
    const { data, error } = await db.rpc("revoke_tree", { p_mandate_id: row.id, p_by: by, p_reason: b.reason ?? null });
    if (error) throw new HttpError(500, "db", error.message);
    return json(200, { revoked: data ?? [], by, at: nowS() });
  }

  // --- status & revocation list (public) ---
  if (method === "GET" && seg[0] === "r" && seg.length === 2) {
    const row = await loadMandate(seg[1]);
    const root = row.root_id === row.id ? row : await loadMandate(row.root_id);
    const s = await treeStatus(root);
    return json(200, s, { "cache-control": `public, max-age=${s.status.ttl}` });
  }
  if (method === "GET" && path === "/revocations") {
    const since = new Date(Date.now() - 7 * 86400 * 1000).toISOString();
    const { data } = await db.from("revocations").select("mandate_id, root_id, at").gte("at", since).order("at", { ascending: false });
    const list = { issuer: ISSUER_DID, asof: nowS(), window_days: 7, revoked: (data ?? []).map((r) => ({ id: r.mandate_id, root: r.root_id, at: Math.floor(new Date(r.at).getTime() / 1000) })) };
    return json(200, { ...list, sig: { kid: ISSUER_KEY.kid, value: signJson(list, ISSUER_KEY.secretKey) } }, { "cache-control": "public, max-age=60" });
  }

  // --- hosted verifier ---
  if (method === "POST" && path === "/verify") {
    const b = await body<{ chain: (string | Mandate)[]; action: Action; counterparty: string; record?: boolean; confirm?: string }>(req);
    if (!Array.isArray(b.chain) || !b.chain.length || !b.action || !b.counterparty) throw new HttpError(400, "malformed", "chain[], action and counterparty are required");
    let chain: Mandate[];
    try { chain = b.chain.map((c) => (typeof c === "string" ? decodeMandate(c) : c)); } catch (e) { throw new HttpError(400, "malformed", (e as Error).message); }
    const first = await loadMandate(chain[0].id);
    const rootRow = first.root_id === first.id ? first : await loadMandate(first.root_id);
    const status = await treeStatus(rootRow);
    const { data: agents } = await db.from("agent_keys").select("kid, public_key");
    const { data: roots } = await db.from("roots").select("id, kid, public_key");
    const keyMap = new Map<string, Uint8Array>([[ISSUER_KEY.kid, ISSUER_KEY.publicKey]]);
    for (const a of agents ?? []) keyMap.set(a.kid, unb64url(a.public_key));
    for (const r of roots ?? []) keyMap.set(r.kid, unb64url(r.public_key));
    const trustedRoots = Object.fromEntries((roots ?? []).map((r) => [r.id, { publicKey: unb64url(r.public_key) }]));
    // A retry of an action the principal has confirmed: allow it once, without a second ledger record.
    let confirmedHash: string | undefined;
    if (b.confirm) {
      const { data: c } = await db.from("confirmations").select("state, action_hash, mandate_id").eq("ref", b.confirm).maybeSingle();
      if (c?.state === "allow" && c.action_hash === b.action.hash && c.mandate_id === chain[chain.length - 1].id) confirmedHash = c.action_hash;
    }
    const verdict = verifyAction(
      { chain, action: b.action, status },
      { now: nowS(), keys: (kid) => keyMap.get(kid) ?? principalKeyBytes(kid), trustedRoots, issuerId: ISSUER_DID, confirmedHash },
    );
    if (b.record === false) return json(200, { verdict });
    if (confirmedHash && verdict.decision === "allow") return json(200, { verdict, ledger: { ref: b.confirm, seq: -1, hash: "", confirm_ref: b.confirm }, note: "confirmed action; the principal's reply is the ledger record" });
    // Hop-1 ids not in our store cannot be ledgered; verdicts with a malformed/bad chain still return without a record.
    if (verdict.reason === "malformed" || verdict.reason === "bad_chain" || verdict.reason === "bad_signature") return json(200, { verdict, ledger: null });
    const { data: actingRow } = await db.from("mandates").select("id").eq("id", chain[chain.length - 1].id).maybeSingle();
    if (!actingRow) return json(200, { verdict, ledger: null, note: "acting mandate is not registered with this issuer; register sub-mandates at POST /mandates to get them ledgered" });
    const rec = signRecordAsVerifier(buildRecord({ verdict, chain, action: b.action, status, counterparty: b.counterparty, prev: await lastHash(rootRow.root_id) }), ISSUER_KEY);
    const ledger = await appendRecord(rec, rootRow.root_id);
    return json(200, { verdict, ledger });
  }

  // --- ledger (counterparties) ---
  if (method === "POST" && seg[0] === "l" && seg.length === 2) {
    const rec = await body<LedgerRecord>(req);
    const row = await loadMandate(seg[1]);
    const rootId = row.root_id;
    if (rec.mandate?.root !== rootId) throw new HttpError(400, "malformed", `record.mandate.root must be ${rootId}`);
    const acting = await loadMandate(rec.mandate.id);
    if (acting.root_id !== rootId) throw new HttpError(400, "malformed", "acting mandate is not in this tree");
    if (!rec.sig?.verifier || !/^[^ ]+:[A-Za-z0-9_-]+$/.test(rec.sig.verifier)) throw new HttpError(400, "malformed", "sig.verifier required as <kid>:<sig>");
    if (rec.sig.issuer) throw new HttpError(400, "malformed", "sig.issuer is added by the issuer");
    // The agent's signature over the action hash must verify against a registered key of the acting agent.
    const { data: akeys } = await db.from("agent_keys").select("kid, public_key").eq("did", acting.agent_did);
    const agentOk = (akeys ?? []).some((k) => verifyRaw(rec.sig.agent, new TextEncoder().encode(rec.action.hash), unb64url(k.public_key)));
    if (!agentOk) throw new HttpError(400, "bad_signature", "sig.agent does not verify against any registered key of " + acting.agent_did);
    if (!["allow", "confirm", "deny"].includes(rec.decision)) throw new HttpError(400, "malformed", "decision");
    if (rec.decision === "allow" && rec.action.amount !== undefined) {
      // Refuse a counterparty posting an allow that the tree cannot afford; the verifier should have denied.
      const root = await loadMandate(rootId);
      if (root.total_limit !== null && Number(root.spent) + (rec.action.amount ?? 0) > Number(root.total_limit)) throw new HttpError(409, "over_limit", "tree total exceeded");
    }
    return json(201, await appendRecord(rec, rootId));
  }

  // --- confirmations ---
  if (method === "GET" && seg[0] === "confirm" && seg.length === 2) {
    const { data: c } = await db.from("confirmations").select("ref, state, action_type, amount, counterparty, action_hash, replied_at, expires_at, reply_sig").eq("ref", seg[1]).maybeSingle();
    if (!c) throw new HttpError(404, "not_found");
    if (c.state === "pending" && new Date(c.expires_at).getTime() < Date.now()) {
      await db.from("confirmations").update({ state: "expired" }).eq("ref", c.ref).eq("state", "pending");
      c.state = "expired";
    }
    return json(200, { ...c, decision: c.state === "allow" ? "allow" : c.state === "pending" ? "confirm" : "deny" });
  }
  if (method === "POST" && seg[0] === "confirm" && seg[2] === "reply") {
    const p = await requirePrincipal(req);
    const { data: c } = await db.from("confirmations").select("*").eq("ref", seg[1]).maybeSingle();
    if (!c) throw new HttpError(404, "not_found");
    const row = await loadMandate(c.mandate_id);
    if (row.principal_root !== p.root || row.principal_sub !== p.sub) throw new HttpError(403, "forbidden");
    if (c.state !== "pending") throw new HttpError(409, "already_answered", c.state);
    if (new Date(c.expires_at).getTime() < Date.now()) throw new HttpError(410, "expired");
    const b = await body<{ reply: "allow" | "deny"; sig: string }>(req);
    if (b.reply !== "allow" && b.reply !== "deny") throw new HttpError(400, "malformed", "reply");
    const m = row.mandate as Mandate;
    const pk = principalKeyBytes(m.principal.key)!;
    const signedBody = { confirm: c.ref, mandate: c.mandate_id, action_hash: c.action_hash, amount: c.amount, reply: b.reply };
    if (!verifyJson(b.sig, signedBody, pk)) throw new HttpError(400, "bad_signature", "sig must cover " + canonicalize(signedBody));
    const { error } = await db.from("confirmations").update({ state: b.reply, reply_sig: b.sig, replied_at: new Date().toISOString() }).eq("ref", c.ref).eq("state", "pending");
    if (error) throw new HttpError(500, "db", error.message);
    if (b.reply === "allow" && c.amount !== null) {
      await db.rpc("append_ledger", {
        p_ref: "led_" + ulid(), p_root_id: c.root_id, p_mandate_id: c.mandate_id,
        p_prev: await lastHash(c.root_id),
        p_hash: hashJson({ confirm: c.ref, reply: "allow", sig: b.sig }), p_decision: "allow", p_reason: null, p_amount: c.amount, p_counterparty: c.counterparty,
        p_record: { kind: "confirm_reply", confirm: c.ref, ledger_ref: c.ledger_ref, reply: "allow", principal_sig: b.sig, at: Date.now() }, p_at: new Date().toISOString(), p_bump_spend: true,
      });
    }
    return json(200, { ref: c.ref, state: b.reply });
  }

  throw new HttpError(404, "no_route", `${method} ${path}`);
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  // Strip the function prefix whether called as /functions/v1/warrant/... or behind a custom domain as /....
  const path = url.pathname.replace(/^\/functions\/v1\/warrant/, "").replace(/^\/warrant/, "") || "/";
  try {
    return await route(req, path);
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.code, message: e.message });
    console.error(e);
    return json(500, { error: "internal", message: (e as Error).message });
  }
});
