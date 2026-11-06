import { actionMatches, checkAttenuation, effective, patternCovers } from "./attenuate.js";
import { utf8 } from "./canon.js";
import { sign, verify as verifySig, type KeyPair } from "./crypto.js";
import { firstBadSignature, parseRootAssertion, signingPayload, validateShape } from "./mandate.js";
import { verifyStatusSignature } from "./status.js";
import { verifyJson } from "./crypto.js";
import {
  CLOCK_SKEW_S,
  MAX_STATUS_TTL_S,
  type Action,
  type AssuranceLevel,
  type CheckResult,
  type DenyReason,
  type KeyResolver,
  type Mandate,
  type SignedStatus,
  type Verdict,
} from "./types.js";

export interface TrustedRoot {
  publicKey: Uint8Array;
}

export interface VerifyContext {
  /** Unix seconds. Injected so verification is a pure function. */
  now: number;
  /** Resolves principal, issuer and agent key ids to public keys. */
  keys: KeyResolver;
  /** Roots this counterparty accepts, by root id. */
  trustedRoots: Record<string, TrustedRoot>;
  /** The issuer identifier assertions must be scoped to (RootAssertion.aud). Checked when set. */
  issuerId?: string;
  /** Minimum assurance level required for an action. Default: spend needs at least "substantial". */
  minLevel?: (action: Action) => AssuranceLevel;
  /** Count of this tree's actions already seen in the current rate window, when the counterparty tracks one. */
  recentActionCount?: number;
}

export interface VerifyInput {
  /** Hop 1 first, acting agent's mandate last. */
  chain: Mandate[];
  action: Action;
  status: SignedStatus;
}

const LEVEL: Record<AssuranceLevel, number> = { low: 0, substantial: 1, high: 2 };
const defaultMinLevel = (a: Action): AssuranceLevel => (a.amount !== undefined && a.amount > 0 ? "substantial" : "low");

function sameSig(a: Mandate["sig"][number], b: Mandate["sig"][number]): boolean {
  return a.by === b.by && a.alg === b.alg && a.kid === b.kid && a.value === b.value && a.did === b.did && a.iat === b.iat;
}

export function parseRate(rate: string): { count: number; windowS: number } | null {
  const m = /^(\d+)\/(\d+)([smhd])$/.exec(rate);
  if (!m) return null;
  const unit = { s: 1, m: 60, h: 3600, d: 86400 }[m[3] as "s" | "m" | "h" | "d"];
  return { count: Number(m[1]), windowS: Number(m[2]) * unit };
}

/** Acting agent signs an action hash. */
export function signAction(hash: string, agentKey: KeyPair): { kid: string; sig: string } {
  return { kid: agentKey.kid, sig: sign(utf8(hash), agentKey.secretKey) };
}

/**
 * The verifier decision. Pure: same inputs and context, same verdict.
 * Runs the seven ordered checks from the spec; the first failure ends evaluation.
 */
export function verifyAction(input: VerifyInput, ctx: VerifyContext): Verdict {
  const { chain, action, status } = input;
  const checks: CheckResult[] = [];
  const root = chain[0];
  const acting = chain[chain.length - 1];
  const base = { mandate: acting?.id ?? "", root: root?.id ?? "", hop: chain.length, ttl: status?.status?.ttl ?? 0 };
  const deny = (reason: DenyReason): Verdict => ({ decision: "deny", reason, checks, ...base });
  const pass = (step: CheckResult["step"], name: string, detail: string) => checks.push({ step, name, ok: true, detail });
  const fail = (step: CheckResult["step"], name: string, detail: string, reason: DenyReason) => {
    checks.push({ step, name, ok: false, detail, reason } as CheckResult);
    return deny(reason);
  };

  // ---- 1. Signatures and chain integrity --------------------------------
  if (!Array.isArray(chain) || chain.length === 0) return fail(1, "Signature chain", "empty chain", "malformed");
  for (const m of chain) {
    const errs = validateShape(m);
    if (errs.length) return fail(1, "Signature chain", `malformed mandate ${m?.id}: ${errs[0]}`, "malformed");
  }
  if (root.parent !== undefined) return fail(1, "Signature chain", "hop 1 must not have a parent", "bad_chain");
  if (root.sig[0]?.kid !== root.principal.key) return fail(1, "Signature chain", "principal signature kid does not match principal.key", "bad_signature");
  const bad = firstBadSignature(root, ctx.keys);
  if (bad >= 0) return fail(1, "Signature chain", `hop 1 signature ${bad} (${root.sig[bad]?.by ?? "missing"}) does not verify`, "bad_signature");
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1], child = chain[i];
    if (child.parent !== parent.id) return fail(1, "Signature chain", `hop ${i + 1} parent ${child.parent} is not ${parent.id}`, "bad_chain");
    if (child.sig.length !== parent.sig.length + 1) return fail(1, "Signature chain", `hop ${i + 1} must carry exactly one more signature than its parent`, "bad_chain");
    for (let k = 0; k < parent.sig.length; k++)
      if (!sameSig(child.sig[k], parent.sig[k])) return fail(1, "Signature chain", `hop ${i + 1} signature ${k} differs from parent`, "bad_chain");
    const hop = child.sig[child.sig.length - 1];
    if (hop.by !== "agent" || hop.did !== parent.agent.did || !hop.kid.startsWith(parent.agent.did + "#"))
      return fail(1, "Signature chain", `hop ${i + 1} must be signed by ${parent.agent.did}`, "bad_signature");
    const pk = ctx.keys(hop.kid);
    if (!pk || !verifyJson(hop.value, signingPayload(child, child.sig.length - 1), pk))
      return fail(1, "Signature chain", `hop ${i + 1} agent signature does not verify`, "bad_signature");
  }
  // The action itself must be signed by the acting agent.
  if (!action.kid.startsWith(acting.agent.did + "#")) return fail(1, "Signature chain", `action signed by ${action.kid}, not by ${acting.agent.did}`, "bad_signature");
  const actingPk = ctx.keys(action.kid);
  if (!actingPk || !verifySig(action.sig, utf8(action.hash), actingPk)) return fail(1, "Signature chain", "action signature does not verify", "bad_signature");
  pass(1, "Signature chain", chain.map((m, i) => `hop ${i + 1} ${m.agent.did}`).join(" → "));

  // ---- 2. Principal assertion -------------------------------------------
  const parsed = parseRootAssertion(root.principal.assertion);
  if (!parsed) return fail(2, "Principal binding", "assertion unparseable", "principal_unverified");
  const trusted = ctx.trustedRoots[parsed.assertion.root];
  if (!trusted) return fail(2, "Principal binding", `root ${parsed.assertion.root} not trusted by this counterparty`, "principal_unverified");
  if (!verifyJson(parsed.signature, parsed.assertion, trusted.publicKey)) return fail(2, "Principal binding", "assertion signature does not verify", "principal_unverified");
  const a = parsed.assertion;
  if (a.root !== root.principal.root || a.sub !== root.principal.sub) return fail(2, "Principal binding", "assertion does not name this principal", "principal_unverified");
  if (ctx.issuerId && a.aud !== ctx.issuerId) return fail(2, "Principal binding", `assertion scoped to ${a.aud}, not ${ctx.issuerId}`, "principal_unverified");
  if (a.exp + CLOCK_SKEW_S < ctx.now) return fail(2, "Principal binding", "assertion expired", "principal_unverified");
  const need = (ctx.minLevel ?? defaultMinLevel)(action);
  if (LEVEL[a.level] < LEVEL[need]) return fail(2, "Principal binding", `assurance ${a.level} below required ${need}`, "principal_unverified");
  pass(2, "Principal binding", `${a.root} · ${a.level}`);

  // ---- 3. Status and validity window ------------------------------------
  const st = status.status;
  const issuerKid = root.sig[1].kid;
  if (status.kid !== issuerKid) return fail(3, "Status", "status not signed by the mandate's issuer", "stale");
  const issuerPk = ctx.keys(issuerKid);
  if (!issuerPk || !verifyStatusSignature(status, issuerPk)) return fail(3, "Status", "status signature does not verify", "stale");
  if (st.id !== root.id) return fail(3, "Status", `status is for ${st.id}, not tree root ${root.id}`, "stale");
  if (st.ttl > MAX_STATUS_TTL_S) return fail(3, "Status", `ttl ${st.ttl} exceeds ${MAX_STATUS_TTL_S}`, "stale");
  if (ctx.now - st.asof > st.ttl + CLOCK_SKEW_S) return fail(3, "Status", `status is ${ctx.now - st.asof}s old, ttl ${st.ttl}`, "stale");
  if (st.status === "revoked") return fail(3, "Status", `revoked${st.reason ? ": " + st.reason : ""}`, "revoked");
  if (st.status === "suspended") return fail(3, "Status", `suspended${st.reason ? ": " + st.reason : ""}`, "revoked");
  if (st.status === "expired") return fail(3, "Status", "issuer reports expired", "expired");
  for (let i = 0; i < chain.length; i++) {
    const m = chain[i];
    if (ctx.now < m.nbf - CLOCK_SKEW_S) return fail(3, "Status", `hop ${i + 1} not valid until ${m.nbf}`, "not_yet_valid");
    if (ctx.now > m.exp + CLOCK_SKEW_S) return fail(3, "Status", `hop ${i + 1} expired at ${m.exp}`, "expired");
  }
  pass(3, "Status", `active · asof ${st.asof} · spent ${st.spent}`);

  // ---- 4. Attenuation ----------------------------------------------------
  for (let i = 1; i < chain.length; i++) {
    const v = checkAttenuation(chain[i - 1], chain[i]);
    if (v.length) return fail(4, "Attenuation", `hop ${i + 1}: ${v[0]}`, "widened");
  }
  pass(4, "Attenuation", chain.length === 1 ? "single hop" : `${chain.length - 1} sub-mandate(s) narrower than parent`);

  // ---- 5. Scope ----------------------------------------------------------
  const eff = effective(chain);
  const refused = (eff.scope.may_not ?? []).find((p) => actionMatches(p, action.type));
  if (refused) return fail(5, "Scope", `${action.type} is refused by may_not (${refused})`, "out_of_scope");
  if (!eff.scope.may.some((p) => actionMatches(p, action.type))) return fail(5, "Scope", `${action.type} is not in effective may`, "out_of_scope");
  if (!eff.scope.counterparties.some((p) => patternCovers(p, action.counterparty)))
    return fail(5, "Scope", `counterparty ${action.counterparty} not in effective counterparties`, "out_of_scope");
  pass(5, "Scope", `${action.type} ∈ may · counterparty ${action.counterparty}`);

  // ---- 6. Limits ---------------------------------------------------------
  const L = eff.limits;
  if (action.amount !== undefined) {
    if (!Number.isInteger(action.amount) || action.amount < 0) return fail(6, "Limits", "amount must be a non-negative integer in minor units", "malformed");
    if (L.total === undefined || L.per_txn === undefined) return fail(6, "Limits", "mandate grants no spending authority", "over_limit");
    if (action.ccy !== L.ccy) return fail(6, "Limits", `currency ${action.ccy} is not mandate currency ${L.ccy}`, "over_limit");
    if (action.amount > L.per_txn) return fail(6, "Limits", `${action.amount} > per_txn ${L.per_txn}`, "over_limit");
    if (st.spent + action.amount > L.total) return fail(6, "Limits", `spent ${st.spent} + ${action.amount} > total ${L.total}`, "over_limit");
  }
  if (L.rate && ctx.recentActionCount !== undefined) {
    const r = parseRate(L.rate);
    if (r && ctx.recentActionCount >= r.count) return fail(6, "Limits", `rate ${L.rate} exhausted`, "over_limit");
  }
  pass(6, "Limits", action.amount === undefined ? "no amount" : `${action.amount} ≤ per_txn ${L.per_txn} · ${st.spent + action.amount} ≤ total ${L.total}`);

  // ---- 7. Confirm threshold ---------------------------------------------
  const overThreshold = action.amount !== undefined && L.confirm_over !== undefined && action.amount > L.confirm_over;
  const alwaysConfirm = (L.confirm_on ?? []).some((p) => actionMatches(p, action.type));
  if (overThreshold || alwaysConfirm) {
    pass(7, "Confirm threshold", overThreshold ? `${action.amount} > confirm_over ${L.confirm_over}` : `${action.type} ∈ confirm_on`);
    return { decision: "confirm", reason: null, checks, effective: eff, ...base };
  }
  pass(7, "Confirm threshold", "under threshold");
  return { decision: "allow", reason: null, checks, effective: eff, ...base };
}
