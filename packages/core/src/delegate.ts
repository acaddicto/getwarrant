import { signJson, type KeyPair } from "./crypto.ts";
import { checkAttenuation } from "./attenuate.ts";
import { MandateError, mandateId, signingPayload, validateShape } from "./mandate.ts";
import type { AgentRef, Limits, Mandate, Scope, Signature } from "./types.ts";

export interface DelegateOptions {
  /** The delegating agent's key. Its kid MUST be a fragment of the parent's agent DID, e.g. did:web:x#k1. */
  agentKey: KeyPair;
  child: {
    agent: AgentRef;
    scope: Scope;
    limits: Limits;
    nbf?: number;
    exp?: number;
  };
  /** Spend already recorded against the parent tree, from the issuer's status. */
  parentSpent?: number;
  id?: string;
  nowMs?: number;
}

/**
 * Issue a sub-mandate under `parent`.
 *
 * Signature binding: the child's sig[] starts with a byte-for-byte copy of the parent's sig[]
 * (which bind the parent's payload), then appends the delegating agent's signature over the child
 * payload with sig[] truncated to those copied entries. A verifier therefore checks the parent chain
 * first, then that each sub-mandate's leading signatures equal its parent's, then the agent hop.
 */
export function delegate(parent: Mandate, opts: DelegateOptions): Mandate {
  if (parent.delegation.max_depth < 1) throw new MandateError("widened", "parent forbids delegation (max_depth 0)");
  const did = parent.agent.did;
  if (!opts.agentKey.kid.startsWith(did + "#"))
    throw new MandateError("bad_signature", `agent key ${opts.agentKey.kid} does not belong to ${did}`);

  const nowS = Math.floor((opts.nowMs ?? Date.now()) / 1000);
  const child: Mandate = {
    typ: parent.typ,
    ver: parent.ver,
    id: opts.id ?? mandateId(opts.nowMs),
    parent: parent.id,
    principal: parent.principal,
    agent: opts.child.agent,
    scope: opts.child.scope,
    limits: opts.child.limits,
    delegation: { max_depth: parent.delegation.max_depth - 1, attenuate: true },
    nbf: opts.child.nbf ?? Math.max(parent.nbf, nowS),
    exp: opts.child.exp ?? parent.exp,
    revocation: parent.revocation,
    ledger: parent.ledger,
    sig: [...parent.sig],
  };
  const shape = validateShape(child);
  if (shape.length) throw new MandateError("malformed", shape.join("; "));
  const violations = checkAttenuation(parent, child, opts.parentSpent ?? 0);
  if (violations.length) throw new MandateError("widened", violations.join("; "));

  const hop: Signature = {
    by: "agent",
    alg: "EdDSA",
    kid: opts.agentKey.kid,
    did,
    iat: nowS,
    value: signJson(signingPayload(child, child.sig.length), opts.agentKey.secretKey),
  };
  return { ...child, sig: [...child.sig, hop] };
}
