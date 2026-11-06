import {
  b64url,
  delegate,
  decodeMandate,
  encodeMandate,
  hashJson,
  signAction,
  signJson,
  type DelegateOptions,
  type KeyPair,
  type Limits,
  type Mandate,
  type Scope,
} from "@getwarrant/core";

export interface MandateRequest {
  purpose?: string;
  scope: Scope;
  limits: Limits;
  delegation: { max_depth: number; attenuate: true };
  nbf?: number;
  exp?: number;
}

type Fetch = typeof fetch;

/**
 * Agent side: register the agent's key with an issuer, ask a principal for a mandate, collect it, delegate,
 * and sign actions. One instance per (agent key, issuer).
 */
export class AgentClient {
  readonly base: string;
  readonly did: string;
  private fetchImpl: Fetch;
  constructor(private readonly key: KeyPair, issuerBase: string, opts: { fetch?: Fetch; runtime?: string; operator?: string } = {}) {
    this.base = issuerBase.replace(/\/$/, "");
    this.did = key.kid.split("#")[0];
    this.fetchImpl = opts.fetch ?? fetch;
    this.runtime = opts.runtime;
    this.operator = opts.operator;
  }
  private runtime?: string;
  private operator?: string;

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(this.base + path, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${j.error ?? ""}: ${j.message ?? ""}`);
    return j as T;
  }

  /** Register (or re-register) this agent's public key. Idempotent. */
  register(): Promise<{ did: string; kid: string }> {
    return this.call("POST", "/agents", { did: this.did, kid: this.key.kid, public_key: b64url(this.key.publicKey), operator: this.operator });
  }

  /** Ask for a mandate. Returns the request id and the consent URL to hand to the principal. */
  requestMandate(draft: MandateRequest): Promise<{ request_id: string; consent_url: string; expires_in: number }> {
    const agent = { did: this.did, kid: this.key.kid, ...(this.runtime ? { runtime: this.runtime } : {}) };
    return this.call("POST", "/requests", { agent, draft, sig: signJson({ agent, draft }, this.key.secretKey) });
  }

  /** Poll until the principal decides. Resolves with the mandate, or null if declined/expired. */
  async awaitMandate(requestId: string, opts: { intervalMs?: number; timeoutMs?: number } = {}): Promise<{ mandate: Mandate; token: string } | null> {
    const deadline = Date.now() + (opts.timeoutMs ?? 15 * 60_000);
    while (Date.now() < deadline) {
      const r = await this.call<{ state: string; token?: string }>("GET", `/requests/${requestId}/token`);
      if (r.state === "approved" && r.token) return { mandate: decodeMandate(r.token), token: r.token };
      if (r.state === "declined" || r.state === "expired") return null;
      await new Promise((res) => setTimeout(res, opts.intervalMs ?? 1500));
    }
    return null;
  }

  /** Issue a sub-mandate under `parent` and register it with the issuer so counterparties can ledger it. */
  async delegate(parent: Mandate, child: DelegateOptions["child"], parentSpent = 0): Promise<{ mandate: Mandate; token: string }> {
    const sub = delegate(parent, { agentKey: this.key, child, parentSpent });
    const token = encodeMandate(sub);
    await this.call("POST", "/mandates", { token });
    return { mandate: sub, token };
  }

  /** Headers for an HTTP action: the chain and a signature over the hash of `description` (what the counterparty will hash too). */
  headers(chain: (Mandate | string)[], description: unknown): Record<string, string> {
    const hash = hashJson(description);
    const { kid, sig } = signAction(hash, this.key);
    return { "warrant-mandate": chain.map((c) => (typeof c === "string" ? c : encodeMandate(c))).join(","), "warrant-action-signature": `${kid}:${sig}` };
  }

  /** Sign an arbitrary action hash. */
  sign(hash: string): { kid: string; sig: string } {
    return signAction(hash, this.key);
  }

  /** Resign authority: revoke a mandate this agent holds or issued (cascades). */
  revoke(mandateId: string, reason?: string): Promise<{ revoked: string[] }> {
    return this.call("POST", `/mandates/${mandateId}/revoke`, { reason, agent: { kid: this.key.kid, sig: signJson({ revoke: mandateId }, this.key.secretKey) } });
  }
}
