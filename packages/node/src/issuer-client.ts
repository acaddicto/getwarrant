import { unb64url, type SignedStatus } from "@getwarrant/core";

export interface IssuerDiscovery {
  issuer: string;
  spec: string;
  keys: { kid: string; alg: string; public_key: string }[];
  endpoints: Record<string, string>;
}

type Fetch = typeof fetch;

/**
 * Read-side client for a Warrant issuer: discovery, status (cached to ttl), agent keys (cached), revocation list.
 * Used by verifiers. No credentials involved.
 */
export class IssuerClient {
  readonly base: string;
  private disco?: Promise<IssuerDiscovery>;
  private statusCache = new Map<string, { s: SignedStatus; until: number }>();
  private agentCache = new Map<string, { keys: Map<string, Uint8Array>; until: number }>();
  private fetchImpl: Fetch;

  constructor(base: string, opts: { fetch?: Fetch } = {}) {
    this.base = base.replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? fetch;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(this.base + path, { headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`${path} → ${res.status}`);
    return (await res.json()) as T;
  }

  discovery(): Promise<IssuerDiscovery> {
    return (this.disco ??= this.get<IssuerDiscovery>("/.well-known/warrant.json"));
  }

  async issuerId(): Promise<string> {
    return (await this.discovery()).issuer;
  }

  /** Signed status for the tree containing `anyIdInTree`. Cached until the issuer's ttl runs out. */
  async status(anyIdInTree: string): Promise<SignedStatus> {
    const hit = this.statusCache.get(anyIdInTree);
    if (hit && hit.until > Date.now()) return hit.s;
    const s = await this.get<SignedStatus>(`/r/${encodeURIComponent(anyIdInTree)}`);
    const until = Date.now() + Math.max(0, s.status.ttl - 5) * 1000;
    this.statusCache.set(anyIdInTree, { s, until });
    this.statusCache.set(s.status.id, { s, until });
    return s;
  }

  forgetStatus(id: string) {
    this.statusCache.delete(id);
  }

  async agentKeys(did: string): Promise<Map<string, Uint8Array>> {
    const hit = this.agentCache.get(did);
    if (hit && hit.until > Date.now()) return hit.keys;
    const r = await this.get<{ keys: { kid: string; public_key: string }[] }>(`/agents/${encodeURIComponent(did)}`).catch(() => ({ keys: [] }));
    const keys = new Map(r.keys.map((k) => [k.kid, unb64url(k.public_key)]));
    this.agentCache.set(did, { keys, until: Date.now() + 5 * 60_000 });
    return keys;
  }

  /** A KeyResolver over the issuer's own keys, the agents in `dids`, and software principal keys ("key:<pubkey>"). */
  async resolver(dids: string[]): Promise<(kid: string) => Uint8Array | undefined> {
    const d = await this.discovery();
    const map = new Map<string, Uint8Array>(d.keys.map((k) => [k.kid, unb64url(k.public_key)]));
    for (const did of new Set(dids)) for (const [kid, pk] of await this.agentKeys(did)) map.set(kid, pk);
    return (kid) => {
      const hit = map.get(kid);
      if (hit) return hit;
      if (kid.startsWith("key:")) {
        try {
          const b = unb64url(kid.slice(4));
          return b.length === 32 ? b : undefined;
        } catch {
          return undefined;
        }
      }
      return undefined;
    };
  }

  async postLedger(rootId: string, record: unknown): Promise<{ ref: string; seq: number; hash: string; issuer_sig: string; confirm_ref?: string; poll?: string }> {
    const res = await this.fetchImpl(`${this.base}/l/${encodeURIComponent(rootId)}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(record) });
    const j = await res.json();
    if (!res.ok) throw new Error(`ledger post → ${res.status} ${j.error}: ${j.message ?? ""}`);
    return j;
  }

  async confirmState(ref: string): Promise<{ decision: "allow" | "confirm" | "deny"; state: string; action_hash?: string; amount?: number | null }> {
    return this.get(`/confirm/${encodeURIComponent(ref)}`);
  }
}
