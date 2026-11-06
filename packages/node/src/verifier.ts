import {
  buildRecord,
  decodeMandate,
  recordHash,
  signRecordAsVerifier,
  verifyAction,
  type Action,
  type AssuranceLevel,
  type KeyPair,
  type LedgerRecord,
  type Mandate,
  type Verdict,
} from "@getwarrant/core";
import { IssuerClient } from "./issuer-client.js";

export interface VerifierOptions {
  /** Issuer base URL, e.g. https://api.getwarrant.dev or the Supabase function URL. */
  issuer: string | IssuerClient;
  /** This counterparty's identifier as agents will name it in scope.counterparties, e.g. "iata:SQ" or "api:booking.com". */
  counterparty: string;
  /** Key this counterparty signs ledger records with. */
  key: KeyPair;
  /** Identity roots this counterparty accepts: root id → raw Ed25519 public key. */
  trustedRoots: Record<string, Uint8Array>;
  /** Minimum assurance per action. Default: any spend needs "substantial". */
  minLevel?: (action: Action) => AssuranceLevel;
  /** Extra key resolution (e.g. principal keys known out of band). Consulted after the issuer's keys. */
  keys?: (kid: string) => Uint8Array | undefined;
  /** Post a ledger record for every decision (default true). */
  ledger?: boolean;
  /** Clock, injectable for tests. Unix seconds. */
  now?: () => number;
}

export interface CheckResult {
  verdict: Verdict;
  chain: Mandate[];
  /** The record posted to the issuer, with the issuer's hash and (for confirm) the confirm ref. */
  ledger?: { ref: string; seq: number; hash: string; confirm_ref?: string; poll?: string };
}

/** Parses "Warrant-Mandate" header value: one or more wrt.* tokens, comma or space separated, hop 1 first. */
export function parseChainHeader(value: string | undefined | null): Mandate[] {
  if (!value) return [];
  return value
    .split(/[,\s]+/)
    .filter(Boolean)
    .map((t) => decodeMandate(t));
}

/** Parses "Warrant-Action-Signature": "<kid>:<base64url sig>". */
export function parseActionSignature(value: string | undefined | null): { kid: string; sig: string } | null {
  if (!value) return null;
  const i = value.lastIndexOf(":");
  if (i < 0) return null;
  return { kid: value.slice(0, i).trim(), sig: value.slice(i + 1).trim() };
}

/**
 * The counterparty's verifier. Holds the issuer client, trusted roots and this counterparty's signing key;
 * `check()` runs the seven checks, posts the ledger record and hands back the verdict.
 */
export class Verifier {
  readonly issuer: IssuerClient;
  readonly counterparty: string;
  private readonly prevByRoot = new Map<string, string | null>();
  constructor(private readonly opts: VerifierOptions) {
    this.issuer = typeof opts.issuer === "string" ? new IssuerClient(opts.issuer) : opts.issuer;
    this.counterparty = opts.counterparty;
  }

  /**
   * Run the seven checks for `action` under `chain`. Pass `confirmRef` when the agent is retrying an action the
   * principal has since confirmed: if the issuer reports that confirm as allowed for this exact action hash, the
   * verdict is allow and no new ledger record is written (the principal's reply already is one).
   */
  async check(chain: Mandate[], action: Action, confirmRef?: string): Promise<CheckResult> {
    if (!chain.length) {
      const v: Verdict = { decision: "deny", reason: "malformed", checks: [], mandate: "", root: "", hop: 0, ttl: 0 };
      return { verdict: v, chain };
    }
    const root = chain[0];
    const issuerKeys = await this.issuer.resolver(chain.map((m) => m.agent.did));
    const keys = (kid: string) => issuerKeys(kid) ?? this.opts.keys?.(kid);
    let confirmedHash: string | undefined;
    if (confirmRef) {
      const c = await this.issuer.confirmState(confirmRef).catch(() => null);
      if (c?.decision === "allow" && c.action_hash === action.hash) confirmedHash = action.hash;
      this.issuer.forgetStatus(root.id); // the reply changed spend; use a fresh status
    }
    const status = await this.issuer.status(root.id);
    const verdict = verifyAction(
      { chain, action, status },
      {
        now: (this.opts.now ?? (() => Math.floor(Date.now() / 1000)))(),
        keys,
        trustedRoots: Object.fromEntries(Object.entries(this.opts.trustedRoots).map(([id, pk]) => [id, { publicKey: pk }])),
        issuerId: await this.issuer.issuerId(),
        minLevel: this.opts.minLevel,
        confirmedHash,
      },
    );
    if (confirmedHash && verdict.decision === "allow") return { verdict, chain, ledger: { ref: confirmRef!, seq: -1, hash: "", confirm_ref: confirmRef } };
    if (this.opts.ledger === false || ["malformed", "bad_chain", "bad_signature"].includes(verdict.reason ?? "")) return { verdict, chain };

    // prev = hash of the last record this verifier knows for the tree; on mismatch the issuer tells us the real head.
    const rec: LedgerRecord = signRecordAsVerifier(
      buildRecord({ verdict, chain, action, status, counterparty: this.opts.counterparty, prev: this.prevByRoot.get(root.id) ?? null }),
      this.opts.key,
    );
    let posted;
    try {
      posted = await this.issuer.postLedger(root.id, rec);
    } catch (e) {
      const m = /expected prev (\S+)/.exec(String(e));
      if (!m) throw e;
      const prev = m[1] === "null" ? null : m[1];
      const retry = signRecordAsVerifier({ ...rec, prev }, this.opts.key);
      posted = await this.issuer.postLedger(root.id, retry);
    }
    this.prevByRoot.set(root.id, posted.hash);
    if (verdict.decision === "allow" && action.amount) this.issuer.forgetStatus(root.id); // spend changed
    return { verdict, chain, ledger: { ref: posted.ref, seq: posted.seq, hash: posted.hash, confirm_ref: posted.confirm_ref, poll: posted.poll } };
  }

  /** Poll a confirm until the principal answers or it expires. Resolves to "allow" or "deny". */
  async awaitConfirm(ref: string, opts: { intervalMs?: number; timeoutMs?: number } = {}): Promise<"allow" | "deny"> {
    const deadline = Date.now() + (opts.timeoutMs ?? 15 * 60_000);
    while (Date.now() < deadline) {
      const c = await this.issuer.confirmState(ref);
      if (c.decision !== "confirm") return c.decision;
      await new Promise((r) => setTimeout(r, opts.intervalMs ?? 2000));
    }
    return "deny";
  }

  /** Verifier-side hash of a record, for callers that keep their own copy of the chain. */
  static hash(record: LedgerRecord): string {
    return recordHash(record);
  }
}
