import { hashJson, signJson, ulid, verifyJson, type KeyPair } from "./crypto.ts";
import type { Action, KeyResolver, LedgerRecord, Mandate, SignedStatus, Verdict } from "./types.ts";

export interface BuildRecordInput {
  verdict: Verdict;
  chain: Mandate[];
  action: Action;
  status: SignedStatus;
  /** Verifier's operator identifier. */
  counterparty: string;
  /** Hash of the previous record in this tree, or null. */
  prev: string | null;
  atMs?: number;
  confirmRef?: string;
}

/** The part of a record that is hashed and signed: everything except the verifier's and issuer's own signatures. */
export function recordBody(r: LedgerRecord): Omit<LedgerRecord, "sig"> & { sig: { agent: string } } {
  const { sig, ...rest } = r;
  return { ...rest, sig: { agent: sig.agent } };
}

export function recordHash(r: LedgerRecord): string {
  return hashJson(recordBody(r));
}

export function buildRecord(input: BuildRecordInput): LedgerRecord {
  const { verdict, chain, action, status } = input;
  const acting = chain[chain.length - 1];
  const rec: LedgerRecord = {
    ref: "led_" + ulid(input.atMs),
    prev: input.prev,
    mandate: { id: acting.id, root: chain[0].id },
    hop: chain.length,
    agent: acting.agent.did,
    counterparty: input.counterparty,
    action: { type: action.type, amount: action.amount, ccy: action.ccy, hash: action.hash },
    decision: verdict.decision,
    reason: verdict.reason,
    status_asof: status.status.asof,
    at: input.atMs ?? Date.now(),
    sig: { agent: action.sig },
  };
  if (verdict.decision === "confirm") rec.confirm = { ref: input.confirmRef ?? "cfm_" + ulid(input.atMs) };
  return rec;
}

export function signRecordAsVerifier(r: LedgerRecord, verifierKey: KeyPair): LedgerRecord {
  return { ...r, sig: { ...r.sig, verifier: verifierKey.kid + ":" + signJson(recordBody(r), verifierKey.secretKey) } };
}

export function signRecordAsIssuer(r: LedgerRecord, issuerKey: KeyPair): LedgerRecord {
  return { ...r, sig: { ...r.sig, issuer: issuerKey.kid + ":" + signJson(recordBody(r), issuerKey.secretKey) } };
}

/** Record the principal's reply to a confirm. Returns a new record; the original stays in the chain. */
export function resolveConfirm(r: LedgerRecord, reply: "allow" | "deny", atMs = Date.now()): LedgerRecord {
  if (!r.confirm) throw new Error("record is not a confirm");
  return { ...r, confirm: { ...r.confirm, reply, at: atMs } };
}

function checkSig(tagged: string | undefined, body: unknown, keys: KeyResolver): boolean {
  if (!tagged) return false;
  const i = tagged.lastIndexOf(":"); // kids may contain colons (DIDs); base64url never does
  if (i < 0) return false;
  const pk = keys(tagged.slice(0, i));
  return !!pk && verifyJson(tagged.slice(i + 1), body, pk);
}

/**
 * Verify a tree's ledger: each record's prev equals the hash of the one before, and the
 * verifier signature (and issuer signature, when present) verifies. Returns the first problem or null.
 */
export function verifyLedger(records: LedgerRecord[], keys: KeyResolver): string | null {
  let prev: string | null = null;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.prev !== prev) return `record ${i} (${r.ref}): prev ${r.prev} does not match ${prev}`;
    if (!checkSig(r.sig.verifier, recordBody(r), keys)) return `record ${i} (${r.ref}): verifier signature missing or invalid`;
    if (r.sig.issuer && !checkSig(r.sig.issuer, recordBody(r), keys)) return `record ${i} (${r.ref}): issuer signature invalid`;
    prev = recordHash(r);
  }
  return null;
}
