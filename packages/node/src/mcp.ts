import { encodeMandate as encode, hashJson, type Action, type Mandate } from "@getwarrant/core";
import { parseChainHeader, Verifier, type CheckResult } from "./verifier.js";

/**
 * Warrant for MCP tools. The calling agent passes its authority inside the tool arguments:
 *
 *   { ...toolArgs, _warrant: { mandate: "<token>[,<token>]", kid: "<kid>", sig: "<sig over hash>" } }
 *
 * The hash is SHA-256 over the JCS form of the tool arguments without `_warrant`. Wrap a tool handler with
 * `guardTool`; the handler receives the verified result and the clean arguments.
 */
export interface WarrantArgs {
  _warrant?: { mandate: string; kid: string; sig: string; confirm?: string };
  [k: string]: unknown;
}

export interface GuardOptions<A extends WarrantArgs> {
  action: string | ((args: A) => string);
  amount?: (args: A) => { amount: number; ccy: string } | undefined;
  onConfirm?: "hold" | "wait";
  waitMs?: number;
}

export class WarrantToolError extends Error {
  constructor(public readonly code: string, message: string, public readonly result?: CheckResult) {
    super(message);
    this.name = "WarrantToolError";
  }
}

export function guardTool<A extends WarrantArgs, R>(verifier: Verifier, opts: GuardOptions<A>, handler: (args: Omit<A, "_warrant">, warrant: CheckResult & { action: Action }) => Promise<R> | R) {
  return async (args: A): Promise<R> => {
    const { _warrant, ...clean } = args;
    if (!_warrant?.mandate || !_warrant.kid || !_warrant.sig) throw new WarrantToolError("mandate_required", "pass _warrant: { mandate, kid, sig } with the tool arguments");
    let chain: Mandate[];
    try {
      chain = parseChainHeader(_warrant.mandate);
    } catch (e) {
      throw new WarrantToolError("malformed", (e as Error).message);
    }
    const amt = opts.amount?.(args);
    const action: Action = {
      type: typeof opts.action === "function" ? opts.action(args) : opts.action,
      ...(amt ? { amount: amt.amount, ccy: amt.ccy } : {}),
      counterparty: verifier.counterparty,
      hash: hashJson(clean),
      kid: _warrant.kid,
      sig: _warrant.sig,
    };
    const result = await verifier.check(chain, action, _warrant.confirm);
    if (result.verdict.decision === "deny") throw new WarrantToolError(result.verdict.reason ?? "deny", result.verdict.checks.at(-1)?.detail ?? "denied", result);
    if (result.verdict.decision === "confirm") {
      const ref = result.ledger?.confirm_ref;
      if ((opts.onConfirm ?? "hold") === "wait" && ref) {
        const answer = await verifier.awaitConfirm(ref, { timeoutMs: opts.waitMs ?? 120_000 });
        if (answer === "deny") throw new WarrantToolError("principal_denied", "the principal declined", result);
      } else {
        throw new WarrantToolError("confirm", `held for the principal; poll ${result.ledger?.poll ?? ref} and call again with _warrant.confirm = "${ref}" once confirmed`, result);
      }
    }
    return handler(clean as Omit<A, "_warrant">, { ...result, action });
  };
}

/** Agent side: build the `_warrant` argument for a tool call. */
export function warrantArgs(chain: Mandate[] | string[], toolArgs: Record<string, unknown>, sign: (hash: string) => { kid: string; sig: string }): WarrantArgs["_warrant"] {
  const tokens = chain.map((c) => (typeof c === "string" ? c : encode(c)));
  return { mandate: tokens.join(","), ...sign(hashJson(toolArgs)) };
}


