import type { Request, RequestHandler, Response } from "express";
import { hashJson, type Action, type Mandate, type Verdict } from "@getwarrant/core";
import { parseActionSignature, parseChainHeader, Verifier, type CheckResult } from "./verifier.js";

export interface WarrantRequest extends Request {
  warrant?: CheckResult & { action: Action };
}

export interface RequireOptions {
  /** Action type, or a function of the request. */
  action: string | ((req: Request) => string);
  /**
   * What the agent is about to do, as the counterparty describes it. Hashed with SHA-256 over JCS and compared
   * to the hash the agent signed. Default: the JSON body. The agent MUST have hashed the same description.
   */
  describe?: (req: Request) => unknown;
  /** Amount in minor units and currency, if the action spends. Default: body.amount / body.ccy when present. */
  amount?: (req: Request) => { amount: number; ccy: string } | undefined;
  /** What to do on `confirm`. "hold" (default) answers 202 with the confirm ref; "wait" polls the issuer up to waitMs. */
  onConfirm?: "hold" | "wait";
  waitMs?: number;
}

export const HEADERS = { mandate: "warrant-mandate", signature: "warrant-action-signature", confirm: "warrant-confirm" } as const;

/**
 * Express middleware. Agents send:
 *   Warrant-Mandate: <hop-1 token>[,<sub-mandate token>...]
 *   Warrant-Action-Signature: <kid>:<base64url Ed25519 signature over the action hash>
 *   Warrant-Confirm: <confirm ref>        (only when retrying an action the principal has confirmed)
 * The hash is SHA-256 over the JCS form of the request body unless `describe` says otherwise.
 */
export function warrantExpress(verifier: Verifier) {
  return {
    require(opts: RequireOptions): RequestHandler {
      return async (req, res, next) => {
        let chain: Mandate[];
        try {
          chain = parseChainHeader(req.header(HEADERS.mandate));
        } catch (e) {
          return deny(res, 400, "malformed", `Warrant-Mandate: ${(e as Error).message}`);
        }
        if (!chain.length) return deny(res, 401, "mandate_required", `send Warrant-Mandate and ${HEADERS.signature}`);
        const sig = parseActionSignature(req.header(HEADERS.signature));
        if (!sig) return deny(res, 401, "signature_required", `send ${HEADERS.signature}: <kid>:<sig>`);
        const amt = (opts.amount ?? defaultAmount)(req);
        const action: Action = {
          type: typeof opts.action === "function" ? opts.action(req) : opts.action,
          ...(amt ? { amount: amt.amount, ccy: amt.ccy } : {}),
          counterparty: verifier.counterparty,
          hash: hashJson((opts.describe ?? ((r) => r.body))(req)),
          kid: sig.kid,
          sig: sig.sig,
        };
        let result: CheckResult;
        try {
          result = await verifier.check(chain, action, req.header(HEADERS.confirm) ?? undefined);
        } catch (e) {
          return deny(res, 502, "issuer_unreachable", (e as Error).message);
        }
        res.setHeader("warrant-decision", result.verdict.decision);
        if (result.ledger) res.setHeader("warrant-ledger-ref", result.ledger.ref);
        if (result.verdict.decision === "deny") return deny(res, 403, result.verdict.reason ?? "deny", result.verdict.checks.at(-1)?.detail ?? "", result.verdict);
        if (result.verdict.decision === "confirm") {
          const ref = result.ledger?.confirm_ref;
          if ((opts.onConfirm ?? "hold") === "wait" && ref) {
            const answer = await verifier.awaitConfirm(ref, { timeoutMs: opts.waitMs ?? 120_000 });
            if (answer === "deny") return deny(res, 403, "principal_denied", "the principal declined", result.verdict);
          } else {
            res.status(202).json({ decision: "confirm", confirm_ref: ref, poll: result.ledger?.poll, message: `held for the principal; once confirmed, repeat the identical request with ${HEADERS.confirm}: ${ref}` });
            return;
          }
        }
        (req as WarrantRequest).warrant = { ...result, action };
        next();
      };
    },
  };
}

function defaultAmount(req: Request): { amount: number; ccy: string } | undefined {
  const b = req.body ?? {};
  return Number.isInteger(b.amount) && typeof b.ccy === "string" ? { amount: b.amount, ccy: b.ccy } : undefined;
}

function deny(res: Response, status: number, error: string, message: string, verdict?: Verdict) {
  res.status(status).json({ error, message, ...(verdict ? { checks: verdict.checks } : {}) });
}
