import type { Limits, Mandate, Scope } from "./types.ts";

/** Does a parent counterparty pattern cover a child pattern? `*` covers all; `prefix:*` covers `prefix:x` and `prefix:*`; else exact. */
export function patternCovers(parent: string, child: string): boolean {
  if (parent === "*") return true;
  if (parent.endsWith(":*")) {
    const prefix = parent.slice(0, -1); // keep the colon
    return child.startsWith(prefix);
  }
  return parent === child;
}

/** Does an action type match a scope entry? Entries are exact or `namespace:*`. */
export function actionMatches(entry: string, actionType: string): boolean {
  return patternCovers(entry, actionType);
}

const minDefined = (a?: number, b?: number) => (a === undefined ? b : b === undefined ? a : Math.min(a, b));
const uniq = (xs: string[]) => [...new Set(xs)];

export interface Effective {
  scope: Scope;
  limits: Limits;
  nbf: number;
  exp: number;
}

/**
 * Intersection of a chain, hop 1 first. Assumes the chain has already passed checkChain();
 * on an unchecked chain this is still the conservative (narrowest) reading.
 */
export function effective(chain: Mandate[]): Effective {
  const [root, ...rest] = chain;
  let eff: Effective = {
    scope: { may: [...root.scope.may], may_not: [...(root.scope.may_not ?? [])], counterparties: [...root.scope.counterparties] },
    limits: { ...root.limits, confirm_on: [...(root.limits.confirm_on ?? [])] },
    nbf: root.nbf,
    exp: root.exp,
  };
  for (const m of rest) {
    eff = {
      scope: {
        may: m.scope.may.filter((a) => eff.scope.may.some((p) => actionMatches(p, a))),
        may_not: uniq([...(eff.scope.may_not ?? []), ...(m.scope.may_not ?? [])]),
        counterparties: m.scope.counterparties.filter((c) => eff.scope.counterparties.some((p) => patternCovers(p, c))),
      },
      limits: {
        ccy: eff.limits.ccy ?? m.limits.ccy,
        total: minDefined(eff.limits.total, m.limits.total),
        per_txn: minDefined(eff.limits.per_txn, m.limits.per_txn),
        confirm_over: minDefined(eff.limits.confirm_over, m.limits.confirm_over),
        confirm_on: uniq([...(eff.limits.confirm_on ?? []), ...(m.limits.confirm_on ?? [])]),
        rate: m.limits.rate ?? eff.limits.rate,
      },
      nbf: Math.max(eff.nbf, m.nbf),
      exp: Math.min(eff.exp, m.exp),
    };
  }
  return eff;
}

/**
 * Attenuation table from the spec, applied to one parent/child pair.
 * `parentSpent` is what the parent tree had already spent when the child was issued (issuer-tracked).
 * Returns [] when the child is equal to or narrower than the parent on every axis.
 */
export function checkAttenuation(parent: Mandate, child: Mandate, parentSpent = 0): string[] {
  const v: string[] = [];
  if (child.parent !== parent.id) v.push(`parent: child.parent=${child.parent} does not name ${parent.id}`);

  for (const a of child.scope.may)
    if (!parent.scope.may.some((p) => actionMatches(p, a))) v.push(`scope.may: ${a} not in parent may`);
  for (const a of parent.scope.may_not ?? [])
    if (!(child.scope.may_not ?? []).includes(a)) v.push(`scope.may_not: child dropped ${a}`);
  for (const c of child.scope.counterparties)
    if (!parent.scope.counterparties.some((p) => patternCovers(p, c))) v.push(`scope.counterparties: ${c} not covered by parent`);

  const P = parent.limits, C = child.limits;
  if (P.total !== undefined) {
    const remaining = Math.max(0, P.total - parentSpent);
    if (C.total === undefined) v.push("limits.total: child must set total when parent has one");
    else if (C.total > remaining) v.push(`limits.total: ${C.total} exceeds parent remaining ${remaining}`);
  }
  if (P.per_txn !== undefined) {
    if (C.per_txn === undefined) v.push("limits.per_txn: child must set per_txn when parent has one");
    else if (C.per_txn > P.per_txn) v.push(`limits.per_txn: ${C.per_txn} > parent ${P.per_txn}`);
  }
  if (P.total === undefined && (C.total !== undefined || C.per_txn !== undefined || C.ccy !== undefined))
    v.push("limits: parent grants no spending authority; child cannot add any");
  if (P.ccy !== undefined && C.ccy !== P.ccy) v.push(`limits.ccy: ${C.ccy} differs from parent ${P.ccy}`);
  if (P.confirm_over !== undefined) {
    if (C.confirm_over === undefined) v.push("limits.confirm_over: child must keep a threshold when parent has one");
    else if (C.confirm_over > P.confirm_over) v.push(`limits.confirm_over: ${C.confirm_over} > parent ${P.confirm_over}`);
  }
  for (const a of P.confirm_on ?? [])
    if (!(C.confirm_on ?? []).includes(a)) v.push(`limits.confirm_on: child dropped ${a}`);

  if (child.delegation.max_depth !== parent.delegation.max_depth - 1)
    v.push(`delegation.max_depth: must be ${parent.delegation.max_depth - 1}, got ${child.delegation.max_depth}`);
  if (child.nbf < parent.nbf) v.push("nbf: earlier than parent");
  if (child.exp > parent.exp) v.push("exp: later than parent");

  const pp = parent.principal, cp = child.principal;
  if (pp.root !== cp.root || pp.sub !== cp.sub || pp.key !== cp.key || pp.assertion !== cp.assertion)
    v.push("principal: must be identical to parent");
  if (child.revocation !== parent.revocation) v.push("revocation: must be identical to parent");
  if (child.ledger !== parent.ledger) v.push("ledger: must be identical to parent");
  return v;
}
