"""Warrant for FastAPI.

The agent sends two headers:

    Warrant-Mandate: <hop-1 token>[,<sub-mandate token>...]
    Warrant-Action-Signature: <kid>:<base64url Ed25519 signature over the action hash>
    Warrant-Confirm: <confirm ref>        (only when retrying an action the principal has since confirmed)

The action hash is SHA-256 over the RFC 8785 (JCS) form of the request's JSON body, unless `describe` says otherwise.
Verification itself runs at the Warrant issuer's hosted verifier (POST /verify), which also writes the ledger record.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import httpx
from fastapi import HTTPException, Request


def jcs(value: Any) -> str:
    """RFC 8785 JSON Canonicalization: sorted keys, no whitespace, ES number formatting for the common cases."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int,)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JCS: non-finite number")
        if value == int(value) and abs(value) < 1e21:
            return str(int(value))
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join("null" if v is None else jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(((k, v) for k, v in value.items() if v is not None), key=lambda kv: [ord(c) for c in kv[0]])
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v) for k, v in items) + "}"
    raise TypeError(f"JCS: unsupported type {type(value)}")


def action_hash(description: Any) -> str:
    return hashlib.sha256(jcs(description).encode("utf-8")).hexdigest()


@dataclass
class WarrantResult:
    decision: str                 # allow | confirm | deny
    reason: Optional[str]
    mandate: str
    root: str
    hop: int
    checks: list[dict]
    ledger: Optional[dict]        # {ref, seq, hash, confirm_ref?, poll?} or None
    action: dict


class WarrantError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str, checks: Optional[list[dict]] = None, extra: Optional[dict] = None):
        detail = {"error": code, "message": message}
        if checks:
            detail["checks"] = checks
        if extra:
            detail.update(extra)
        super().__init__(status_code=status_code, detail=detail)


class WarrantVerifier:
    """One per service. `issuer` is the issuer base URL; `counterparty` is how agents name you in scope.counterparties."""

    def __init__(self, issuer: str, counterparty: str, *, client: Optional[httpx.AsyncClient] = None, timeout: float = 10.0):
        self.issuer = issuer.rstrip("/")
        self.counterparty = counterparty
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def verify(self, chain: list[str], action: dict, confirm: Optional[str] = None) -> WarrantResult:
        payload: dict = {"chain": chain, "action": action, "counterparty": self.counterparty}
        if confirm:
            payload["confirm"] = confirm
        r = await self._client.post(f"{self.issuer}/verify", json=payload)
        if r.status_code >= 400:
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": "issuer_error", "message": r.text}
            raise WarrantError(502 if r.status_code >= 500 else 400, body.get("error", "issuer_error"), body.get("message", ""))
        j = r.json()
        v = j["verdict"]
        return WarrantResult(v["decision"], v.get("reason"), v["mandate"], v["root"], v["hop"], v.get("checks", []), j.get("ledger"), action)

    async def confirm_state(self, ref: str) -> str:
        r = await self._client.get(f"{self.issuer}/confirm/{ref}")
        r.raise_for_status()
        return r.json()["decision"]

    def require(
        self,
        action: str | Callable[[Request], str],
        *,
        describe: Optional[Callable[[Request, Any], Any]] = None,
        amount: Optional[Callable[[Request, Any], Optional[tuple[int, str]]]] = None,
        on_confirm: str = "hold",
    ) -> Callable[[Request], Awaitable[WarrantResult]]:
        """FastAPI dependency factory.

            verifier = WarrantVerifier("https://api.getwarrant.dev", "iata:SQ")

            @app.post("/book")
            async def book(body: Booking, w: WarrantResult = Depends(verifier.require("travel:book_flight"))):
                ...

        `describe(request, body)` returns what gets hashed (default: the JSON body). `amount(request, body)` returns
        (minor_units, ccy) or None (default: body["amount"], body["ccy"] when both present).
        """

        async def dependency(request: Request) -> WarrantResult:
            mandate_header = request.headers.get("warrant-mandate")
            sig_header = request.headers.get("warrant-action-signature")
            if not mandate_header:
                raise WarrantError(401, "mandate_required", "send Warrant-Mandate and Warrant-Action-Signature")
            if not sig_header or ":" not in sig_header:
                raise WarrantError(401, "signature_required", "send Warrant-Action-Signature: <kid>:<sig>")
            kid, _, sig = sig_header.rpartition(":")
            chain = [t for t in mandate_header.replace(" ", ",").split(",") if t]
            try:
                body = await request.json()
            except Exception:
                body = None
            desc = describe(request, body) if describe else body
            amt = amount(request, body) if amount else _default_amount(body)
            act: dict = {
                "type": action(request) if callable(action) else action,
                "counterparty": self.counterparty,
                "hash": action_hash(desc),
                "kid": kid.strip(),
                "sig": sig.strip(),
            }
            if amt:
                act["amount"], act["ccy"] = amt
            result = await self.verify(chain, act, request.headers.get("warrant-confirm"))
            if result.decision == "deny":
                detail = result.checks[-1]["detail"] if result.checks else "denied"
                raise WarrantError(403, result.reason or "deny", detail, result.checks)
            if result.decision == "confirm":
                ref = (result.ledger or {}).get("confirm_ref")
                if on_confirm == "wait" and ref:
                    import asyncio
                    for _ in range(60):
                        state = await self.confirm_state(ref)
                        if state != "confirm":
                            break
                        await asyncio.sleep(2)
                    if state != "allow":
                        raise WarrantError(403, "principal_denied", "the principal declined or did not answer", result.checks)
                else:
                    raise WarrantError(202, "confirm", f"held for the principal; once confirmed, repeat the identical request with Warrant-Confirm: {ref}", extra={"confirm_ref": ref, "poll": (result.ledger or {}).get("poll")})
            return result

        return dependency


def _default_amount(body: Any) -> Optional[tuple[int, str]]:
    if isinstance(body, dict) and isinstance(body.get("amount"), int) and not isinstance(body.get("amount"), bool) and isinstance(body.get("ccy"), str):
        return body["amount"], body["ccy"]
    return None
