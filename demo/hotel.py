"""Mock hotel API on FastAPI: uses the issuer's hosted verifier through warrant-fastapi."""
import os
from fastapi import Depends, FastAPI
from warrant_fastapi import WarrantResult, WarrantVerifier

ISSUER = os.environ.get("WARRANT_BASE", "https://vvnvwrefyrrapjhmpajr.supabase.co/functions/v1/warrant")
app = FastAPI(title="Booking.com (mock)")
warrant = WarrantVerifier(ISSUER, counterparty="api:booking.com")

ROOMS = [{"hotel": "Hotel Jen Orchardgateway", "nights": 4, "total": 54000}, {"hotel": "Hotel G Singapore", "nights": 4, "total": 38000}]


@app.get("/rooms")
async def rooms():
    return {"rooms": ROOMS, "ccy": "USD"}


# Agents POST {hotel, amount, ccy} and sign the hash of exactly that body.
@app.post("/hold")
async def hold(body: dict, w: WarrantResult = Depends(warrant.require("travel:book_hotel"))):
    return {"held": body["hotel"], "hop": w.hop, "ledger": (w.ledger or {}).get("ref")}
