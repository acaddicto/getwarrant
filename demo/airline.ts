/**
 * Mock airline: an Express API that only books under a valid Warrant mandate.
 * Runs its own verifier (local checks, own signing key, its own list of trusted identity roots).
 */
import express from "express";
import { Verifier, warrantExpress } from "@getwarrant/node";
import { AIRLINE_PORT, ISSUER, keys } from "./config.ts";

const verifier = new Verifier({
  issuer: ISSUER,
  counterparty: "iata:SQ",
  key: keys.airline,
  trustedRoots: { "demo-wallet": keys.demoRoot.publicKey },
});
const warrant = warrantExpress(verifier);
const app = express();
app.use(express.json());

const flights = [{ no: "SQ529", from: "MAA", to: "SIN", date: "2026-11-14", fare: 47800 }, { no: "SQ528", from: "SIN", to: "MAA", date: "2026-11-18", fare: 46200 }];
app.get("/flights", (_req, res) => res.json({ flights, ccy: "USD" }));

// Agents POST { flight, amount, ccy } and sign the hash of exactly that body.
app.post("/book", warrant.require({ action: "travel:book_flight" }), (req, res) => {
  const w = (req as any).warrant;
  const f = flights.find((x) => x.no === req.body.flight);
  if (!f) return res.status(404).json({ error: "no_such_flight" });
  if (req.body.amount !== f.fare) return res.status(409).json({ error: "fare_changed", fare: f.fare });
  res.json({ pnr: "W" + Math.random().toString(36).slice(2, 7).toUpperCase(), flight: f, hop: w.verdict.hop, agent: w.chain.at(-1).agent.did, ledger: w.ledger?.ref });
});

app.post("/cancel", warrant.require({ action: "travel:cancel_own_booking", onConfirm: "hold" }), (req, res) => res.json({ cancelled: req.body.pnr }));

app.listen(AIRLINE_PORT, () => console.log(`airline  listening on :${AIRLINE_PORT} (iata:SQ, trusts demo-wallet, verifies locally)`));
