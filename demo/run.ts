/** Starts the airline and the hotel, runs the agent, shuts everything down. */
import { spawn } from "node:child_process";
import { AIRLINE_PORT, HOTEL_PORT } from "./config.ts";

const procs = [
  spawn("npx", ["tsx", "airline.ts"], { stdio: ["ignore", "inherit", "inherit"] }),
  spawn("python3", ["-m", "uvicorn", "hotel:app", "--port", String(HOTEL_PORT), "--log-level", "warning"], { stdio: ["ignore", "inherit", "inherit"] }),
];
const up = async (url: string) => { for (let i = 0; i < 60; i++) { try { if ((await fetch(url)).ok) return; } catch {} await new Promise((r) => setTimeout(r, 500)); } throw new Error("service did not start: " + url); };
try {
  await up(`http://127.0.0.1:${AIRLINE_PORT}/flights`);
  await up(`http://127.0.0.1:${HOTEL_PORT}/rooms`);
  console.log(`hotel    listening on :${HOTEL_PORT} (api:booking.com, hosted verifier)\n`);
  await new Promise<void>((res, rej) => { const a = spawn("npx", ["tsx", "agent.ts"], { stdio: "inherit" }); a.on("exit", (c) => (c ? rej(new Error("agent exited " + c)) : res())); });
} finally {
  procs.forEach((p) => p.kill());
}
