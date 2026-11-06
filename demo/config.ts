import { b64url, keyPairFromSecret } from "@getwarrant/core";

export const ISSUER = process.env.WARRANT_BASE ?? "https://vvnvwrefyrrapjhmpajr.supabase.co/functions/v1/warrant";
export const AIRLINE_PORT = 4010;
export const HOTEL_PORT = 4020;

// Demo keys only. Deterministic so the walk-through is reproducible; never reuse these seeds.
const seed = (n: number) => new Uint8Array(32).map((_, i) => (i * 11 + n * 29) % 256);
export const keys = {
  demoRoot: keyPairFromSecret("demo-wallet:signer-1", seed(100)),
  principal: (() => { const k = keyPairFromSecret("", seed(1)); k.kid = "key:" + b64url(k.publicKey); return k; })(),
  tripwise: keyPairFromSecret("did:web:agents.tripwise.com#k1", seed(4)),
  farescout: keyPairFromSecret("did:web:farescout.ai#k1", seed(5)),
  airline: keyPairFromSecret("did:web:singaporeair.com#verifier", seed(7)),
};
