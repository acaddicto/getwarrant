// Writes web/consent.html from the CONSENT_HTML template so the page can be hosted statically (GitHub Pages, getwarrant.dev).
import { writeFileSync } from "node:fs";
import { CONSENT_HTML } from "../supabase/functions/warrant/consent.ts";
writeFileSync(new URL("../web/consent.html", import.meta.url), CONSENT_HTML);
console.log("wrote web/consent.html", CONSENT_HTML.length, "bytes");
