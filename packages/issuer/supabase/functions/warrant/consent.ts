// The consent page, served at GET /consent/:request_id. One file, no build step.
// Flow: load request → sign in (root assertion) → have or create a passkey → adjust terms → approve with passkey → done.
export const CONSENT_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Warrant · Consent</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:ital,wght@0,500;1,400&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
:root{--bg:#F5F6F9;--surface:#fff;--sunk:#EDEFF4;--line:#D9DDE6;--line-strong:#B9BFCC;--fg:#151A23;--muted:#5B6474;--faint:#8A92A3;--accent:#1F3FBF;--accent-fg:#fff;--accent-soft:#E6EAFB;--good:#1C7A4C;--good-soft:#E2F3EA;--warn:#A8601A;--warn-soft:#FBEFDF;--bad:#B52F2C;--bad-soft:#FBE6E5;--sans:"IBM Plex Sans",system-ui,sans-serif;--serif:"IBM Plex Serif",Georgia,serif;--mono:"IBM Plex Mono",ui-monospace,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0F1218;--surface:#171B23;--sunk:#1E232D;--line:#2A3040;--line-strong:#3C4457;--fg:#E8EBF2;--muted:#A4ACBD;--faint:#6F788A;--accent:#8EA3FF;--accent-fg:#0B1030;--accent-soft:#1F2744;--good:#5BC98A;--good-soft:#13301F;--warn:#E6A35A;--warn-soft:#352614;--bad:#F07C78;--bad-soft:#3A1816;color-scheme:dark}}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}button{cursor:pointer}:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.app{height:100%;display:grid;grid-template-rows:auto 1fr}
header{height:52px;display:flex;align-items:center;gap:10px;padding:0 max(16px,env(safe-area-inset-left));border-bottom:1px solid var(--line);background:var(--surface);font-weight:600;font-size:15px}
.mark{width:22px;height:22px;border-radius:5px;background:var(--accent);color:var(--accent-fg);display:grid;place-items:center;font-family:var(--serif);font-style:italic}
header .who{margin-left:auto;font-weight:400;color:var(--muted);font-size:13px}
main{min-height:0;overflow:auto;padding:28px max(16px,env(safe-area-inset-right)) 48px max(16px,env(safe-area-inset-left))}
.letter{max-width:680px;margin:0 auto;background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 2px rgba(20,26,35,.06),0 8px 24px rgba(20,26,35,.06);overflow:hidden}
.head{padding:26px 28px 22px;border-bottom:1px solid var(--line);display:grid;gap:14px}
.eyebrow{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{margin:0;font-family:var(--serif);font-weight:500;font-size:26px;line-height:1.25;text-wrap:balance}h1 em{font-style:italic;color:var(--accent)}
.parties{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:620px){.parties{grid-template-columns:1fr}.head,.body,.foot{padding-left:18px;padding-right:18px}}
.party{display:grid;grid-template-columns:40px 1fr;gap:12px;padding:12px;border:1px solid var(--line);border-radius:6px;background:var(--bg)}
.logo{width:40px;height:40px;border-radius:8px;display:grid;place-items:center;font-weight:600;background:var(--sunk);border:1px solid var(--line)}.logo.agent{background:var(--accent-soft);color:var(--accent);border-color:transparent}
.name{font-weight:600}.sub{color:var(--muted);font-size:12.5px;line-height:1.45;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 8px;border-radius:11px;font-size:12px;font-weight:500;margin-top:8px;margin-right:6px}.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.good{background:var(--good-soft);color:var(--good)}.pill.accent{background:var(--accent-soft);color:var(--accent)}.pill.neutral{background:var(--sunk);color:var(--muted)}.pill.warn{background:var(--warn-soft);color:var(--warn)}.pill.bad{background:var(--bad-soft);color:var(--bad)}
.body{padding:8px 28px 10px}
.summary{display:grid;gap:10px;padding:16px 0 12px}.srow{display:grid;grid-template-columns:20px 1fr;gap:12px;align-items:start;font-size:14.5px}
.tick{width:20px;height:20px;border-radius:4px;display:grid;place-items:center;font-size:11px;font-weight:700;margin-top:2px}.tick.yes{background:var(--good-soft);color:var(--good)}.tick.no{background:var(--bad-soft);color:var(--bad)}
.clauses{border-top:1px solid var(--line)}.clause{display:grid;grid-template-columns:150px 1fr;gap:16px;padding:16px 0;border-bottom:1px solid var(--line)}.clause:last-child{border-bottom:0}@media(max-width:620px){.clause{grid-template-columns:1fr;gap:8px}}
.k{font-weight:600}.k small{display:block;font-weight:400;color:var(--muted);font-size:12px;margin-top:2px}
.caps{display:grid;gap:6px}.cap{display:flex;gap:10px;align-items:flex-start}
.limits{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:620px){.limits{grid-template-columns:1fr}}
.limit{display:grid;gap:5px;padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--bg)}.limit label{font-size:12px;color:var(--muted)}
.limit input,.limit select{width:100%;max-width:160px;height:32px;padding:0 8px;border:1px solid var(--line-strong);border-radius:5px;background:var(--surface);font-family:var(--mono)}
.req{font-size:11.5px;color:var(--faint)}.req.changed{color:var(--warn)}
.chip{display:inline-flex;height:26px;padding:0 10px;border-radius:13px;border:1px solid var(--line);background:var(--bg);align-items:center;font-size:12.5px;margin:0 6px 6px 0}
.foot{padding:18px 28px 22px;border-top:1px solid var(--line);background:var(--bg);display:grid;gap:14px}
.stamp{display:flex;gap:8px;font-size:12.5px;color:var(--muted);align-items:center}.seal{flex:none;width:28px;height:28px;border-radius:50%;border:1.5px dashed var(--line-strong);display:grid;place-items:center;font-family:var(--serif);font-style:italic;color:var(--faint)}
.actions{display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:38px;padding:0 16px;border-radius:6px;border:1px solid var(--line-strong);background:var(--surface);font-weight:500;white-space:nowrap}.btn:hover{background:var(--sunk)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}.btn.ghost{border-color:transparent;background:none;color:var(--accent)}.btn.small{height:30px;padding:0 10px;font-size:13px}.btn:disabled{opacity:.5;cursor:default}
.step{padding:18px 28px;display:grid;gap:12px}.step h2{margin:0;font-size:16px}.step p{margin:0;color:var(--muted)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row input[type=text]{height:38px;padding:0 10px;border:1px solid var(--line-strong);border-radius:6px;background:var(--surface);min-width:220px}
.mono{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
.err{color:var(--bad);font-size:13px}
.kv{display:grid;grid-template-columns:140px 1fr;gap:8px 16px;font-size:13.5px}.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
pre{margin:0;font-family:var(--mono);font-size:11.5px;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:12px;max-height:220px;overflow:auto;color:var(--muted)}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="app">
  <header><span class="mark">w</span>Warrant <span class="who" id="who"></span></header>
  <main>
    <div class="letter" id="letter">
      <div class="head" id="head"><div class="eyebrow">Mandate request</div><h1 id="title">Loading…</h1><div class="parties" id="parties"></div></div>
      <div id="stage"></div>
    </div>
  </main>
</div>
<script>
(() => {
  // ---- helpers --------------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (minor, ccy) => (ccy ? new Intl.NumberFormat(undefined, { style: "currency", currency: ccy }).format(minor / 100) : String(minor));
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
  const BASE = location.pathname.replace(/\\/consent\\/.*$/, "");
  const REQ = location.pathname.split("/consent/")[1]?.split(/[/?#]/)[0];
  const AUTH_KEY = "warrant.assertion";
  let assertion = sessionStorage.getItem(AUTH_KEY) || "";
  const api = async (method, path, body, auth = true) => {
    const h = { "content-type": "application/json" };
    if (auth && assertion) h.authorization = "Warrant-Principal " + assertion;
    const r = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.message || j.error || r.status), { code: j.error, status: r.status });
    return j;
  };
  const act = (type) => type.split(":").pop().replace(/_/g, " ");
  let req, me, disco;

  // ---- render ---------------------------------------------------------------
  function renderHead() {
    const d = req.draft, agentName = req.agent.operator || req.agent.did;
    $("title").innerHTML = "<em>" + esc(agentName) + "</em> is asking for authority to act on your behalf." + (d.purpose ? " <span style='color:var(--muted);font-size:17px;display:block;margin-top:6px'>" + esc(d.purpose) + "</span>" : "");
    $("parties").innerHTML =
      '<div class="party"><div class="logo agent">' + esc(agentName[0].toUpperCase()) + '</div><div><div class="name">' + esc(agentName) + '</div><div class="sub mono">' + esc(req.agent.did) + "</div><div class='sub'>" + (d.agent?.runtime ? "Runtime attested: " + esc(d.agent.runtime) : "No runtime attestation") + "</div>" +
      '<span class="pill good">Key registered</span><span class="pill neutral">' + req.agent.mandates_issued + " mandate" + (req.agent.mandates_issued === 1 ? "" : "s") + " issued</span></div></div>" +
      '<div class="party"><div class="logo">' + (me ? esc(me.sub.replace(/^pw_demo_/, "")[0].toUpperCase()) : "?") + '</div><div><div class="name">You</div><div class="sub">' + (me ? "Signed in through <b>" + esc(me.root) + "</b> · assurance " + esc(me.level) + "<br>Signing key: " + (me.passkeys.length ? "passkey on this device" : "no passkey yet") : "Not signed in") + '</div><span class="pill accent">Principal</span></div></div>';
    $("who").textContent = me ? me.sub.replace(/^pw_demo_/, "") + " · " + me.root : "";
  }
  function stage(html) { $("stage").innerHTML = html; }

  function stageSignIn(err) {
    stage('<div class="step"><h2>Sign in to review this request</h2><p>Your identity root vouches for who you are; Warrant never sees your documents. This instance accepts the development root <b>demo-wallet</b>.</p>' +
      '<div class="row"><input type="text" id="demoName" placeholder="Your name (demo wallet)" autocomplete="off"><button class="btn primary" id="demoBtn">Sign in with demo wallet</button></div>' + (err ? '<div class="err">' + esc(err) + "</div>" : "") + "</div>");
    $("demoBtn").onclick = async () => {
      try { const r = await api("POST", "/dev/assertion", { sub: $("demoName").value }, false); assertion = r.assertion; sessionStorage.setItem(AUTH_KEY, assertion); await boot(); }
      catch (e) { stageSignIn(e.message); }
    };
  }

  function stagePasskey(err) {
    stage('<div class="step"><h2>Create a passkey to sign mandates</h2><p>Every mandate you approve, and every confirmation you give, is signed by a passkey on this device. The issuer only ever sees the public key. Counterparties verify your signature directly; the issuer cannot forge it.</p>' +
      '<div class="row"><button class="btn primary" id="pkBtn">Create passkey</button><button class="btn ghost small" id="signOut">Not you? Sign out</button></div>' + (err ? '<div class="err">' + esc(err) + "</div>" : "") + "</div>");
    $("signOut").onclick = signOut;
    $("pkBtn").onclick = async () => {
      try {
        const { publicKey } = await api("POST", "/passkeys/options");
        publicKey.challenge = unb64u(publicKey.challenge); publicKey.user.id = unb64u(publicKey.user.id);
        publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((c) => ({ ...c, id: unb64u(c.id) }));
        const cred = await navigator.credentials.create({ publicKey });
        const resp = cred.response;
        const spki = resp.getPublicKey && resp.getPublicKey();
        if (!spki) throw new Error("This browser does not expose the credential public key (getPublicKey). Try a current Chrome, Safari or Firefox.");
        await api("POST", "/passkeys", { credential_id: cred.id, client_data_json: b64u(resp.clientDataJSON), public_key_spki: b64u(spki), public_key_alg: resp.getPublicKeyAlgorithm(), label: navigator.platform || null });
        await boot();
      } catch (e) { stagePasskey(e.message); }
    };
  }

  function stageTerms(err) {
    const d = req.draft, L = d.limits || {}, ccy = L.ccy, hasSpend = L.total !== undefined;
    const days = Math.max(1, Math.round(((d.exp ?? 0) - (d.nbf ?? Math.floor(Date.now() / 1000))) / 86400)) || 7;
    stage(
      '<div class="body">' +
      '<div class="summary" id="summary"></div>' +
      '<div><button class="btn ghost small" id="toggle" aria-expanded="false" style="margin-left:-10px">Adjust limits and show full terms ↓</button></div>' +
      '<div class="clauses hidden" id="clauses">' +
        '<div class="clause"><div class="k">May<small>Without asking you again</small></div><div class="caps">' + d.scope.may.map((a) => '<div class="cap"><span class="tick yes">✓</span><span>' + esc(act(a)) + '</span></div>').join("") + "</div></div>" +
        (d.scope.may_not?.length ? '<div class="clause"><div class="k">May not<small>Refused at the counterparty even if asked</small></div><div class="caps">' + d.scope.may_not.map((a) => '<div class="cap" style="color:var(--muted)"><span class="tick no">✕</span><span>' + esc(act(a)) + '</span></div>').join("") + "</div></div>" : "") +
        (hasSpend ? '<div class="clause"><div class="k">Spend<small>You can lower what it asked for</small></div><div class="limits">' +
          '<div class="limit"><label for="total">Total ceiling (' + esc(ccy) + ')</label><input type="number" id="total" min="0" step="1" value="' + L.total / 100 + '"><span class="req" id="totalReq"></span></div>' +
          '<div class="limit"><label for="per_txn">Per transaction (' + esc(ccy) + ')</label><input type="number" id="per_txn" min="0" step="1" value="' + L.per_txn / 100 + '"><span class="req" id="per_txnReq"></span></div>' +
          (L.confirm_over !== undefined ? '<div class="limit"><label for="confirm_over">Ask me first above (' + esc(ccy) + ')</label><input type="number" id="confirm_over" min="0" step="1" value="' + L.confirm_over / 100 + '"><span class="req" id="confirm_overReq"></span></div>' : "") +
          '<div class="limit"><label for="days">Valid for</label><select id="days"><option value="1">24 hours</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option></select><span class="req" id="daysReq"></span></div>' +
        "</div></div>" : "") +
        '<div class="clause"><div class="k">Counterparties<small>Who will honour this mandate</small></div><div>' + d.scope.counterparties.map((c) => '<span class="chip">' + esc(c) + "</span>").join("") + "</div></div>" +
        '<div class="clause"><div class="k">Sub-agents<small>Hand-offs can only be narrower</small></div><div>' + (d.delegation.max_depth > 0 ? "May hand off to sub-agents, " + d.delegation.max_depth + " level" + (d.delegation.max_depth > 1 ? "s" : "") + " deep, each bound by these limits." : "May not hand off to other agents.") + "</div></div>" +
      "</div></div>" +
      '<div class="foot"><div class="stamp"><span class="seal">w</span><span>Signed by your passkey · every action is signed by the acting agent and logged · revoke at any time, cascading to sub-agents</span></div>' +
      (err ? '<div class="err">' + esc(err) + "</div>" : "") +
      '<div class="actions"><button class="btn" id="decline">Decline</button><button class="btn primary" id="approve">Approve with passkey</button></div></div>'
    );
    const sel = $("days"); if (sel) sel.value = String([1, 7, 30, 90].includes(days) ? days : 7);
    const read = () => {
      const g = (id) => { const el = $(id); return el ? Math.round(Number(el.value) * 100) : undefined; };
      return { total: g("total"), per_txn: g("per_txn"), confirm_over: g("confirm_over"), days: sel ? Number(sel.value) : days };
    };
    const sync = () => {
      const v = read();
      for (const k of ["total", "per_txn", "confirm_over"]) { const el = $(k + "Req"); if (!el || L[k] === undefined) continue; const changed = v[k] !== L[k]; el.textContent = "Requested " + fmt(L[k], ccy) + (changed ? " · you set " + fmt(v[k], ccy) : ""); el.classList.toggle("changed", changed); if (v[k] > L[k]) { el.textContent = "Cannot exceed the " + fmt(L[k], ccy) + " requested"; } }
      if ($("daysReq")) $("daysReq").textContent = "Agent asked for " + days + " day" + (days === 1 ? "" : "s");
      $("summary").innerHTML =
        '<div class="srow"><span class="tick yes">✓</span><span>' + esc(act(d.scope.may[0])) + (d.scope.may.length > 1 ? " and " + (d.scope.may.length - 1) + " other action" + (d.scope.may.length > 2 ? "s" : "") : "") + " on your behalf.</span></div>" +
        (hasSpend ? '<div class="srow"><span class="tick yes">$</span><span>Spend up to <b>' + fmt(v.total, ccy) + "</b> in total, <b>" + fmt(v.per_txn, ccy) + "</b> per transaction." + (v.confirm_over !== undefined ? " Asks you first above <b>" + fmt(v.confirm_over, ccy) + "</b>" + (L.confirm_on?.length ? " and before " + L.confirm_on.map(act).join(", ") : "") + "." : "") + "</span></div>" : '<div class="srow"><span class="tick no">$</span><span>No spending authority.</span></div>') +
        (d.scope.may_not?.length ? '<div class="srow"><span class="tick no">✕</span><span>Cannot ' + d.scope.may_not.map(act).join(", ") + ".</span></div>" : "") +
        '<div class="srow"><span class="tick yes">◷</span><span>Valid for <b>' + v.days + " day" + (v.days === 1 ? "" : "s") + "</b>, with " + d.scope.counterparties.length + " counterpart" + (d.scope.counterparties.length === 1 ? "y" : "ies") + ".</span></div>";
    };
    sync();
    for (const id of ["total", "per_txn", "confirm_over", "days"]) { const el = $(id); if (el) el.addEventListener("input", sync); }
    $("toggle").onclick = () => { const c = $("clauses"); const open = c.classList.toggle("hidden"); $("toggle").textContent = open ? "Adjust limits and show full terms ↓" : "Hide full terms ↑"; $("toggle").setAttribute("aria-expanded", String(!open)); };
    $("decline").onclick = async () => { try { await api("POST", "/requests/" + REQ + "/decline", {}); stageDone("declined"); } catch (e) { stageTerms(e.message); } };
    $("approve").onclick = async () => {
      $("approve").disabled = true; $("approve").textContent = "Waiting for your passkey…";
      try {
        const v = read(), key = me.passkeys[0].kid, t = Math.floor(Date.now() / 1000);
        const limits = {}; for (const k of ["total", "per_txn", "confirm_over"]) if (v[k] !== undefined && L[k] !== undefined) limits[k] = Math.min(v[k], L[k]);
        const prep = await api("POST", "/requests/" + REQ + "/prepare", { key, limits, exp: t + v.days * 86400 });
        const cred = await navigator.credentials.get({ publicKey: { challenge: unb64u(prep.challenge), rpId: prep.rp_id, allowCredentials: prep.allow_credentials.map((c) => ({ ...c, id: unb64u(c.id) })), userVerification: "preferred", timeout: 120000 } });
        const r = cred.response;
        const out = await api("POST", "/requests/" + REQ + "/approve", { sig: { alg: "ES256", value: b64u(r.signature), webauthn: { authenticatorData: b64u(r.authenticatorData), clientDataJSON: b64u(r.clientDataJSON) } } });
        stageDone("approved", out);
      } catch (e) { stageTerms(e.name === "NotAllowedError" ? "Passkey prompt was cancelled or timed out." : e.message); }
    };
  }

  function stageDone(state, out) {
    if (state === "approved") {
      const m = out.mandate;
      stage('<div class="step"><div class="row"><span class="tick yes" style="width:36px;height:36px;border-radius:50%;font-size:16px">✓</span><h2>Mandate issued</h2></div>' +
        '<p>' + esc(req.agent.operator || req.agent.did) + ' now holds a mandate signed by your passkey and co-signed by the issuer. It collects the token itself; you can close this page.</p>' +
        '<dl class="kv"><dt>Mandate</dt><dd class="mono">' + esc(m.id) + "</dd><dt>Spend</dt><dd>" + (m.limits.total !== undefined ? fmt(m.limits.total, m.limits.ccy) + " total · " + fmt(m.limits.per_txn, m.limits.ccy) + " per transaction" : "none") + "</dd><dt>Expires</dt><dd>" + new Date(m.exp * 1000).toLocaleString() + "</dd><dt>Signed by</dt><dd>" + m.sig.map((s) => s.by + " (" + s.alg + (s.webauthn ? ", passkey" : "") + ")").join(", ") + "</dd></dl>" +
        '<details><summary class="eyebrow" style="cursor:pointer">What the agent carries</summary><pre>' + esc(JSON.stringify(m, null, 2)) + "</pre></details></div>");
    } else {
      const msg = { declined: "You declined. Nothing was signed and the agent holds no authority.", approved_before: "This request was already approved.", expired: "This request expired before it was answered.", declined_before: "This request was already declined." }[state] || state;
      stage('<div class="step"><h2>' + esc(state === "declined" ? "Request declined" : "Request closed") + "</h2><p>" + esc(msg) + "</p></div>");
    }
  }

  async function signOut() { sessionStorage.removeItem(AUTH_KEY); assertion = ""; me = null; await boot(); }

  // ---- boot -----------------------------------------------------------------
  async function boot() {
    try {
      if (!REQ) { $("title").textContent = "No request in the URL."; return; }
      [req, disco] = await Promise.all([api("GET", "/requests/" + REQ, undefined, false), api("GET", "/.well-known/warrant.json", undefined, false)]);
      me = null;
      if (assertion) { try { me = await api("GET", "/me"); } catch { assertion = ""; sessionStorage.removeItem(AUTH_KEY); } }
      renderHead();
      if (req.state === "approved") return stageDone("approved_before");
      if (req.state === "declined") return stageDone("declined_before");
      if (new Date(req.expires_at).getTime() < Date.now() || req.state === "expired") return stageDone("expired");
      if (!me) return stageSignIn();
      if (!window.PublicKeyCredential) return stage('<div class="step"><h2>Passkeys are not available in this browser</h2><p>Open this link in a browser that supports WebAuthn.</p></div>');
      if (!me.passkeys.length) return stagePasskey();
      stageTerms();
    } catch (e) {
      $("title").textContent = e.status === 404 ? "This request does not exist." : "Could not load the request.";
      stage('<div class="step"><p class="err">' + esc(e.message) + "</p></div>");
    }
  }
  boot();
})();
</script>
</body>
</html>`;
