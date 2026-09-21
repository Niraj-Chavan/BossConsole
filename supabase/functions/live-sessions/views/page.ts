/**
 * The single page this function serves.
 *
 * One document, three states driven by the inline script: sign-in form (no
 * token), "opening" (exactly one live session), list (several or none). The
 * script is nonce-stamped; there is no external asset and no third-party
 * script, which is what lets the CSP stay `default-src 'none'`.
 *
 * Palette mirrors BOSS Blueprint (organisation/views/layout.ts is the source
 * of the values). Wrapped in Cloudflare's `<!--email_off-->` because
 * api.risaboss.com sits behind Cloudflare whose Email Obfuscation would inject
 * a script the CSP blocks.
 *
 * Token handling, in order, and why:
 *   1. GoTrue's implicit-flow redirect lands on `/auth#access_token=…`. The
 *      fragment never reaches this server, so the page reads it itself.
 *   2. It is copied into sessionStorage (tab-scoped, gone on close) and the
 *      fragment is stripped with history.replaceState so the bearer leaves the
 *      address bar and history.
 *   3. Every data call is same-origin (`connect-src 'self'`) with the token as a
 *      Bearer header; the function forwards it to PostgREST, which validates the
 *      JWT and applies RLS.
 */

import { esc, jsonForScript } from "../utils/html.ts"

export interface PageModel {
  basePath: string
  liveWindowSeconds: number
  /** Non-fatal notice to show above the form (e.g. "link expired"). */
  notice?: string
}

const STYLES = `
  :root {
    --ink: #05070B; --raised: #0E141E; --line: #1C2432; --line-strong: #5A6474;
    --text: #E6EBF2; --text-2: #9AA6B8; --signal: #0F5BFF; --signal-text: #88A9FF;
    --ok: #3DDC97; --warn: #F2A93B; --danger: #FF5C5C; --wash: rgba(15, 91, 255, 0.12);
  }
  @media (prefers-color-scheme: light) {
    :root {
      --ink: #F4F6FA; --raised: #FFFFFF; --line: #DCE2EB; --line-strong: #868E9B;
      --text: #0B1220; --text-2: #4B5565; --signal: #0F5BFF; --signal-text: #0B45C2;
      --wash: rgba(15, 91, 255, 0.08);
    }
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background-color: var(--ink); color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
  main { max-width: 640px; margin: 0 auto; padding: 32px 16px 48px; }
  header { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 20px; }
  h1 { font-size: 20px; margin: 0; letter-spacing: -0.2px; }
  .sub { color: var(--text-2); font-size: 13px; }
  .card { background-color: var(--raised); border: 1px solid var(--line); border-radius: 10px; padding: 20px; }
  .card + .card { margin-top: 12px; }
  label { display: block; font-size: 13px; color: var(--text-2); margin-bottom: 6px; }
  input[type=email] { width: 100%; font: inherit; color: var(--text); background-color: var(--ink);
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 10px 12px; }
  input[type=email]:focus-visible { outline: 2px solid var(--signal); outline-offset: 1px; }
  button, a.btn { font: inherit; font-weight: 600; border-radius: 7px; padding: 10px 16px; cursor: pointer;
    border: 1px solid var(--signal); background-color: var(--signal); color: #FFFFFF; text-decoration: none; display: inline-block; }
  button.secondary, a.btn.secondary { background-color: transparent; color: var(--text-2); border-color: var(--line-strong); }
  button:disabled { opacity: 0.6; cursor: default; }
  .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
  .hidden { display: none !important; }
  .notice { border-left: 3px solid var(--warn); padding: 8px 12px; color: var(--text-2); margin-bottom: 14px; background-color: var(--wash); border-radius: 0 7px 7px 0; }
  .notice.error { border-left-color: var(--danger); }
  .notice.ok { border-left-color: var(--ok); }
  ul.sessions { list-style: none; margin: 0; padding: 0; }
  ul.sessions li { display: flex; justify-content: space-between; align-items: center; gap: 12px;
    padding: 14px 0; border-top: 1px solid var(--line); }
  ul.sessions li:first-child { border-top: 0; padding-top: 0; }
  .name { font-weight: 600; }
  .meta { color: var(--text-2); font-size: 13px; }
  .pill { display: inline-block; font-size: 11px; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--line-strong); color: var(--text-2); margin-left: 6px; vertical-align: middle; }
  .pill.ok { border-color: var(--ok); color: var(--ok); }
  .pill.warn { border-color: var(--warn); color: var(--warn); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--signal-text); }
  footer { margin-top: 28px; color: var(--text-2); font-size: 12px; text-align: center; }
  a { color: var(--signal-text); }
`

/**
 * Browser script. Plain ES2017, no build step. Reads config from the
 * `#cfg` JSON block so the template never interpolates into JS directly.
 */
const SCRIPT = `
(function () {
  "use strict";
  var cfg = JSON.parse(document.getElementById("cfg").textContent);
  var base = cfg.basePath;
  var $ = function (id) { return document.getElementById(id); };
  var TOKEN_KEY = "boss.live.access", REFRESH_KEY = "boss.live.refresh";
  var pollTimer = null, openTimer = null, cancelledAutoOpen = false;

  function show(id) {
    ["signin", "sent", "loading", "list", "opening"].forEach(function (s) {
      $(s).classList.toggle("hidden", s !== id);
    });
  }
  function notice(text, kind) {
    var n = $("notice");
    n.textContent = text || "";
    n.className = "notice" + (kind ? " " + kind : "");
    n.classList.toggle("hidden", !text);
  }
  function store(k, v) { try { if (v) sessionStorage.setItem(k, v); else sessionStorage.removeItem(k); } catch (_) {} }
  function load(k) { try { return sessionStorage.getItem(k); } catch (_) { return null; } }

  // 1. Harvest GoTrue's implicit-flow fragment, then strip it from the URL.
  function harvestFragment() {
    var h = (location.hash || "").replace(/^#/, "");
    if (!h) return;
    var p = new URLSearchParams(h);
    if (p.get("access_token")) {
      store(TOKEN_KEY, p.get("access_token"));
      store(REFRESH_KEY, p.get("refresh_token") || "");
    } else if (p.get("error_description") || p.get("error")) {
      notice(p.get("error_description") || p.get("error"), "error");
    }
    history.replaceState(null, "", location.pathname + location.search);
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function ago(iso) {
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (s < 60) return s + "s ago";
    var m = Math.round(s / 60); if (m < 60) return m + " min ago";
    var h = Math.round(m / 60); if (h < 48) return h + " h ago";
    return Math.round(h / 24) + " d ago";
  }
  function safeHttpUrl(u) {
    try { var x = new URL(u); return (x.protocol === "https:" || x.protocol === "http:") ? x.href : null; }
    catch (_) { return null; }
  }

  async function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
    var token = load(TOKEN_KEY);
    if (token && opts.auth !== false) headers["Authorization"] = "Bearer " + token;
    if (opts.body) headers["Content-Type"] = "application/json";
    return fetch(base + path, { method: opts.method || "GET", headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: "omit" });
  }

  async function refreshOnce() {
    var rt = load(REFRESH_KEY);
    if (!rt) return false;
    var r = await api("/api/refresh", { method: "POST", body: { refresh_token: rt }, auth: false });
    if (!r.ok) return false;
    var j = await r.json();
    if (!j.access_token) return false;
    store(TOKEN_KEY, j.access_token); store(REFRESH_KEY, j.refresh_token || rt);
    return true;
  }

  function signOut(msg) {
    store(TOKEN_KEY, null); store(REFRESH_KEY, null);
    stopPolling();
    show("signin");
    if (msg) notice(msg, "error");
  }

  async function loadSessions(isPoll) {
    if (!isPoll) show("loading");
    var r = await api("/api/sessions");
    if (r.status === 401) {
      if (await refreshOnce()) r = await api("/api/sessions");
      if (r.status === 401) { signOut("Your sign-in expired. Enter your email to get a new link."); return; }
    }
    if (!r.ok) { notice("Could not load sessions (HTTP " + r.status + "). Retrying…", "error"); show("list"); return; }
    var data = await r.json();
    render(data.sessions || [], data.email || "");
  }

  function render(sessions, email) {
    $("who").textContent = email || "";
    var ul = $("sessions");
    ul.innerHTML = "";
    if (sessions.length === 1 && !cancelledAutoOpen && !openTimer) {
      var s = sessions[0], url = safeHttpUrl(s.control_url);
      if (url) {
        $("opening-device").textContent = s.device_name + (s.session_name ? " · " + s.session_name : "");
        $("opening-link").setAttribute("href", url);
        show("opening");
        openTimer = setTimeout(function () { openTimer = null; location.assign(url); }, 1500);
        return;
      }
    }
    if (sessions.length === 0) {
      ul.innerHTML = '<li><div><div class="name">No live sessions</div><div class="meta">Share a tab from a signed-in BossTerm and it will appear here.</div></div></li>';
    }
    sessions.forEach(function (s) {
      var url = safeHttpUrl(s.control_url); if (!url) return;
      var li = document.createElement("li");
      li.innerHTML =
        '<div><div class="name">' + esc(s.device_name) +
        (s.session_name && s.session_name !== s.device_name ? ' <span class="meta">' + esc(s.session_name) + "</span>" : "") +
        (s.secure ? '<span class="pill ok">E2E ' + esc(s.e2e_code || "") + "</span>" : '<span class="pill warn">not encrypted</span>') +
        "</div>" +
        '<div class="meta">' + esc(s.scope === "WINDOW" ? "Whole window" : "One tab") +
        " · started " + esc(ago(s.started_at)) + " · seen " + esc(ago(s.last_seen_at)) + "</div></div>" +
        '<a class="btn" rel="noreferrer">Open</a>';
      li.querySelector("a").setAttribute("href", url);
      ul.appendChild(li);
    });
    show("list");
    startPolling();
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(function () {
      if (document.visibilityState === "visible") loadSessions(true).catch(function () {});
    }, 10000);
  }
  function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  // Wiring
  $("signin-form").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var email = $("email").value.trim();
    if (!email) return;
    $("send").disabled = true;
    try {
      var r = await api("/api/otp", { method: "POST", body: { email: email }, auth: false });
      if (r.status === 429) { notice("Too many attempts. Try again in a few minutes.", "error"); return; }
      if (!r.ok) { notice("Could not send the link (HTTP " + r.status + ").", "error"); return; }
      $("sent-email").textContent = email;
      notice("");
      show("sent");
    } finally { $("send").disabled = false; }
  });
  $("sent-back").addEventListener("click", function () { show("signin"); });
  $("refresh").addEventListener("click", function () { loadSessions(false).catch(function () {}); });
  $("signout").addEventListener("click", function () { signOut(); });
  $("opening-cancel").addEventListener("click", function (ev) {
    ev.preventDefault();
    cancelledAutoOpen = true;
    if (openTimer) { clearTimeout(openTimer); openTimer = null; }
    loadSessions(false).catch(function () {});
  });
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible" && load(TOKEN_KEY) && !$("list").classList.contains("hidden")) {
      loadSessions(true).catch(function () {});
    }
  });

  harvestFragment();
  if (load(TOKEN_KEY)) loadSessions(false).catch(function () { notice("Network error.", "error"); show("list"); });
  else show("signin");
})();
`

export function livePage(model: PageModel, nonce: string): string {
  const cfg = { basePath: model.basePath, liveWindowSeconds: model.liveWindowSeconds }
  const notice = model.notice ? `<div id="notice" class="notice">${esc(model.notice)}</div>` : `<div id="notice" class="notice hidden"></div>`
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>BossTerm Live Sessions</title>
<style nonce="${esc(nonce)}">${STYLES}</style>
</head>
<body>
<!--email_off-->
<main>
  <header>
    <div><h1>BossTerm live sessions</h1><div class="sub">Terminal sessions shared from BossTerm, signed in with your BOSS account</div></div>
    <div class="sub" id="who"></div>
  </header>
  ${notice}

  <section id="signin" class="card hidden">
    <form id="signin-form" autocomplete="on">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" required autocomplete="email" inputmode="email" placeholder="you@company.com">
      <div class="row">
        <button id="send" type="submit">Email me a sign-in link</button>
        <span class="sub">Uses the same account you signed into BossTerm with.</span>
      </div>
    </form>
  </section>

  <section id="sent" class="card hidden">
    <div class="name">Check your email</div>
    <p class="sub">We sent a sign-in link to <strong id="sent-email"></strong>. Open it on this device and your live sessions will appear here.</p>
    <div class="row"><button id="sent-back" class="secondary" type="button">Use a different email</button></div>
  </section>

  <section id="loading" class="card hidden"><div class="sub">Loading your sessions…</div></section>

  <section id="opening" class="card hidden">
    <div class="name">Opening <span id="opening-device"></span>…</div>
    <p class="sub">Your only live session. If nothing happens, use the button.</p>
    <div class="row">
      <a id="opening-link" class="btn" rel="noreferrer" href="#">Open session</a>
      <a id="opening-cancel" class="btn secondary" href="#">Show the list instead</a>
    </div>
  </section>

  <section id="list" class="card hidden">
    <ul id="sessions" class="sessions"></ul>
    <div class="row">
      <button id="refresh" class="secondary" type="button">Refresh</button>
      <button id="signout" class="secondary" type="button">Sign out</button>
      <span class="sub">Sessions disappear about ${esc(String(model.liveWindowSeconds))} seconds after BossTerm stops sharing or closes.</span>
    </div>
  </section>

  <footer>Only you can see this list. Links open the live share-viewer end to end encrypted when the badge shows <code>E2E</code>.</footer>
</main>
<!--/email_off-->
<script id="cfg" type="application/json">${jsonForScript(cfg)}</script>
<script nonce="${esc(nonce)}">${SCRIPT}</script>
</body>
</html>`
}
