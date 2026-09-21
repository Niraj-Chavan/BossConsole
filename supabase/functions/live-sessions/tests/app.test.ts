/**
 * Route behaviour, driven through app.request() with `deps.fetch` stubbed so
 * no network is touched.
 *
 * Run: cd supabase/functions/live-sessions && deno test --allow-all
 */

import { assert, assertEquals, assertStringIncludes } from "@std/assert"
import { app, bearerToken, deps, emailFromJwt, isSessionRow } from "../app.ts"
import { resetRateLimits } from "../utils/rate-limit.ts"

const BASE = "/live-sessions"

type Call = { url: string; init?: RequestInit }

function withEnv(fn: () => Promise<void>): () => Promise<void> {
  return async () => {
    Deno.env.set("SUPABASE_URL", "https://stack.example")
    Deno.env.set("SUPABASE_ANON_KEY", "anon-key")
    Deno.env.set("LIVE_SESSIONS_PUBLIC_BASE_URL", "https://api.risaboss.com")
    resetRateLimits()
    try {
      await fn()
    } finally {
      Deno.env.delete("LIVE_SESSIONS_PUBLIC_BASE_URL")
    }
  }
}

function stubFetch(handler: (call: Call) => Response): { calls: Call[]; restore: () => void } {
  const calls: Call[] = []
  const original = deps.fetch
  deps.fetch = (url: string, init?: RequestInit) => {
    const call = { url, init }
    calls.push(call)
    return Promise.resolve(handler(call))
  }
  return { calls, restore: () => (deps.fetch = original) }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
}

/** A syntactically valid unsigned JWT carrying an email claim (display only). */
function fakeJwt(email: string): string {
  const b64 = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  return `${b64(JSON.stringify({ alg: "HS256" }))}.${b64(JSON.stringify({ sub: "u1", email }))}.sig-sig-sig-sig-sig`
}

const ROW = {
  share_id: "0123456789abcdef",
  device_name: "shivang_mac",
  session_name: "deploy",
  scope: "TAB",
  view_url: "https://x.trycloudflare.com/?t=view#k=abc",
  control_url: "https://x.trycloudflare.com/?t=acct#k=abc",
  secure: true,
  e2e_code: "deadbeef",
  app_version: "1.2.140",
  started_at: "2026-09-20T10:00:00Z",
  last_seen_at: "2026-09-20T10:05:00Z",
}

// ---- page ----

Deno.test("GET / renders the page with a nonce'd script and CSP, no-store", withEnv(async () => {
  const res = await app.request(`${BASE}/`)
  assertEquals(res.status, 200)
  const csp = res.headers.get("content-security-policy") ?? ""
  const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1]
  assert(nonce, "CSP must carry a script nonce")
  const html = await res.text()
  assertStringIncludes(html, `<script nonce="${nonce}">`)
  assertStringIncludes(html, `<style nonce="${nonce}">`)
  assertStringIncludes(html, 'id="signin-form"')
  assertStringIncludes(html, 'id="opening"') // single-session auto-open state exists
  assertStringIncludes(html, '"basePath":"/functions/v1/live-sessions"')
  assertEquals(res.headers.get("cache-control"), "no-store, max-age=0")
  assertEquals(res.headers.get("x-frame-options"), "DENY")
  assert(!html.includes("unsafe-inline"))
}))

Deno.test("GET /auth serves the same page (magic-link landing)", withEnv(async () => {
  const res = await app.request(`${BASE}/auth`)
  assertEquals(res.status, 200)
  assertStringIncludes(await res.text(), "access_token") // the fragment harvester is present
}))

// ---- otp ----

Deno.test("POST /api/otp sends a magic link with redirect_to=<base>/auth and hides account existence", withEnv(async () => {
  const stub = stubFetch(() => json({ msg: "user not found" }, 400)) // GoTrue 4xx
  try {
    const res = await app.request(`${BASE}/api/otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "Someone@Example.com" }),
    })
    assertEquals(res.status, 200)
    assertEquals(await res.json(), { sent: true })
    assertEquals(stub.calls.length, 1)
    const url = new URL(stub.calls[0].url)
    assertEquals(url.pathname, "/auth/v1/otp")
    assertEquals(url.searchParams.get("redirect_to"), "https://api.risaboss.com/functions/v1/live-sessions/auth")
    assertEquals(JSON.parse(String(stub.calls[0].init?.body)).email, "someone@example.com")
  } finally {
    stub.restore()
  }
}))

Deno.test("POST /api/otp rejects malformed email without calling GoTrue", withEnv(async () => {
  const stub = stubFetch(() => json({}))
  try {
    const res = await app.request(`${BASE}/api/otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nope" }),
    })
    assertEquals(res.status, 400)
    assertEquals(stub.calls.length, 0)
  } finally {
    stub.restore()
  }
}))

Deno.test("POST /api/otp rate-limits the 6th attempt from one client", withEnv(async () => {
  const stub = stubFetch(() => json({}))
  try {
    const headers = { "Content-Type": "application/json", "x-forwarded-for": "203.0.113.9" }
    for (let i = 0; i < 5; i++) {
      const ok = await app.request(`${BASE}/api/otp`, { method: "POST", headers, body: JSON.stringify({ email: "a@b.co" }) })
      assertEquals(ok.status, 200)
    }
    const blocked = await app.request(`${BASE}/api/otp`, { method: "POST", headers, body: JSON.stringify({ email: "a@b.co" }) })
    assertEquals(blocked.status, 429)
    assertEquals(stub.calls.length, 5)
  } finally {
    stub.restore()
  }
}))

// ---- sessions ----

Deno.test("GET /api/sessions without a Bearer is 401 and never touches PostgREST", withEnv(async () => {
  const stub = stubFetch(() => json([ROW]))
  try {
    const res = await app.request(`${BASE}/api/sessions`)
    assertEquals(res.status, 401)
    assertEquals(stub.calls.length, 0)
  } finally {
    stub.restore()
  }
}))

Deno.test("GET /api/sessions forwards the user's JWT, applies the freshness filter, returns rows + email", withEnv(async () => {
  const stub = stubFetch(() => json([ROW, { junk: true }]))
  try {
    const jwt = fakeJwt("me@risalabs.ai")
    const res = await app.request(`${BASE}/api/sessions`, { headers: { Authorization: `Bearer ${jwt}` } })
    assertEquals(res.status, 200)
    const body = await res.json()
    assertEquals(body.sessions.length, 1) // shape guard drops the junk row
    assertEquals(body.sessions[0].control_url, ROW.control_url)
    assertEquals(body.email, "me@risalabs.ai")

    const call = stub.calls[0]
    const url = new URL(call.url)
    assertEquals(url.pathname, "/rest/v1/terminal_sessions")
    assert(url.searchParams.get("last_seen_at")?.startsWith("gt."), "must filter on freshness server-side")
    assertEquals(url.searchParams.get("order"), "last_seen_at.desc")
    const headers = call.init?.headers as Record<string, string>
    assertEquals(headers.Authorization, `Bearer ${jwt}`) // the USER's token, not a service key
    assertEquals(headers.apikey, "anon-key")
  } finally {
    stub.restore()
  }
}))

Deno.test("GET /api/sessions maps a PostgREST 401 (bad/expired JWT) to 401", withEnv(async () => {
  const stub = stubFetch(() => json({ message: "JWT expired" }, 401))
  try {
    const res = await app.request(`${BASE}/api/sessions`, { headers: { Authorization: `Bearer ${fakeJwt("x@y.z")}` } })
    assertEquals(res.status, 401)
  } finally {
    stub.restore()
  }
}))

// ---- refresh ----

Deno.test("POST /api/refresh proxies GoTrue and returns only the two tokens", withEnv(async () => {
  const stub = stubFetch(() => json({ access_token: "A", refresh_token: "R", user: { email: "leak@no" } }))
  try {
    const res = await app.request(`${BASE}/api/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: "old" }),
    })
    assertEquals(res.status, 200)
    assertEquals(await res.json(), { access_token: "A", refresh_token: "R" })
    assertStringIncludes(stub.calls[0].url, "/auth/v1/token?grant_type=refresh_token")
  } finally {
    stub.restore()
  }
}))

// ---- helpers ----

Deno.test("bearerToken accepts a JWT-shaped token and rejects garbage", () => {
  assertEquals(bearerToken(`Bearer ${fakeJwt("a@b.c")}`), fakeJwt("a@b.c"))
  assertEquals(bearerToken("Bearer short"), null)
  assertEquals(bearerToken("Basic abc"), null)
  assertEquals(bearerToken(undefined), null)
})

Deno.test("emailFromJwt reads the claim and tolerates junk", () => {
  assertEquals(emailFromJwt(fakeJwt("me@risalabs.ai")), "me@risalabs.ai")
  assertEquals(emailFromJwt("not.a.jwt"), "")
})

Deno.test("isSessionRow requires an http(s) control_url", () => {
  assert(isSessionRow(ROW))
  assert(!isSessionRow({ ...ROW, control_url: "javascript:alert(1)" }))
  assert(!isSessionRow({ ...ROW, control_url: undefined }))
})
