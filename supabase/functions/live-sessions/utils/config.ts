/**
 * Deployment configuration for the live-sessions function.
 *
 * THE PUBLIC BASE PATH IS NOT DERIVABLE FROM THE REQUEST (see
 * organisation/utils/config.ts for the full story): the gateway strips
 * `/functions/v1`, so anything the browser or GoTrue will use - the magic-link
 * `redirect_to`, fetch URLs in the page - is built from `publicBasePath()`.
 *
 * HTML only renders on the custom domain (api.risaboss.com); on the *.supabase.co
 * host Supabase rewrites text/html to text/plain.
 */

const DEFAULT_BASE_PATH = "/functions/v1/live-sessions"

/** Browser-facing path prefix, without a trailing slash. */
export function publicBasePath(): string {
  const configured = Deno.env.get("LIVE_SESSIONS_PUBLIC_BASE_PATH")?.trim()
  const raw = configured && configured.length > 0 ? configured : DEFAULT_BASE_PATH
  const withSlash = raw.startsWith("/") ? raw : `/${raw}`
  return withSlash.endsWith("/") ? withSlash.slice(0, -1) : withSlash
}

/** Absolute browser-usable path for a route within this function. */
export function publicPath(route: string): string {
  const suffix = route.startsWith("/") ? route : `/${route}`
  return `${publicBasePath()}${suffix}`
}

/**
 * Absolute base URL for links that leave this function - here, the GoTrue
 * `redirect_to`. GoTrue allow-lists the EXACT value (config.toml
 * additional_redirect_urls), so LIVE_SESSIONS_PUBLIC_BASE_URL should be set in
 * production to the canonical `https://api.risaboss.com`; the request origin is
 * only a fallback for local stacks.
 */
export function publicBaseUrl(requestUrl: string, forwardedHost: string | null, secure: boolean): string {
  const configured = Deno.env.get("LIVE_SESSIONS_PUBLIC_BASE_URL")?.trim()
  if (configured) return configured.replace(/\/+$/, "") + publicBasePath()

  const host = forwardedHost?.split(",")[0]?.trim() ||
    (() => {
      try {
        return new URL(requestUrl).host
      } catch {
        return ""
      }
    })()
  const scheme = secure ? "https" : "http"
  return host ? `${scheme}://${host}${publicBasePath()}` : publicBasePath()
}

/** True when the browser reached us over https (gateway terminates TLS, so read X-Forwarded-Proto). */
export function isSecureRequest(requestUrl: string, forwardedProto: string | null): boolean {
  if (forwardedProto) return forwardedProto.split(",")[0].trim().toLowerCase() === "https"
  try {
    return new URL(requestUrl).protocol === "https:"
  } catch {
    return false
  }
}

export interface LiveSessionsConfig {
  supabaseUrl: string
  anonKey: string
}

/**
 * The anon key is all this function needs: OTP send is an anon-key endpoint,
 * and every database read is made AS THE USER with their own JWT so RLS does
 * the filtering. There is deliberately no service-role read path.
 */
export function readConfig(): LiveSessionsConfig {
  return {
    supabaseUrl: (Deno.env.get("SUPABASE_URL") ?? "").replace(/\/+$/, ""),
    anonKey: Deno.env.get("SUPABASE_ANON_KEY") ?? "",
  }
}

/** A row is live when the desktop heartbeated within this window (heartbeat is 30 s). */
export const LIVE_WINDOW_SECONDS = 90
