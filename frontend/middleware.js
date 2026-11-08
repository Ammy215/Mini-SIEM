// Vercel Routing Middleware: proxies /api/* to Render with a shared secret the
// backend requires (backend/middleware/proxy_secret.py), so the Render URL
// can't be called directly with a forged X-Forwarded-For. vercel.json can't do
// this itself — rewrites can't add request headers, and it can't read env vars.
//
// The response headers below are what @vercel/functions' rewrite() emits;
// they're written out to avoid a dependency for one call.

export const config = { matcher: '/api/:path*' }

const API_ORIGIN = 'https://mini-siem-api-ga6i.onrender.com'

export default function middleware(request) {
  // Trimmed on both sides: a pasted trailing newline would otherwise lock the app out.
  const secret = process.env.INTERNAL_PROXY_SECRET?.trim()
  // Unset: fall through to the plain rewrite in vercel.json.
  if (!secret) return

  const url = new URL(request.url)
  const upstream = new Headers(request.headers)
  upstream.set('x-internal-proxy-secret', secret)

  const out = new Headers({ 'x-middleware-rewrite': API_ORIGIN + url.pathname + url.search })
  const names = []
  upstream.forEach((value, name) => {
    names.push(name)
    out.set(`x-middleware-request-${name}`, value)
  })
  out.set('x-middleware-override-headers', names.join(','))
  return new Response(null, { headers: out })
}
