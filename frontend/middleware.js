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
  const url = new URL(request.url)

  // TEMP DIAGNOSTIC — remove in the next commit.
  if (url.pathname === '/api/_probe') {
    const probe = new Headers(request.headers)
    probe.set('x-probe', 'hello')
    const res = new Headers({ 'x-middleware-rewrite': 'https://httpbin.org/headers', 'x-proxy-mw': '1' })
    const keys = []
    probe.forEach((value, name) => {
      keys.push(name)
      res.set(`x-middleware-request-${name}`, value)
    })
    res.set('x-middleware-override-headers', keys.join(','))
    return new Response(null, { headers: res })
  }

  const secret = process.env.INTERNAL_PROXY_SECRET
  // Unset: fall through to the plain rewrite in vercel.json.
  if (!secret) return

  const upstream = new Headers(request.headers)
  upstream.set('x-internal-proxy-secret', secret)

  const out = new Headers({
    'x-middleware-rewrite': API_ORIGIN + url.pathname + url.search,
    'x-proxy-mw': '1', // TEMP DIAGNOSTIC
  })
  const names = []
  upstream.forEach((value, name) => {
    names.push(name)
    out.set(`x-middleware-request-${name}`, value)
  })
  out.set('x-middleware-override-headers', names.join(','))
  return new Response(null, { headers: out })
}
