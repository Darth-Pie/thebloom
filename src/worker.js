// Gates /keeper.html and the Keeper's Reference docs behind the
// "Keeper's Secrets" login on 919gaming.com. Verifies the same signed
// cookie that Worker sets (shared AUTH_SECRET); everything else passes
// through to the static site untouched.

const LOGIN_URL = 'https://919gaming.com/keepers-secrets';
const COOKIE_NAME = 'keeper_auth';
const GATED_PATHS = new Set([
  '/keeper.html',
  '/keeper',
  '/The-Blooming-Keepers-Reference.docx',
  '/The-Blooming-Keepers-Reference.pdf'
]);

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'"
].join('; ');

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Content-Security-Policy', CSP);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function b64urlToBuf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
}
async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  try {
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify('HMAC', key, b64urlToBuf(sig), new TextEncoder().encode(payload));
    if (!valid) return null;
    const obj = JSON.parse(new TextDecoder().decode(b64urlToBuf(payload)));
    if (obj.exp && obj.exp < Math.floor(Date.now() / 1000)) return null;
    return obj;
  } catch (e) {
    return null;
  }
}
function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/keeper-status' && request.method === 'GET') {
      const token = getCookie(request, COOKIE_NAME);
      const authSecret = await env.AUTH_SECRET.get();
      const session = await verifyToken(token, authSecret);
      return withSecurityHeaders(new Response(JSON.stringify({ loggedIn: !!session }), {
        headers: { 'content-type': 'application/json', 'cache-control': 'no-store, private' }
      }));
    }

    if (GATED_PATHS.has(url.pathname)) {
      const token = getCookie(request, COOKIE_NAME);
      const authSecret = await env.AUTH_SECRET.get();
      const session = await verifyToken(token, authSecret);
      if (!session) {
        return withSecurityHeaders(Response.redirect(LOGIN_URL, 302));
      }
    }
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  }
};
