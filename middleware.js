export const config = {
  matcher: '/((?!login\\.html|api/login|favicon\\.ico).*)',
};

const COOKIE_NAME = 'trip-auth';
const MAX_AGE_MS = 30 * 24 * 3600 * 1000;

export default async function middleware(request) {
  const url = new URL(request.url);
  const loginUrl = new URL('/login.html', url.origin);

  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(new RegExp('(?:^|; )' + COOKIE_NAME + '=([^;]+)'));
  if (!match) return Response.redirect(loginUrl, 302);

  const token = decodeURIComponent(match[1]);
  const dot = token.indexOf('.');
  if (dot < 0) return Response.redirect(loginUrl, 302);

  const ts = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const tsNum = parseInt(ts, 10);
  if (!tsNum || Date.now() - tsNum > MAX_AGE_MS) {
    return Response.redirect(loginUrl, 302);
  }

  const expected = await hmacHex(ts, process.env.AUTH_SECRET || '');
  if (sig !== expected) return Response.redirect(loginUrl, 302);

  return;
}

async function hmacHex(data, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
