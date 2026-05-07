export const config = { runtime: 'edge' };

const COOKIE_NAME = 'trip-auth';
const MAX_AGE_S = 30 * 24 * 3600;

export default async function handler(request) {
  const url = new URL(request.url);

  if (request.method !== 'POST') {
    return Response.redirect(new URL('/login.html', url.origin), 302);
  }

  const form = await request.formData();
  const pwd = (form.get('password') || '').toString();
  const expected = process.env.AUTH_PASSWORD || '';

  if (!expected || pwd !== expected) {
    return Response.redirect(new URL('/login.html?err=1', url.origin), 302);
  }

  const ts = String(Date.now());
  const sig = await hmacHex(ts, process.env.AUTH_SECRET || '');
  const cookieVal = ts + '.' + sig;
  const cookie =
    COOKIE_NAME + '=' + cookieVal +
    '; Path=/; Max-Age=' + MAX_AGE_S +
    '; HttpOnly; Secure; SameSite=Lax';

  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': cookie,
    },
  });
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
