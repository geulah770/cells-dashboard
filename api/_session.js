const crypto = require('crypto');

const SESSION = 'dd_session';
const STATE = 'dd_state';
const MAX_AGE = 60 * 24 * 3600; // 60 days, renewed on every use
const SCOPE = 'https://www.googleapis.com/auth/spreadsheets';

function key() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error('SESSION_SECRET is not set');
  return crypto.createHash('sha256').update(s).digest();
}
function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const enc = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64url');
}
function open(str) {
  try {
    const b = Buffer.from(str, 'base64url');
    const d = crypto.createDecipheriv('aes-256-gcm', key(), b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
  } catch (e) { return null; }
}
function cookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value, maxAge) {
  const c = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : [c]);
}
function origin(req) {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/, '');
  return `https://${req.headers['x-forwarded-host'] || req.headers.host}`;
}
function readSession(req) {
  const v = cookies(req)[SESSION];
  return v ? open(v) : null;
}
function saveSession(res, rt) { setCookie(res, SESSION, seal({ rt }), MAX_AGE); }
function clearSession(res) { setCookie(res, SESSION, '', 0); }
function guard(req, res, method) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== method || req.headers['x-requested-with'] !== 'dashboard') {
    res.status(400).json({ error: 'bad_request' });
    return false;
  }
  return true;
}
async function googleToken(params) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID || '',
      client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
      ...params,
    }),
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, data: j };
}

module.exports = { SESSION, STATE, SCOPE, setCookie, cookies, origin, readSession, saveSession, clearSession, guard, googleToken };
