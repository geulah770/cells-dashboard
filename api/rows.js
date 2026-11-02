// Reads and writes the "תאים" tab of the cells sheet for the dashboard.
// Env: GOOGLE_SERVICE_ACCOUNT_JSON, DASHBOARD_PASSWORD, SHEET_ID (optional).
const crypto = require('crypto');

const SHEET_ID = process.env.SHEET_ID || '1d6I8hfk97lWhuvlh9HA3E-IGRSCM-abxafiHYLrSmXM';
const TAB = 'תאים';
const FIRST_ROW = 2;
const LAST_ROW = 100;
const COLS = 10;

let tokenCache = { value: null, exp: 0 };

function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function accessToken(account) {
  const now = Math.floor(Date.now() / 1000);
  if (tokenCache.value && tokenCache.exp - 60 > now) return tokenCache.value;
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: account.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }));
  const signature = crypto.createSign('RSA-SHA256').update(header + '.' + claim).sign(account.private_key);
  const jwt = header + '.' + claim + '.' + b64url(signature);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt }),
  });
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error('token');
  tokenCache = { value: j.access_token, exp: now + (j.expires_in || 3600) };
  return tokenCache.value;
}

function sheetsUrl(range, query) {
  return 'https://sheets.googleapis.com/v4/spreadsheets/' + SHEET_ID + '/values/' +
    encodeURIComponent(range) + (query ? '?' + query : '');
}

function sameKey(given, expected) {
  const a = crypto.createHash('sha256').update(String(given || '')).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 20000) throw new Error('too_big');
  }
  return raw ? JSON.parse(raw) : {};
}

module.exports = async function handler(req, res) {
  const password = process.env.DASHBOARD_PASSWORD;
  const rawAccount = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!password || !rawAccount) return send(res, 503, { error: 'not_configured' });
  if (!sameKey(req.headers['x-dashboard-key'], password)) return send(res, 401, { error: 'unauthorized' });

  let account;
  try {
    account = JSON.parse(rawAccount);
  } catch (e) {
    return send(res, 503, { error: 'not_configured' });
  }

  try {
    const token = await accessToken(account);
    const auth = { authorization: 'Bearer ' + token };

    if (req.method === 'GET') {
      const r = await fetch(sheetsUrl(TAB + '!A' + FIRST_ROW + ':J' + LAST_ROW, 'majorDimension=ROWS'), { headers: auth });
      const j = await r.json();
      if (!r.ok) return send(res, 502, { error: 'upstream_error' });
      return send(res, 200, { values: j.values || [] });
    }

    if (req.method === 'POST') {
      const body = await readBody(req);
      const row = Number(body.row);
      const values = body.values;
      if (!Number.isInteger(row) || row < FIRST_ROW || row > LAST_ROW) return send(res, 400, { error: 'bad_row' });
      if (!Array.isArray(values) || values.length !== COLS) return send(res, 400, { error: 'bad_values' });
      const clean = values.map(function (v) {
        if (typeof v === 'number' && Number.isFinite(v)) return v;
        return v == null ? '' : String(v).slice(0, 300);
      });

      // The row must still hold the same cabinet and cell number, so an edit never lands on a shifted row.
      const chk = await fetch(sheetsUrl(TAB + '!A' + row + ':B' + row), { headers: auth });
      const cj = await chk.json();
      const have = (cj.values && cj.values[0]) || [];
      if (!chk.ok || String(have[0]) !== String(clean[0]) || String(have[1]) !== String(clean[1])) {
        return send(res, 409, { error: 'row_changed' });
      }

      const w = await fetch(sheetsUrl(TAB + '!A' + row + ':J' + row, 'valueInputOption=RAW'), {
        method: 'PUT',
        headers: Object.assign({ 'content-type': 'application/json' }, auth),
        body: JSON.stringify({ range: TAB + '!A' + row + ':J' + row, majorDimension: 'ROWS', values: [clean] }),
      });
      if (!w.ok) return send(res, 502, { error: 'upstream_error' });
      return send(res, 200, { ok: true });
    }

    res.setHeader('allow', 'GET, POST');
    return send(res, 405, { error: 'method_not_allowed' });
  } catch (e) {
    return send(res, 502, { error: 'upstream_error' });
  }
};
