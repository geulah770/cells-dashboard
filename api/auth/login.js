const crypto = require('crypto');
const { STATE, SCOPE, setCookie, origin } = require('../_session');

module.exports = function (req, res) {
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, STATE, state, 600);
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.search = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID || '',
    redirect_uri: origin(req) + '/api/auth/callback',
    response_type: 'code',
    scope: SCOPE,
    access_type: 'offline',
    prompt: 'consent select_account',
    state,
  }).toString();
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 302;
  res.setHeader('Location', u.toString());
  res.end();
};
