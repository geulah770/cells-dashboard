const { readSession, saveSession, clearSession, guard, googleToken } = require('../_session');

module.exports = async function (req, res) {
  if (!guard(req, res, 'GET')) return;
  let s;
  try { s = readSession(req); } catch (e) { return res.status(500).json({ error: 'server_config' }); }
  if (!s || !s.rt) return res.status(401).json({ error: 'no_session' });
  try {
    const { ok, data } = await googleToken({ grant_type: 'refresh_token', refresh_token: s.rt });
    if (!ok) {
      if (data.error === 'invalid_grant') { clearSession(res); return res.status(401).json({ error: 'expired' }); }
      return res.status(502).json({ error: 'google' });
    }
    saveSession(res, s.rt); // sliding expiry
    return res.status(200).json({ access_token: data.access_token, expires_in: data.expires_in });
  } catch (e) {
    return res.status(502).json({ error: 'server' });
  }
};
