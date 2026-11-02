const { STATE, SCOPE, cookies, setCookie, origin, saveSession, googleToken } = require('../_session');

function back(res, err) {
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 302;
  res.setHeader('Location', err ? '/?autherror=' + encodeURIComponent(err) : '/');
  res.end();
}

module.exports = async function (req, res) {
  const q = req.query || {};
  const want = cookies(req)[STATE];
  setCookie(res, STATE, '', 0);
  if (q.error) return back(res, q.error);
  if (!want || q.state !== want || !q.code) return back(res, 'state');
  try {
    const { ok, data } = await googleToken({
      grant_type: 'authorization_code',
      code: q.code,
      redirect_uri: origin(req) + '/api/auth/callback',
    });
    if (!ok || !data.refresh_token) return back(res, data.error || 'no_refresh_token');
    if (String(data.scope || '').indexOf(SCOPE) < 0) return back(res, 'missing_scope');
    saveSession(res, data.refresh_token);
    return back(res);
  } catch (e) {
    return back(res, 'server');
  }
};
