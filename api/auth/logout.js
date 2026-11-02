const { readSession, clearSession, guard } = require('../_session');

module.exports = async function (req, res) {
  if (!guard(req, res, 'POST')) return;
  try {
    const s = readSession(req);
    if (s && s.rt) {
      await fetch('https://oauth2.googleapis.com/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: s.rt }),
      }).catch(() => {});
    }
  } catch (e) {}
  clearSession(res);
  res.status(200).json({ ok: true });
};
