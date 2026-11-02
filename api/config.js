module.exports = function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({ clientId: process.env.GOOGLE_CLIENT_ID || '' });
};
