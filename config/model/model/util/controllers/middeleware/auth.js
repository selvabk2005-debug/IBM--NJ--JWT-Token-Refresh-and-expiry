const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Protect routes using access token (sent in Authorization: Bearer <token>)
module.exports = async function (req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'no token provided' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(payload.sub).select('-password');
    if (!user) return res.status(401).json({ message: 'user not found' });
    req.user = { id: user._id.toString(), username: user.username, roles: user.roles };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'invalid or expired token' });
  }
};