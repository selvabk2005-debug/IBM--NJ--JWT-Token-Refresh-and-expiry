const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateAccessToken, generateRefreshToken } = require('../utils/tokens');

const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

// Register (simple)
exports.register = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username and password required' });

  const existing = await User.findOne({ username });
  if (existing) return res.status(409).json({ message: 'username taken' });

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  const user = await User.create({ username, password: hash });
  res.status(201).json({ id: user._id, username: user.username });
};

// Login -> issue access + refresh
exports.login = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ message: 'invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'invalid credentials' });

  const payload = { sub: user._id.toString(), username: user.username, roles: user.roles };
  const accessToken = generateAccessToken(payload);
  const refreshTokenString = generateRefreshToken({ sub: user._id.toString() });

  // Save refresh token to DB with expiry
  const decoded = jwt.decode(refreshTokenString);
  const expiresAt = decoded ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7*24*60*60*1000);

  await RefreshToken.create({ token: refreshTokenString, user: user._id, expiresAt });

  // Send access token in response body, refresh token as httpOnly cookie (recommended)
  res.cookie('refreshToken', refreshTokenString, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 * 7 // match refresh expiry (7 days)
  });

  res.json({ accessToken });
};

// Refresh endpoint
exports.refresh = async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken || req.headers['x-refresh-token'];
  if (!token) return res.status(401).json({ message: 'no refresh token provided' });

  // Check token exists in DB
  const stored = await RefreshToken.findOne({ token }).populate('user');
  if (!stored) return res.status(403).json({ message: 'refresh token revoked' });

  // Verify signature
  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = stored.user;
    const newAccess = generateAccessToken({ sub: user._id.toString(), username: user.username, roles: user.roles });

    // Optionally: rotate refresh tokens (issue new refresh, delete old)
    const newRefresh = generateRefreshToken({ sub: user._id.toString() });
    const decoded = jwt.decode(newRefresh);
    const expiresAt = decoded ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7*24*60*60*1000);

    // replace stored token
    stored.token = newRefresh;
    stored.expiresAt = expiresAt;
    await stored.save();

    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 7
    });

    return res.json({ accessToken: newAccess });
  } catch (err) {
    // token invalid/expired
    await RefreshToken.deleteOne({ token }).catch(() => {}); // cleanup
    return res.status(403).json({ message: 'invalid refresh token' });
  }
};

// Logout -> delete refresh token
exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken || req.headers['x-refresh-token'];
  if (token) await RefreshToken.deleteOne({ token });
  res.clearCookie('refreshToken');
  res.json({ message: 'logged out' });
};

// Example protected route (for testing)
exports.protected = async (req, res) => {
  res.json({ message: Hello ${req.user.username}, this is protected, user: req.user });
};