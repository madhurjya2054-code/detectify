// server/routes/auth.js — Secure JWT Auth Routes
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const router   = express.Router();
const config   = require('../config/env');
const logger   = require('../utils/logger');
const { sanitizeBody } = require('../middleware/sanitize');

let User = null;
try { User = require('../models/db').User; } catch {}

function signToken(payload) {
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN });
}

// ---- POST /api/auth/register ----
router.post('/register', sanitizeBody, async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email format.' });

    // If MongoDB is available
    if (User) {
      const exists = await User.findOne({ email });
      if (exists) return res.status(409).json({ error: 'Email already registered.' });
      const hashed = await bcrypt.hash(password, 12);
      const user   = await User.create({ name, email, password: hashed });
      const token  = signToken({ id: user._id, name, email });
      logger.info(`New user registered: ${email}`);
      return res.status(201).json({ token, user: { name, email } });
    }

    // No DB — token-only mode
    const token = signToken({ name, email });
    return res.status(201).json({ token, user: { name, email } });

  } catch (err) { next(err); }
});

// ---- POST /api/auth/login ----
router.post('/login', sanitizeBody, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });

    if (User) {
      const user = await User.findOne({ email });
      if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        logger.warn(`Failed login attempt for: ${email}`);
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
      await User.updateOne({ _id: user._id }, { lastLogin: new Date() });
      const token = signToken({ id: user._id, name: user.name, email });
      logger.info(`User logged in: ${email}`);
      return res.json({ token, user: { name: user.name, email } });
    }

    // No DB — demo token
    const token = signToken({ name: email.split('@')[0], email });
    return res.json({ token, user: { name: email.split('@')[0], email } });

  } catch (err) { next(err); }
});

// ---- GET /api/auth/me ----
router.get('/me', require('../middleware/auth').requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
