'use strict';

const express  = require('express');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const mongoose = require('mongoose');
const logger   = require('../utils/logger');

const router = express.Router();

/* ─── Configuration ─────────────────────────────────────────────────────── */
const JWT_SECRET     = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS  = 12;
const MAX_ATTEMPTS   = 5;
const LOCKOUT_MS     = 15 * 60 * 1000;

if (!JWT_SECRET) throw new Error('[auth] JWT_SECRET is required.');

/* ─── User Model ─────────────────────────────────────────────────────────── */
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true, maxlength: 100 },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

/* ─── In-memory brute force protection ──────────────────────────────────── */
const loginAttempts = new Map();

function getLockoutRemaining(email) {
  const record = loginAttempts.get(email);
  if (!record?.lockedUntil) return 0;
  const remaining = record.lockedUntil - Date.now();
  if (remaining <= 0) { loginAttempts.delete(email); return 0; }
  return remaining;
}

function recordFailedLogin(email) {
  const now    = Date.now();
  const record = loginAttempts.get(email) || { count: 0, firstAttempt: now, lockedUntil: null };
  record.count += 1;
  if (record.count >= MAX_ATTEMPTS) record.lockedUntil = now + LOCKOUT_MS;
  loginAttempts.set(email, record);
}

function resetLoginAttempts(email) {
  loginAttempts.delete(email);
}

/* ─── Helpers ────────────────────────────────────────────────────────────── */
function isValidEmail(email) {
  const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return re.test(email) && email.length <= 254;
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 8)
    return 'Password must be at least 8 characters long.';
  if (!/[A-Z]/.test(password))
    return 'Password must contain at least one uppercase letter.';
  if (!/[a-z]/.test(password))
    return 'Password must contain at least one lowercase letter.';
  if (!/[0-9]/.test(password))
    return 'Password must contain at least one number.';
  return null;
}

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
  );
}

function safeUser(user) {
  return {
    id:        user._id.toString(),
    name:      user.name,
    email:     user.email,
    createdAt: user.createdAt
  };
}

/* ─── POST /api/auth/register ────────────────────────────────────────────── */
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};

    if (!name?.trim() || !email || !password)
      return res.status(400).json({ message: 'Name, email, and password are required.' });

    const normalizedEmail = email.trim().toLowerCase();

    if (!isValidEmail(normalizedEmail))
      return res.status(400).json({ message: 'Please enter a valid email address.' });

    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ message: pwError });

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: 'Database not connected. Please try again later.' });
    }

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({
        message: 'Unable to create account. Please try a different email or sign in.',
      });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await User.create({
      name:     name.trim(),
      email:    normalizedEmail,
      password: passwordHash,
    });

    const token = signToken(user);
    logger.info(`New user registered: ${normalizedEmail}`);
    return res.status(201).json({ token, user: safeUser(user) });

  } catch (err) {
    logger.error('[auth/register]', err.message);
    return res.status(500).json({ message: 'An unexpected error occurred. Please try again.' });
  }
});

/* ─── POST /api/auth/login ───────────────────────────────────────────────── */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const normalizedEmail = email.trim().toLowerCase();

    const lockRemaining = getLockoutRemaining(normalizedEmail);
    if (lockRemaining > 0) {
      const minutes = Math.ceil(lockRemaining / 60_000);
      return res.status(429).json({
        message: `Too many failed attempts. Please try again in ${minutes} minute${minutes !== 1 ? 's' : ''}.`,
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: 'Database not connected. Please try again later.' });
    }

    const user = await User.findOne({ email: normalizedEmail });

    const DUMMY_HASH = '$2b$12$invalidhashusedtopreventimenumeration00000000000000000';
    const hashToCompare = user ? user.password : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    if (!user || !passwordMatch) {
      if (user) recordFailedLogin(normalizedEmail);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    resetLoginAttempts(normalizedEmail);
    await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

    const token = signToken(user);
    logger.info(`User logged in: ${normalizedEmail}`);
    return res.status(200).json({ token, user: safeUser(user) });

  } catch (err) {
    logger.error('[auth/login]', err.message);
    return res.status(500).json({ message: 'An unexpected error occurred. Please try again.' });
  }
});

module.exports = router;
