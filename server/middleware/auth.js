// server/middleware/auth.js — JWT verification middleware
const jwt    = require('jsonwebtoken');
const config = require('../config/env');
const logger = require('../utils/logger');

/**
 * Strict auth — rejects if no valid token
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    logger.warn(`Auth failure from ${req.ip}: ${err.message}`);
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/**
 * Optional auth — attaches user if token present, continues either way
 */
function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.split(' ')[1], config.JWT_SECRET);
    } catch {
      req.user = null;
    }
  }
  next();
}

module.exports = { requireAuth, optionalAuth };
