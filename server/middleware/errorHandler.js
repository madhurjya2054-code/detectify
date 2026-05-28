// server/middleware/errorHandler.js — Centralized error handling
const logger = require('../utils/logger');

function errorHandler(err, req, res, next) {
  logger.error(`${req.method} ${req.path} — ${err.message}`, { stack: err.stack });

  const status  = err.status || err.statusCode || 500;
  const message = status < 500 ? err.message : 'Internal server error. Please try again.';

  res.status(status).json({ error: message });
}

function notFound(req, res) {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found.` });
}

module.exports = { errorHandler, notFound };
