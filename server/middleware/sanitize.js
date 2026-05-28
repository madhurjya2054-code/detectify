// server/middleware/sanitize.js — Input sanitization + URL validation
const xss = require('xss');

// Dangerous URL schemes that must never be scanned
const BLOCKED_SCHEMES = ['javascript:', 'data:', 'file:', 'chrome:', 'vbscript:', 'about:'];

/**
 * Sanitize and validate URL from req.body.url
 */
function sanitizeUrl(req, res, next) {
  let { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'A valid URL string is required.' });
  }

  // Strip HTML/XSS from input
  url = xss(url.trim());

  // Length check
  if (url.length > 2000) {
    return res.status(400).json({ error: 'URL exceeds maximum length of 2000 characters.' });
  }

  if (url.length < 4) {
    return res.status(400).json({ error: 'URL is too short to be valid.' });
  }

  // Block dangerous schemes
  const lower = url.toLowerCase();
  const blocked = BLOCKED_SCHEMES.find(s => lower.startsWith(s));
  if (blocked) {
    return res.status(400).json({ error: `Blocked URL scheme: "${blocked}". Only http/https URLs are allowed.` });
  }

  // Auto-add https:// if missing scheme
  if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
    url = 'https://' + url;
  }

  // Must contain at least one dot (basic domain check)
  try {
    const parsed = new URL(url);
    if (!parsed.hostname.includes('.')) {
      return res.status(400).json({ error: 'Invalid URL — no valid domain found.' });
    }
  } catch {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  req.body.url = url;
  next();
}

/**
 * Sanitize all string fields in req.body
 */
function sanitizeBody(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    }
  }
  next();
}

module.exports = { sanitizeUrl, sanitizeBody };
