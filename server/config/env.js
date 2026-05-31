// server/config/env.js — Environment variable validation
require('dotenv').config({ override: false });

const required = ['GEMINI_API_KEY'];
const missing  = required.filter(k => !process.env[k]);

if (missing.length > 0) {
  console.warn(`⚠️  Missing env vars: ${missing.join(', ')} — fallback mode active`);
}

module.exports = {
  PORT:              process.env.PORT || 3000,
  NODE_ENV:          process.env.NODE_ENV || 'development',
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY || null,
  GEMINI_API_KEY:    process.env.GEMINI_API_KEY || null,
  MONGODB_URI:       process.env.MONGODB_URI || null,
  JWT_SECRET:        process.env.JWT_SECRET || 'detectify-dev-secret-change-in-prod',
  JWT_EXPIRES_IN:    process.env.JWT_EXPIRES_IN || '7d',
  GOOGLE_SAFE_BROWSING_KEY: process.env.GOOGLE_SAFE_BROWSING_KEY || null,
  VIRUSTOTAL_KEY:    process.env.VIRUSTOTAL_KEY || null,
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15,
  RATE_LIMIT_MAX:    parseInt(process.env.RATE_LIMIT_MAX) || 100,
  SCAN_LIMIT_MAX:    parseInt(process.env.SCAN_LIMIT_MAX) || 20,
};