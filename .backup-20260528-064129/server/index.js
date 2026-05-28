// ================================
//  server/index.js — Detectify v4
//  Production Express Server
// ================================
require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const config      = require('./config/env');
const logger      = require('./utils/logger');
const { connectDB } = require('./models/db');
const scanRouter  = require('./routes/scan');
const authRouter  = require('./routes/auth');
const { errorHandler, notFound } = require('./middleware/errorHandler');

const app = express();

// ---- Trust Proxy (for deployment behind nginx/render) ----
app.set('trust proxy', 1);

// ---- Security Headers (Helmet) ----
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      fontSrc:     ["'self'", 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      objectSrc:   ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false  // Allow CDN fonts/icons
}));

// ---- CORS ----
app.use(cors({
  origin:      config.NODE_ENV === 'production' ? false : '*',
  credentials: true
}));

// ---- Body Parsing ----
app.use(express.json({ limit: '10kb' }));          // Prevent large payload attacks
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ---- Global Rate Limiter ----
app.use(rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW * 60 * 1000,
  max:      config.RATE_LIMIT_MAX,
  message:  { error: 'Too many requests. Please slow down.' }
}));

// ---- Request Logger ----
app.use((req, res, next) => {
  logger.debug(`${req.method} ${req.path} — ${req.ip}`);
  next();
});

// ---- Static Frontend ----
app.use(express.static(path.join(__dirname, '../public'), {
  maxAge: config.NODE_ENV === 'production' ? '1d' : 0
}));

// ---- API Routes ----
app.use('/api/auth', authRouter);
app.use('/api',      scanRouter);

// ---- Catch-all → SPA ----
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ---- Error Handling ----
app.use(notFound);
app.use(errorHandler);

// ---- Start ----
async function start() {
  // Connect MongoDB (optional)
  if (config.MONGODB_URI) {
    await connectDB(config.MONGODB_URI);
  } else {
    logger.warn('MONGODB_URI not set — running without database');
  }

  app.listen(config.PORT, () => {
    logger.info(`\n🛡️  Detectify v4 running → http://localhost:${config.PORT}`);
    logger.info(`   Mode:       ${config.NODE_ENV}`);
    logger.info(`   Claude AI:  ${config.ANTHROPIC_API_KEY  ? '✅' : '❌ not set'}`);
    logger.info(`   Google SB:  ${config.GOOGLE_SAFE_BROWSING_KEY ? '✅' : '❌ not set'}`);
    logger.info(`   VirusTotal: ${config.VIRUSTOTAL_KEY     ? '✅' : '❌ not set'}`);
    logger.info(`   MongoDB:    ${config.MONGODB_URI        ? '✅' : '❌ not set'}\n`);
  });
}

start();

module.exports = app; // For testing
