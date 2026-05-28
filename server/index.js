require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const config       = require('./config/env');
const logger       = require('./utils/logger');
const { connectDB }= require('./models/db');
const scanRouter   = require('./routes/scan');
const authRouter   = require('./routes/auth');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      fontSrc:     ["'self'", 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      objectSrc:   ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: config.NODE_ENV === 'production' ? false : '*', credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(rateLimit({ windowMs: config.RATE_LIMIT_WINDOW * 60 * 1000, max: config.RATE_LIMIT_MAX, message: { error: 'Too many requests.' } }));
app.use((req, res, next) => { logger.debug(`${req.method} ${req.path} — ${req.ip}`); next(); });
app.use(express.static(path.join(__dirname, '../public'), {
  maxAge: 0, etag: false, lastModified: false,
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));
app.use('/api/auth', authRouter);
app.use('/api', scanRouter);
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, '../public/index.html'));
});
app.use(notFound);
app.use(errorHandler);
async function start() {
  if (config.MONGODB_URI) await connectDB(config.MONGODB_URI);
  else logger.warn('MONGODB_URI not set — running without database');
  app.listen(config.PORT, () => {
    logger.info(`\n🛡️  Detectify v4 running → http://localhost:${config.PORT}`);
    logger.info(`   Mode: ${config.NODE_ENV}`);
  });
}
start();
module.exports = app;
