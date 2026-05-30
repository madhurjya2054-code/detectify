// server/routes/scan.js — Upgraded scan route
const express    = require('express');
const rateLimit  = require('express-rate-limit');
const router     = express.Router();
const { analyzeUrl }  = require('../services/threatIntelligence');
const { sanitizeUrl } = require('../middleware/sanitize');
const { optionalAuth }= require('../middleware/auth');
const logger     = require('../utils/logger');

let Scan = null;
try { Scan = require('../models/db').Scan; } catch {}

// ---- Rate limiter for /api/scan ----
const scanLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutes
  max: 20,
  message:         { error: 'Scan limit reached (20/10min). Please wait.' },
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    (req) => req.ip
});

// ---- POST /api/scan ----
router.post('/scan', scanLimiter, sanitizeUrl, optionalAuth, async (req, res, next) => {
  const { url, localChecks } = req.body;
  const startTime = Date.now();

  try {
    logger.info(`Scan requested: ${url} from ${req.ip}`);

    const result = await analyzeUrl(url, localChecks || {});

    // Save to MongoDB if available
    if (Scan) {
      await Scan.create({
        userId:         req.user?.id || null,
        url,
        finalScore:     result.finalScore,
        verdict:        result.verdict,
        threatCategory: result.threatCategory,
        analysis:       result.analysis,
        topRisks:       result.topRisks,
        localChecks,
        sources:        result.sources,
        ip:             req.ip
      }).catch(err => logger.warn('Scan save failed:', err.message));
    }

    logger.info(`Scan complete: ${url} → ${result.verdict} (${result.finalScore}) in ${Date.now()-startTime}ms`);
    res.json(result);

  } catch (err) {
    logger.error(`Scan error for ${url}: ${err.message}`);
    next(err);
  }
});

// ---- GET /api/health ----
router.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    service:   'Detectify API v4',
    version:   '4.0.1',
    features: {
      ai:               !!process.env.ANTHROPIC_API_KEY,
      googleSafeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_KEY,
      virusTotal:       !!process.env.VIRUSTOTAL_KEY,
      database:         !!process.env.MONGODB_URI
    },
    timestamp: new Date().toISOString()
  });
});

// ---- GET /api/stats (dashboard analytics) ----
router.get('/stats', optionalAuth, async (req, res, next) => {
  try {
    if (!Scan) return res.json({ message: 'Database not connected — stats unavailable' });

    const userId = req.user?.id;
    const filter = userId ? { userId } : {};

    const [total, threats, suspicious, safe, recent] = await Promise.all([
      Scan.countDocuments(filter),
      Scan.countDocuments({ ...filter, verdict: 'Phishing' }),
      Scan.countDocuments({ ...filter, verdict: 'Suspicious' }),
      Scan.countDocuments({ ...filter, verdict: 'Safe' }),
      Scan.find(filter).sort({ createdAt: -1 }).limit(10).select('url verdict finalScore createdAt')
    ]);

    res.json({ total, threats, suspicious, safe, recent });
  } catch (err) { next(err); }
});

module.exports = router;
