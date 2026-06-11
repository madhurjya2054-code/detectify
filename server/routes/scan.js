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
  const keys = Object.keys(process.env).filter(k => 
    k.includes('ANTHROPIC') || k.includes('GOOGLE') || k.includes('VIRUSTOTAL')
  );
  res.json({
    status:    'ok',
    service:   'Detectify API v4',
    version:   '4.0.2',
    features: {
      ai:               !!process.env.ANTHROPIC_API_KEY,
      googleSafeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_KEY,
      virusTotal:       !!process.env.VIRUSTOTAL_KEY,
      database:         !!process.env.MONGODB_URI
    },
    debug_keys: keys,
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


// ---- GET /api/whois ----
router.get('/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    const whois = require('whois-json');
    const data = await whois(domain);
    const created = data.creationDate || data.created || data.registrationDate || null;
    const expires = data.expirationDate || data.expires || data.registrarRegistrationExpirationDate || null;
    const registrar = data.registrar || data.sponsoringRegistrar || 'Unknown';
    const country = data.registrantCountry || data.country || 'Unknown';
    const status = Array.isArray(data.domainStatus) ? data.domainStatus[0] : (data.domainStatus || 'ok');

    let age = 'Unknown';
    let isNew = false;
    if (created) {
      const createdDate = new Date(created);
      const now = new Date();
      const diffMs = now - createdDate;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      if (diffDays < 365) {
        age = diffDays < 30 ? diffDays + ' days — ⚠️ Very new' : Math.floor(diffDays/30) + ' months';
        isNew = diffDays < 180;
      } else {
        const years = Math.floor(diffDays / 365);
        age = years + ' year' + (years > 1 ? 's' : '');
      }
    }

    res.json({
      domain,
      registrar,
      created: created ? new Date(created).toISOString().split('T')[0] : 'Unknown',
      expires: expires ? new Date(expires).toISOString().split('T')[0] : 'Unknown',
      country,
      status: typeof status === 'string' ? status.split(' ')[0] : 'ok',
      age,
      isNew,
      simulated: false
    });
  } catch (err) {
    res.status(500).json({ error: 'WHOIS lookup failed', message: err.message });
  }
});

module.exports = router;
