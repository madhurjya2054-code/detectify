// server/services/threatIntelligence.js
// Combines AI + Google Safe Browsing + VirusTotal into unified score
const config = require('../config/env');
const logger = require('../utils/logger');

// ---- Google Safe Browsing ----
async function checkGoogleSafeBrowsing(url) {
  if (!config.GOOGLE_SAFE_BROWSING_KEY) return null;
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.GOOGLE_SAFE_BROWSING_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client:     { clientId: 'detectify', clientVersion: '4.0.0' },
          threatInfo: {
            threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes:    ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries:    [{ url }]
          }
        }),
        signal: AbortSignal.timeout(5000)
      }
    );
    const data = await res.json();
    const matches = data.matches || [];
    return {
      source:  'Google Safe Browsing',
      flagged: matches.length > 0,
      threats: matches.map(m => m.threatType),
      score:   matches.length > 0 ? 90 : 0
    };
  } catch (err) {
    logger.warn(`Google Safe Browsing failed: ${err.message}`);
    return null;
  }
}

// ---- VirusTotal ----
async function checkVirusTotal(url) {
  if (!config.VIRUSTOTAL_KEY) return null;
  try {
    // Submit URL for analysis
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey':     config.VIRUSTOTAL_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`,
      signal: AbortSignal.timeout(8000)
    });

    if (!submitRes.ok) return null;
    const submitData = await submitRes.json();
    const analysisId = submitData.data?.id;
    if (!analysisId) return null;

    // Get analysis results
    const resultRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': config.VIRUSTOTAL_KEY },
      signal: AbortSignal.timeout(8000)
    });

    const resultData = await resultRes.json();
    const stats = resultData.data?.attributes?.stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const total      = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
    const flaggedBy  = malicious + suspicious;

    return {
      source:    'VirusTotal',
      flagged:   flaggedBy > 0,
      malicious,
      suspicious,
      total,
      score:     Math.min(Math.round((flaggedBy / total) * 100), 100)
    };
  } catch (err) {
    logger.warn(`VirusTotal failed: ${err.message}`);
    return null;
  }
}

// ---- Claude AI Analysis ----
async function checkClaudeAI(url, localChecks) {
  if (!config.ANTHROPIC_API_KEY) return null;

  const prompt = `You are a cybersecurity expert. Analyze this URL for phishing threats: "${url}"

Local analysis:
- HTTPS: ${localChecks?.hasHTTPS ?? false}
- Keywords: ${localChecks?.suspiciousKeywords?.join(', ') || 'none'}
- Typosquatting: ${localChecks?.typosquatting ?? false}
- IP domain: ${localChecks?.hasIP ?? false}
- Long URL: ${localChecks?.longURL ?? false}
- Many subdomains: ${localChecks?.manySubdomains ?? false}
- Redirects: ${localChecks?.redirectParams ?? false}
- Suspicious TLD: ${localChecks?.hasSuspiciousTLD ?? false}
- Local score: ${localChecks?.localScore ?? 0}/100

Respond ONLY with valid JSON:
{
  "aiScore": <0-100>,
  "verdict": "<Safe|Suspicious|Phishing>",
  "domainAge": "<Likely new (< 1 year)|Established (1-5 years)|Well established (5+ years)|Unknown>",
  "sslStatus": "<Valid and trusted|Missing - major red flag|Suspicious configuration|Unknown>",
  "threatCategory": "<None|Credential Harvesting|Brand Impersonation|Malware Distribution|Scam|Spam|Unknown>",
  "analysis": "<2-3 sentence plain English explanation>",
  "topRisks": ["<risk1>","<risk2>","<risk3>"]
}`;

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         config.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 800,
        messages:   [{ role: 'user', content: prompt }]
      }),
      signal: AbortSignal.timeout(15000)
    });

    if (!res.ok) return null;
    const data  = await res.json();
    const text  = data.content.map(i => i.text || '').join('');
    const clean = text.replace(/```json|```/g, '').trim();
    return { source: 'Claude AI', ...JSON.parse(clean) };
  } catch (err) {
    logger.warn(`Claude AI failed: ${err.message}`);
    return null;
  }
}

// ---- Unified Scoring Engine ----
function computeUnifiedScore(localScore, gsb, vt, ai) {
  let totalWeight = 0;
  let weightedSum = 0;

  // Local checks — weight 20%
  weightedSum += localScore * 0.20;
  totalWeight += 0.20;

  // Google Safe Browsing — weight 35% (very reliable)
  if (gsb) {
    weightedSum += gsb.score * 0.35;
    totalWeight += 0.35;
  }

  // VirusTotal — weight 30%
  if (vt) {
    weightedSum += vt.score * 0.30;
    totalWeight += 0.30;
  }

  // Claude AI — weight 30%
  if (ai) {
    weightedSum += (ai.aiScore || 0) * 0.30;
    totalWeight += 0.30;
  }

  return Math.min(Math.round(weightedSum / totalWeight), 100);
}

// ---- Main Export ----
async function analyzeUrl(url, localChecks) {
  // Run all checks in parallel
  const [gsb, vt, ai] = await Promise.all([
    checkGoogleSafeBrowsing(url),
    checkVirusTotal(url),
    checkClaudeAI(url, localChecks)
  ]);

  const localScore   = localChecks?.localScore || 0;
  const finalScore   = computeUnifiedScore(localScore, gsb, vt, ai);
  const verdict      = finalScore >= 65 ? 'Phishing' : finalScore >= 30 ? 'Suspicious' : 'Safe';

  return {
    finalScore,
    verdict,
    domainAge:      ai?.domainAge     || 'Unknown',
    sslStatus:      ai?.sslStatus     || (localChecks?.hasHTTPS ? 'Present' : 'Missing'),
    threatCategory: ai?.threatCategory || (gsb?.flagged ? gsb.threats[0] : 'Unknown'),
    analysis:       ai?.analysis      || buildFallbackAnalysis(url, localChecks, gsb, vt),
    topRisks:       buildTopRisks(localChecks, gsb, vt, ai),
    sources: {
      localScore,
      googleSafeBrowsing: gsb,
      virusTotal:         vt,
      claudeAI:           ai ? { aiScore: ai.aiScore, verdict: ai.verdict } : null
    }
  };
}

function buildTopRisks(local, gsb, vt, ai) {
  const risks = [];
  if (gsb?.flagged)                 risks.push(`Flagged by Google Safe Browsing: ${gsb.threats.join(', ')}`);
  if (vt?.malicious > 0)            risks.push(`${vt.malicious}/${vt.total} VirusTotal engines flagged`);
  if (!local?.hasHTTPS)             risks.push('No HTTPS encryption');
  if (local?.hasIP)                 risks.push('IP address used as domain');
  if (local?.typosquatting)         risks.push('Possible brand impersonation');
  if (local?.hasSuspiciousTLD)      risks.push('High-risk domain extension');
  if (local?.manySubdomains)        risks.push('Excessive subdomain depth');
  if (ai?.topRisks)                 risks.push(...ai.topRisks);
  return [...new Set(risks)].slice(0, 5);
}

function buildFallbackAnalysis(url, local, gsb, vt) {
  if (gsb?.flagged) return `This URL was flagged by Google Safe Browsing for: ${gsb.threats.join(', ')}. Do not visit this URL.`;
  if (vt?.malicious > 0) return `VirusTotal flagged this URL with ${vt.malicious} malicious detections out of ${vt.total} engines. High threat risk.`;
  const score = local?.localScore || 0;
  if (score >= 65) return 'Multiple high-risk signals detected. This URL shows strong phishing characteristics.';
  if (score >= 30) return 'Some suspicious patterns detected. Proceed with caution.';
  return 'No major threat signals detected. Always remain cautious online.';
}

module.exports = { analyzeUrl };
