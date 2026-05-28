// ================================
//  scanner.js — Local URL Analysis
// ================================

/**
 * Runs all local (no-API) checks on a URL.
 * Returns an object with individual check results and a localScore.
 */
function runLocalChecks(url) {
  const lower = url.toLowerCase();

  // 1. HTTPS check
  const hasHTTPS = url.startsWith('https://');

  // 2. Suspicious keywords in URL
  const suspiciousKeywords = [
    'login', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'paypal', 'amazon', 'apple',
    'microsoft', 'google', 'facebook', 'instagram', 'signin'
  ].filter(k => lower.includes(k));

  // 3. Typosquatting detection
  const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'instagram', 'ebay'];
  const domain = (lower.split('/')[2] || '').replace('www.', '');
  const typosquatting = brands.some(brand => {
    const leet = brand
      .replace(/a/g, '[a4@]')
      .replace(/o/g, '[o0]')
      .replace(/i/g, '[i1!]')
      .replace(/e/g, '[e3]')
      .replace(/s/g, '[s5]');
    const leetRegex = new RegExp(leet);
    return leetRegex.test(domain) && !domain.endsWith(brand + '.com') && !domain.includes('.' + brand + '.com');
  });

  // 4. IP address used as domain
  const hasIP = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);

  // 5. @ symbol in URL (credential trick)
  const hasAtSymbol = url.includes('@');

  // 6. Unusually long URL
  const longURL = url.length > 100;

  // 7. Too many subdomains
  const manySubdomains = (lower.split('/')[2] || '').split('.').length > 4;

  // 8. Redirect/forwarding parameters
  const redirectParams = lower.includes('redirect=') || lower.includes('url=') || lower.includes('link=') || lower.includes('goto=');

  // 9. Suspicious TLDs
  const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.download'];
  const hasSuspiciousTLD = suspiciousTLDs.some(tld => lower.includes(tld));

  // 10. Excessive hyphens in domain
  const domainPart = (lower.split('/')[2] || '');
  const excessiveHyphens = (domainPart.match(/-/g) || []).length > 2;

  // Calculate local score
  let score = 0;
  if (!hasHTTPS)              score += 20;
  if (suspiciousKeywords.length > 0) score += Math.min(suspiciousKeywords.length * 8, 25);
  if (typosquatting)          score += 30;
  if (hasIP)                  score += 35;
  if (hasAtSymbol)            score += 20;
  if (longURL)                score += 10;
  if (manySubdomains)         score += 15;
  if (redirectParams)         score += 15;
  if (hasSuspiciousTLD)       score += 20;
  if (excessiveHyphens)       score += 10;

  return {
    hasHTTPS,
    suspiciousKeywords,
    typosquatting,
    hasIP,
    hasAtSymbol,
    longURL,
    manySubdomains,
    redirectParams,
    hasSuspiciousTLD,
    excessiveHyphens,
    localScore: Math.min(score, 100)
  };
}

/**
 * Determines risk level from a score 0-100.
 */
function getRiskLevel(score) {
  if (score < 30) return { label: 'Safe',       cssClass: 'risk-safe',       color: '#639922' };
  if (score < 65) return { label: 'Suspicious', cssClass: 'risk-suspicious', color: '#BA7517' };
  return             { label: 'Phishing',    cssClass: 'risk-phishing',   color: '#E24B4A' };
}

/**
 * Downloads a professional HTML report for a given scan result.
 */
function downloadReport(url, score, verdict, category, analysis, risks) {
  const risk         = getRiskLevel(score);
  const now          = new Date().toLocaleString();
  const user         = JSON.parse(localStorage.getItem('detectify_user') || '{}');
  const scannedBy    = user.name || 'Guest';
  const verdictColor = score >= 65 ? '#791F1F' : score >= 30 ? '#633806' : '#27500A';
  const verdictBg    = score >= 65 ? '#FCEBEB' : score >= 30 ? '#FAEEDA' : '#EAF3DE';
  const gaugeColor   = score >= 65 ? '#E24B4A' : score >= 30 ? '#BA7517' : '#639922';

  const riskRowsHTML = (risks || []).map(r =>
    `<tr><td style="padding:10px 14px;border-bottom:1px solid #eee;font-size:14px;"><span style="color:#E24B4A;margin-right:8px;">⚠</span>${r}</td></tr>`
  ).join('');

  const hasHTTPS  = url.startsWith('https://');
  const hasIP     = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);

  const checksHTML = [
    { label: 'SSL / HTTPS',   val: hasHTTPS ? '✅ Present'  : '❌ Missing — red flag' },
    { label: 'IP-Based URL',  val: hasIP    ? '❌ Detected' : '✅ No IP detected'     },
    { label: 'Verdict',       val: verdict  },
    { label: 'Threat Category', val: category },
  ].map(c => `<tr>
    <td style="padding:10px 14px;border-bottom:1px solid #eee;font-weight:600;font-size:13px;color:#6b7280;width:40%;">${c.label}</td>
    <td style="padding:10px 14px;border-bottom:1px solid #eee;font-size:14px;">${c.val}</td>
  </tr>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Detectify — Scan Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:Arial,sans-serif;background:#f3f4f6;color:#111827;}
    .page{max-width:750px;margin:32px auto;background:white;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.10);}
    .header{background:linear-gradient(135deg,#0C447C,#185FA5);color:white;padding:32px 36px;}
    .header-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;}
    .brand{font-size:22px;font-weight:700;display:flex;align-items:center;gap:10px;}
    .brand-icon{width:38px;height:38px;background:rgba(255,255,255,.2);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px;}
    .report-meta{font-size:12px;opacity:.75;text-align:right;line-height:1.8;}
    .verdict-bar{display:flex;align-items:center;gap:16px;background:rgba(255,255,255,.1);border-radius:10px;padding:14px 20px;}
    .verdict-label{font-size:13px;opacity:.8;margin-bottom:4px;}
    .verdict-badge{padding:6px 20px;border-radius:20px;font-weight:700;font-size:15px;background:${verdictBg};color:${verdictColor};}
    .body{padding:28px 36px;}
    .section{margin-bottom:24px;}
    .section-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#185FA5;margin-bottom:12px;}
    .url-box{font-family:monospace;background:#f3f4f6;padding:12px 16px;border-radius:8px;word-break:break-all;font-size:13px;border-left:4px solid #185FA5;}
    .score-num{font-size:36px;font-weight:700;color:${gaugeColor};margin-bottom:8px;}
    .gauge-track{height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden;}
    .gauge-fill{height:100%;border-radius:7px;background:${gaugeColor};width:${score}%;}
    .score-legend{display:flex;justify-content:space-between;font-size:11px;color:#9ca3af;margin-top:6px;}
    table{width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;}
    th{background:#f3f4f6;padding:10px 14px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;}
    .analysis-box{background:#EDF4FD;border-left:4px solid #185FA5;border-radius:0 8px 8px 0;padding:14px 18px;font-size:14px;line-height:1.75;color:#1f2937;}
    .footer{background:#f9fafb;border-top:1px solid #e5e7eb;padding:16px 36px;text-align:center;font-size:12px;color:#9ca3af;}
  </style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="header-top">
      <div class="brand"><div class="brand-icon">🛡️</div> Detectify</div>
      <div class="report-meta">Scan Report<br>${now}<br>Scanned by: ${scannedBy}</div>
    </div>
    <div class="verdict-bar">
      <div>
        <div class="verdict-label">Threat Verdict</div>
        <span class="verdict-badge">${verdict}</span>
      </div>
      <div style="flex:1"></div>
      <div style="text-align:right;">
        <div class="verdict-label">Risk Score</div>
        <div style="font-size:26px;font-weight:700;">${score}/100</div>
      </div>
    </div>
  </div>
  <div class="body">
    <div class="section">
      <div class="section-title">📎 Scanned URL</div>
      <div class="url-box">${url}</div>
    </div>
    <div class="section">
      <div class="section-title">📊 Risk Score</div>
      <div class="score-num">${score}<span style="font-size:18px;color:#9ca3af;">/100</span></div>
      <div class="gauge-track"><div class="gauge-fill"></div></div>
      <div class="score-legend">
        <span style="color:#639922;">Safe (0–29)</span>
        <span style="color:#BA7517;">Suspicious (30–64)</span>
        <span style="color:#E24B4A;">Phishing (65–100)</span>
      </div>
    </div>
    <div class="section">
      <div class="section-title">🔍 Security Checks</div>
      <table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>${checksHTML}</tbody></table>
    </div>
    <div class="section">
      <div class="section-title">🤖 AI Analysis</div>
      <div class="analysis-box">${analysis}</div>
    </div>
    ${riskRowsHTML ? `<div class="section"><div class="section-title">⚠️ Risk Signals</div><table><thead><tr><th>Detected Signal</th></tr></thead><tbody>${riskRowsHTML}</tbody></table></div>` : ''}
  </div>
  <div class="footer">Detectify · AI-Powered Threat Detection · Final Year Project · For Educational Purposes Only</div>
</div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `detectify-report-${Date.now()}.html`;
  a.click();
}
