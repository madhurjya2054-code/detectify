// ================================
//  api.js — Frontend API Client
//  ✅ NO API KEY HERE EVER
//  All AI calls go through backend
// ================================

/**
 * Calls our secure Express backend at /api/scan
 * The backend handles the Anthropic API key — never exposed to browser
 */
async function callClaudeAPI(url, localChecks) {
  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, localChecks })
    });

    if (response.status === 429) {
      // Rate limited
      showToast('⚠️ Scan limit reached. Please wait a few minutes.', 'warning');
      return generateClientFallback(url, localChecks);
    }

    if (!response.ok) {
      const err = await response.json();
      console.error('Backend error:', err);
      return generateClientFallback(url, localChecks);
    }

    return await response.json();

  } catch (error) {
    console.error('Network error:', error);
    showToast('⚠️ Could not reach server. Showing local analysis only.', 'warning');
    return generateClientFallback(url, localChecks);
  }
}

/**
 * Client-side fallback if backend is unreachable.
 * Uses local checks only — no AI.
 */
function generateClientFallback(url, localChecks) {
  const score = localChecks?.localScore || 0;
  let verdict, threatCategory, analysis;

  if (score >= 65) {
    verdict        = 'Phishing';
    threatCategory = localChecks.typosquatting ? 'Brand Impersonation' : 'Credential Harvesting';
    analysis       = `This URL shows multiple high-risk signals associated with phishing. ${localChecks.hasIP ? 'It uses an IP address instead of a real domain name. ' : ''}${localChecks.typosquatting ? 'The domain appears to impersonate a known brand. ' : ''}Do not visit this URL.`;
  } else if (score >= 30) {
    verdict        = 'Suspicious';
    threatCategory = 'Unknown';
    analysis       = `This URL contains suspicious characteristics. ${!localChecks.hasHTTPS ? 'It lacks HTTPS encryption. ' : ''}Proceed with caution before entering any personal information.`;
  } else {
    verdict        = 'Safe';
    threatCategory = 'None';
    analysis       = `No major phishing indicators detected. ${localChecks.hasHTTPS ? 'The URL uses HTTPS encryption. ' : ''}Always remain cautious online.`;
  }

  const topRisks = [];
  if (!localChecks.hasHTTPS)                  topRisks.push('No HTTPS encryption');
  if (localChecks.hasIP)                       topRisks.push('IP address used as domain');
  if (localChecks.typosquatting)               topRisks.push('Possible brand impersonation');
  if (localChecks.suspiciousKeywords?.length)  topRisks.push('Suspicious keywords detected');
  if (localChecks.manySubdomains)              topRisks.push('Excessive subdomain depth');
  if (localChecks.hasSuspiciousTLD)            topRisks.push('High-risk domain extension');

  return { finalScore: score, verdict, domainAge: 'Unknown', sslStatus: localChecks.hasHTTPS ? 'Present' : 'Missing', threatCategory, analysis, topRisks: topRisks.slice(0,4) };
}

/**
 * Simple toast notification
 */
function showToast(message, type = 'info') {
  const existing = document.getElementById('detectify-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'detectify-toast';
  const bg = type === 'warning' ? '#BA7517' : type === 'error' ? '#E24B4A' : '#185FA5';
  toast.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:9999;
    background:${bg}; color:white; padding:12px 20px;
    border-radius:10px; font-size:14px; font-family:'Space Grotesk',sans-serif;
    box-shadow:0 4px 16px rgba(0,0,0,0.2); animation:slideUp 0.3s ease;
    max-width:320px; line-height:1.5;`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
