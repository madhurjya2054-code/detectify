// ================================
//  app.js — Main Application Logic
// ================================

const HISTORY_KEY = 'detectify_history';
const STATS_KEY   = 'detectify_stats';

// ---- Load from localStorage ----
let scanHistory = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
scanHistory = scanHistory.map(h => ({ ...h, time: new Date(h.time) }));

let stats = JSON.parse(localStorage.getItem(STATS_KEY) || '{"total":0,"threats":0,"safe":0,"suspicious":0}');
let bulkMode = false;

// ---- STATS ----
function updateStats() {
  document.getElementById('m-total').textContent      = stats.total;
  document.getElementById('m-threats').textContent    = stats.threats;
  document.getElementById('m-safe').textContent       = stats.safe;
  document.getElementById('m-suspicious').textContent = stats.suspicious;
  localStorage.setItem(STATS_KEY, JSON.stringify(stats));
}

// ---- BULK TOGGLE ----
function toggleBulk() {
  bulkMode = !bulkMode;
  document.getElementById('bulk-area').style.display = bulkMode ? 'block' : 'none';
  document.getElementById('bulk-label').textContent  = bulkMode
    ? 'Switch to Single URL Scan'
    : 'Switch to Bulk Scan (multiple URLs)';
}

// ---- SINGLE SCAN ----
async function startScan() {
  const url = document.getElementById('url-input').value.trim();
  if (!url) { alert('Please enter a URL to scan.'); return; }
  await scanSingleUrl(url);
}

// ---- BULK SCAN ----
async function startBulkScan() {
  const lines = document.getElementById('bulk-input').value
    .split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) { alert('Please enter at least one URL.'); return; }
  for (const url of lines) await scanSingleUrl(url);
}

// ---- CORE SCAN ----
async function scanSingleUrl(url) {
  const btn = document.getElementById('scan-btn');
  btn.disabled  = true;
  btn.innerHTML = '<i class="ti ti-loader-2" style="animation:spin 1s linear infinite"></i> Scanning...';

  const container = document.getElementById('results-container');
  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div class="result-header">
      <div class="result-url"><i class="ti ti-link"></i> ${url}</div>
      <div class="risk-badge risk-suspicious">Analyzing...</div>
    </div>
    <div class="scanning-status">
      <div class="loading-dots"><span></span><span></span><span></span></div>
      <span>Running AI + pattern analysis + WHOIS lookup...</span>
    </div>`;
  container.insertBefore(card, container.firstChild);

  try {
    const localChecks = runLocalChecks(url);
    const aiResult    = await callClaudeAPI(url, localChecks);
    renderResult(card, url, localChecks, aiResult);
  } catch (error) {
    card.innerHTML = `<div class="scan-error"><i class="ti ti-alert-circle"></i> Error: ${error.message || 'Please try again.'}</div>`;
  }

  btn.disabled  = false;
  btn.innerHTML = '<i class="ti ti-radar"></i> Scan URL';
}

// ---- RENDER RESULT ----
function renderResult(card, url, local, ai) {
  const risk = getRiskLevel(ai.finalScore);
  const now  = new Date();

  // Save to history (localStorage)
  const entry = { url, score: ai.finalScore, verdict: ai.verdict, time: now.toISOString() };
  scanHistory.unshift({ ...entry, time: now });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(scanHistory.slice(0, 50).map(h => ({ ...h, time: h.time.toISOString ? h.time.toISOString() : h.time }))));
  renderHistory();

  // Update stats
  stats.total++;
  if      (ai.finalScore >= 65) stats.threats++;
  else if (ai.finalScore >= 30) stats.suspicious++;
  else                          stats.safe++;
  updateStats();

  const riskTagsHTML = (ai.topRisks && ai.topRisks.length > 0)
    ? `<div class="risk-tags">${ai.topRisks.map(r => `<span class="risk-tag">${r}</span>`).join('')}</div>`
    : '';

  const whoisHTML = renderWHOIS(url);

  card.innerHTML = `
    <div class="result-header">
      <div class="result-url"><i class="ti ti-link"></i> ${url}</div>
      <div class="risk-badge ${risk.cssClass}">${risk.label}</div>
    </div>

    <!-- RISK GAUGE -->
    <div class="gauge-section">
      <div class="gauge-label">
        <span>Risk Score</span>
        <span style="font-weight:700;color:${risk.color};">${ai.finalScore} / 100</span>
      </div>
      <div class="gauge-track">
        <div class="gauge-fill" style="width:0%;background:${risk.color};transition:width 1.2s ease;" data-target="${ai.finalScore}"></div>
      </div>
      <div class="gauge-markers">
        <span style="color:#639922;">Safe (0–29)</span>
        <span style="color:#BA7517;">Suspicious (30–64)</span>
        <span style="color:#E24B4A;">Phishing (65+)</span>
      </div>
    </div>

    <!-- CHECKS GRID -->
    <div class="checks-grid">
      <div class="check-item">
        <i class="ti ${local.hasHTTPS ? 'ti-lock' : 'ti-lock-open'} check-icon" style="color:${local.hasHTTPS ? '#639922' : '#E24B4A'}"></i>
        <div><div class="check-val">SSL / HTTPS</div><div class="check-label">${ai.sslStatus}</div></div>
      </div>
      <div class="check-item">
        <i class="ti ti-calendar check-icon" style="color:${ai.domainAge.toLowerCase().includes('new') ? '#E24B4A' : '#639922'}"></i>
        <div><div class="check-val">Domain Age</div><div class="check-label">${ai.domainAge}</div></div>
      </div>
      <div class="check-item">
        <i class="ti ${local.typosquatting ? 'ti-alert-triangle' : 'ti-check'} check-icon" style="color:${local.typosquatting ? '#E24B4A' : '#639922'}"></i>
        <div><div class="check-val">Typosquatting</div><div class="check-label">${local.typosquatting ? 'Detected — brand impersonation' : 'Not detected'}</div></div>
      </div>
      <div class="check-item">
        <i class="ti ti-tag check-icon" style="color:${ai.threatCategory === 'None' ? '#639922' : '#E24B4A'}"></i>
        <div><div class="check-val">Threat Category</div><div class="check-label">${ai.threatCategory}</div></div>
      </div>
      <div class="check-item">
        <i class="ti ${local.hasIP ? 'ti-alert-circle' : 'ti-check'} check-icon" style="color:${local.hasIP ? '#E24B4A' : '#639922'}"></i>
        <div><div class="check-val">IP-Based URL</div><div class="check-label">${local.hasIP ? 'Yes — high risk signal' : 'No — domain used'}</div></div>
      </div>
      <div class="check-item">
        <i class="ti ${local.suspiciousKeywords.length > 0 ? 'ti-eye-exclamation' : 'ti-check'} check-icon" style="color:${local.suspiciousKeywords.length > 0 ? '#BA7517' : '#639922'}"></i>
        <div><div class="check-val">Suspicious Keywords</div><div class="check-label">${local.suspiciousKeywords.length > 0 ? local.suspiciousKeywords.slice(0,3).join(', ') : 'None found'}</div></div>
      </div>
    </div>

    ${riskTagsHTML}

    <!-- WHOIS -->
    ${whoisHTML}

    <!-- AI ANALYSIS -->
    <div class="ai-analysis">
      <div class="ai-analysis-label"><i class="ti ti-brain"></i> AI Analysis</div>
      ${ai.analysis}
    </div>

    <!-- ACTIONS -->
    <div class="result-actions">
      <button class="report-btn" onclick='downloadReport(
        ${JSON.stringify(url)},
        ${ai.finalScore},
        ${JSON.stringify(ai.verdict)},
        ${JSON.stringify(ai.threatCategory)},
        ${JSON.stringify(ai.analysis)},
        ${JSON.stringify(ai.topRisks || [])}
      )'>
        <i class="ti ti-download"></i> Download Report
      </button>
      <button class="share-btn" onclick="copyResult('${url}', ${ai.finalScore}, '${ai.verdict}')">
        <i class="ti ti-copy"></i> Copy Result
      </button>
    </div>`;

  // Animate gauge
  requestAnimationFrame(() => {
    const fill = card.querySelector('.gauge-fill');
    if (fill) fill.style.width = fill.dataset.target + '%';
  });
}

// ---- COPY RESULT ----
function copyResult(url, score, verdict) {
  const text = `Detectify Scan Result\nURL: ${url}\nVerdict: ${verdict}\nRisk Score: ${score}/100\nScanned: ${new Date().toLocaleString()}`;
  navigator.clipboard.writeText(text).then(() => {
    alert('Result copied to clipboard!');
  });
}

// ---- HISTORY ----
function renderHistory() {
  const list = document.getElementById('history-list');
  if (!list) return;
  if (scanHistory.length === 0) {
    list.innerHTML = `<div class="empty-state"><i class="ti ti-history"></i><p>No scans yet.</p></div>`;
    return;
  }
  list.innerHTML = scanHistory.slice(0, 20).map(h => {
    const risk    = getRiskLevel(h.score);
    const time    = new Date(h.time);
    const timeStr = time.toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
    const icon    = h.score < 30 ? 'ti-shield-check' : h.score < 65 ? 'ti-shield-exclamation' : 'ti-shield-x';
    return `
      <div class="history-item">
        <i class="ti ${icon}" style="color:${risk.color};font-size:20px;"></i>
        <div class="history-url">${h.url}</div>
        <div class="history-badge ${risk.cssClass}">${h.verdict}</div>
        <div class="history-score" style="color:${risk.color};">${h.score}/100</div>
        <div class="history-time">${timeStr}</div>
      </div>`;
  }).join('');
}

function clearHistory() {
  if (confirm('Clear all scan history?')) {
    scanHistory = [];
    stats = { total: 0, threats: 0, safe: 0, suspicious: 0 };
    localStorage.removeItem(HISTORY_KEY);
    localStorage.removeItem(STATS_KEY);
    renderHistory();
    updateStats();
  }
}

// ---- INIT ----
document.addEventListener('DOMContentLoaded', () => {
  updateStats();
  renderHistory();
  const input = document.getElementById('url-input');
  if (input) input.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
});

// CSS for spin animation
const style = document.createElement('style');
style.textContent = `@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`;
document.head.appendChild(style);
