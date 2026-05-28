// ================================
//  whois.js — WHOIS Simulation
// ================================

/**
 * Simulates a WHOIS lookup based on URL patterns.
 * Returns realistic domain registration data.
 */
function simulateWHOIS(url) {
  const lower  = url.toLowerCase();
  const domain = (lower.split('/')[2] || '').replace('www.', '');

  // Known safe/established domains
  const established = ['google.com','github.com','wikipedia.org','microsoft.com','apple.com',
    'amazon.com','facebook.com','instagram.com','twitter.com','youtube.com','linkedin.com',
    'stackoverflow.com','reddit.com','netflix.com','paypal.com','ebay.com'];

  const isEstablished = established.some(d => domain.includes(d));

  // Suspicious signals
  const isSuspicious = domain.includes('login') || domain.includes('verify') ||
    domain.includes('secure') || domain.includes('paypa1') || domain.includes('amaz0n') ||
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain) ||
    ['.xyz','.tk','.ml','.ga','.cf','.gq','.top'].some(t => domain.includes(t));

  let registrar, created, expires, country, status, age;

  if (isEstablished) {
    const years = Math.floor(Math.random() * 15) + 10;
    const d = new Date();
    d.setFullYear(d.getFullYear() - years);
    created  = d.toISOString().split('T')[0];
    expires  = new Date(Date.now() + 365*24*60*60*1000*2).toISOString().split('T')[0];
    registrar = ['GoDaddy LLC', 'MarkMonitor Inc.', 'CSC Corporate Domains'][Math.floor(Math.random()*3)];
    country  = 'United States';
    status   = 'clientTransferProhibited';
    age      = `${years} years`;
  } else if (isSuspicious) {
    const days = Math.floor(Math.random() * 60) + 1;
    const d = new Date();
    d.setDate(d.getDate() - days);
    created  = d.toISOString().split('T')[0];
    expires  = new Date(Date.now() + 365*24*60*60*1000).toISOString().split('T')[0];
    registrar = ['Namecheap Inc.', 'PDR Ltd.', 'PublicDomainRegistry.com'][Math.floor(Math.random()*3)];
    country  = ['Russia','China','Unknown','Panama'][Math.floor(Math.random()*4)];
    status   = 'ok';
    age      = `${days} days — ⚠️ Very new`;
  } else {
    const months = Math.floor(Math.random() * 36) + 6;
    const d = new Date();
    d.setMonth(d.getMonth() - months);
    created  = d.toISOString().split('T')[0];
    expires  = new Date(Date.now() + 365*24*60*60*1000).toISOString().split('T')[0];
    registrar = ['GoDaddy LLC', 'Namecheap Inc.', 'Google Domains'][Math.floor(Math.random()*3)];
    country  = 'United States';
    status   = 'ok';
    age      = `${months} months`;
  }

  return {
    domain,
    registrar,
    created,
    expires,
    country,
    status,
    age,
    isNew: isSuspicious
  };
}

/**
 * Renders a WHOIS info card inside a result card.
 */
function renderWHOIS(url) {
  const w = simulateWHOIS(url);
  return `
    <div class="whois-card">
      <div class="whois-title"><i class="ti ti-world"></i> WHOIS Domain Info <span class="whois-badge">Simulated</span></div>
      <div class="whois-grid">
        <div class="whois-row"><span class="whois-key">Domain</span><span class="whois-val">${w.domain}</span></div>
        <div class="whois-row"><span class="whois-key">Registrar</span><span class="whois-val">${w.registrar}</span></div>
        <div class="whois-row"><span class="whois-key">Created</span><span class="whois-val" style="color:${w.isNew ? '#E24B4A' : 'inherit'}">${w.created}</span></div>
        <div class="whois-row"><span class="whois-key">Expires</span><span class="whois-val">${w.expires}</span></div>
        <div class="whois-row"><span class="whois-key">Country</span><span class="whois-val">${w.country}</span></div>
        <div class="whois-row"><span class="whois-key">Domain Age</span><span class="whois-val" style="color:${w.isNew ? '#E24B4A' : '#639922'}">${w.age}</span></div>
        <div class="whois-row"><span class="whois-key">Status</span><span class="whois-val">${w.status}</span></div>
      </div>
    </div>`;
}
