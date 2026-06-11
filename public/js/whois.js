// ================================
//  whois.js — Real WHOIS Lookup
// ================================

async function fetchWHOIS(url) {
  try {
    const domain = (url.toLowerCase().split('/')[2] || '').replace('www.', '');
    const res = await fetch('/api/whois?domain=' + encodeURIComponent(domain));
    if (!res.ok) throw new Error('WHOIS failed');
    return await res.json();
  } catch (err) {
    console.warn('WHOIS lookup failed:', err.message);
    return null;
  }
}

async function renderWHOIS(url) {
  const w = await fetchWHOIS(url);
  if (!w) return '<div class="whois-card"><div class="whois-title"><i class="ti ti-world"></i> WHOIS Domain Info</div><p style="padding:1rem;color:var(--text-muted)">WHOIS data unavailable</p></div>';
  
  const badge = w.simulated ? '<span class="whois-badge">Simulated</span>' : '<span class="whois-badge" style="background:var(--green-dim);color:var(--green)">Live</span>';
  const createdColor = w.isNew ? '#E24B4A' : 'inherit';
  const ageColor = w.isNew ? '#E24B4A' : '#639922';

  return `
    <div class="whois-card">
      <div class="whois-title"><i class="ti ti-world"></i> WHOIS Domain Info ${badge}</div>
      <div class="whois-grid">
        <div class="whois-row"><span class="whois-key">Domain</span><span class="whois-val">${w.domain}</span></div>
        <div class="whois-row"><span class="whois-key">Registrar</span><span class="whois-val">${w.registrar}</span></div>
        <div class="whois-row"><span class="whois-key">Created</span><span class="whois-val" style="color:${createdColor}">${w.created}</span></div>
        <div class="whois-row"><span class="whois-key">Expires</span><span class="whois-val">${w.expires}</span></div>
        <div class="whois-row"><span class="whois-key">Country</span><span class="whois-val">${w.country}</span></div>
        <div class="whois-row"><span class="whois-key">Domain Age</span><span class="whois-val" style="color:${ageColor}">${w.age}</span></div>
        <div class="whois-row"><span class="whois-key">Status</span><span class="whois-val">${w.status}</span></div>
      </div>
    </div>`;
}
