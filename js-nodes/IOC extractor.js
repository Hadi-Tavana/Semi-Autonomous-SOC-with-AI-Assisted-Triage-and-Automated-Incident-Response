const globalSet = new Set();
const results = [];

// ---- VALIDATORS ----

function isValidHash(h) {
  return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(h);
}

function isValidIP(ip) {
  if (!ip) return false;
  const parts = ip.split('.');
  return parts.length === 4 && parts.every(p => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function isLikelyDomain(d) {
  if (!d) return false;

  const lower = d.toLowerCase();

  // ❌ Reject filenames / code artifacts
  if (
    lower.endsWith('.exe') ||
    lower.endsWith('.dll') ||
    lower.endsWith('.ps1') ||
    lower.endsWith('.bat') ||
    lower.endsWith('.go') ||
    lower.includes('system.') ||
    lower.includes('wc.') ||
    lower.includes('headers')
  ) return false;

  // Must have at least one dot
  if (!d.includes('.')) return false;

  // Basic domain pattern
  return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(d);
}

function extractIPs(text) {
  if (!text) return [];
  return text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
}

function extractDomains(text) {
  if (!text) return [];
  return text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
}

// ---- PROCESS ----

for (const item of items) {
  const alert = item.json.alert || item.json;
  const alert_id = item.json.alert_id;

  const add = (type, value) => {
    const key = `${type}:${value}`;
    if (!globalSet.has(key)) {
      globalSet.add(key);
      results.push({
        json: {
          alert_id,
          type,
          value
        }
      });
    }
  };

  // ---- HASHES ----
  (alert.hashes || []).forEach(h => {
    if (isValidHash(h)) add("hash", h);
  });

  // ---- IPs ----
  [alert.src_ip, alert.dst_ip].forEach(ip => {
    if (isValidIP(ip)) add("ip", ip);
  });

  // ---- DOMAIN FIELD ----
  if (isLikelyDomain(alert.domain)) {
    add("domain", alert.domain);
  }

  // ---- COMMAND LINES ----
  (alert.command_lines || []).forEach(cmd => {
    extractIPs(cmd).forEach(ip => {
      if (isValidIP(ip)) add("ip", ip);
    });

    extractDomains(cmd).forEach(d => {
      if (isLikelyDomain(d)) add("domain", d);
    });
  });

  // ---- URLS ----
  (alert.urls || []).forEach(url => {
    extractIPs(url).forEach(ip => {
      if (isValidIP(ip)) add("ip", ip);
    });

    extractDomains(url).forEach(d => {
      if (isLikelyDomain(d)) add("domain", d);
    });
  });
}

return results;
