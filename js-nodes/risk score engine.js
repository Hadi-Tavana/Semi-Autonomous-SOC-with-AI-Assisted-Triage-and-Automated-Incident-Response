// === CONFIG ===
const TRUSTED_DOMAINS = [
  "windowsupdate.com",
  "microsoft.com",
  "azureedge.net"
];

// === HELPERS ===
function isTrustedDomain(domain) {
  if (!domain) return false;
  return TRUSTED_DOMAINS.some(d => domain.includes(d));
}

function isWindowsUpdate(alert) {
  return (
    alert.user_agent?.includes("Microsoft-Delivery-Optimization") ||
    alert.urls?.some(u => u.includes("msdownload")) ||
    isTrustedDomain(alert.domain)
  );
}

function buildFullUrls(alert) {
  if (!alert.urls) return [];
  if (!alert.domain) return alert.urls;

  return alert.urls.map(u => {
    if (u.startsWith("http")) return u;
    return `http://${alert.domain}${u}`;
  });
}

// === GROUPING ===
function getGroupingKey(item) {
  const alert = item.alert || {};
  
  // 1. Use domain if present (Windows Update etc.)
  if (alert.domain) {
    return `domain:${alert.domain}`;
  }
  
  // 2. Use type:value for IP / hash / domain alerts
  if (item.type && item.value) {
    return `${item.type}:${item.value}`;
  }
  
  // 3. Fallback: use alert_id so every generic alert is its own group
  return `alert_id:${item.alert_id || item.alert?.alert_id || Math.random()}`;
}

// === SCORING ===
function scoreItem(item) {
  let score = 0;

  const alert = item.alert && Object.keys(item.alert).length > 1
  ? item.alert
  : item;
  const osint = item.osint_summary || {};

  const title = (alert.title || "").toLowerCase();
  const flow = (alert.asset_flow || "").toLowerCase();
  const role = (alert.src_role || "").toLowerCase();

  const hasOSINT = item.has_osint_targets;

  // =========================
  // 1. OSINT
  // =========================
  if (osint.detection?.malicious > 10) score += 30;
  else if (osint.detection?.malicious > 0) score += 15;

  if (osint.reputation?.abuse_score > 50) score += 15;

  // =========================
  // 2. BEHAVIOR (REDUCED + CONTROLLED)
  // =========================

  // Critical attacks
  if (title.includes("kerberoast") || flow.includes("credential access")) {
    score += 60;
  }

  // Persistence / Priv Esc
  else if (title.includes("admin account creation") || flow.includes("persistence")) {
    score += 50;
  }

  // Discovery
  else if (title.includes("discovery") || flow.includes("discovery")) {
    score += 30;
  }

  // =========================
  // 3. CONTEXT (NO DUPLICATION)
  // =========================
  if (role.includes("domain controller")) {
    score += 25;
  } else if (role.includes("server")) {
    score += 15;
  }

  // Severity
  if (alert.severity >= 5) score += 25;
  else if (alert.severity === 4) score += 15;

  // SOC priority (reduced weight)
  score += (alert.soc_priority || 1) * 5;

  // =========================
  // 4. NO OSINT (FLAT BONUS, NO MULTIPLIER)
  // =========================
  if (!hasOSINT) {
    score += 10;
  }

  // =========================
  // 5. SIGNALS
  // =========================
  if (alert.command_lines?.some(cmd =>
    cmd.toLowerCase().includes("executionpolicy bypass")
  )) score += 20;

  if (alert.process_names?.some(p =>
    p.toLowerCase().includes("printspoofer")
  )) score += 40;

  if (alert.process_names?.some(p =>
    p.toLowerCase().includes("sandcat")
  )) score += 35;

  if (alert.command_lines?.some(cmd =>
    cmd.includes(":8888")
  )) score += 25;

  // =========================
  // 6. CORRELATION
  // =========================
  if (item.occurrences > 2) score += 10;
  if (item.related_alerts?.length > 2) score += 10;

  // =========================
  // 7. BENIGN OVERRIDE (KEEP)
  // =========================
  if (isWindowsUpdate(alert)) {
    score = Math.min(score, 20);
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function verdictFromScore(score) {
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

// === MAIN ===

// 1. Normalize
const normalized = items.map(item => {
  const i = item.json;

  i.alert = i.alert || {};
  i.osint_summary = i.osint_summary || {};

  i.alert.urls = buildFullUrls(i.alert);

  if (isWindowsUpdate(i.alert)) {
    i.alert.alert_type = "benign_update_activity";
    i.alert.playbook = "ignore_or_whitelist";
  }

  if (i.type === "ip" && isTrustedDomain(i.alert.domain)) {
    i.osint_summary.classification = "trusted_vendor";
  }

  return i;
});

// 2. Group
const grouped = {};

for (const item of normalized) {
  const key = getGroupingKey(item);

  if (!grouped[key]) {
    grouped[key] = {
      ...item,
      occurrences: 1,
      related_alerts: [item.alert.alert_id]
    };
  } else {
    grouped[key].occurrences++;
    grouped[key].related_alerts.push(item.alert.alert_id);
  }
}

// 3. Score
for (const key in grouped) {
  const item = grouped[key];

  const score = scoreItem(item);
  item.risk_score = score;
  item.final_verdict = verdictFromScore(score);
}

// 4. Noise suppression
// === NOISE SUPPRESSION (improved) ===
const NOISE_SUPPRESSION_THRESHOLD = 1;        // ← you can change this
const MIN_SOC_PRIORITY_TO_KEEP = 3;       // keep everything >=4 even if LOW

// === FINAL FILTER ===
const result = Object.values(grouped).filter(i => {
  const verdict = i.final_verdict;
  const occurrences = i.occurrences || 1;
  const socPriority = i.alert?.soc_priority || i.soc_priority || 4;

  // Keep HIGH and MEDIUM no matter what
  if (verdict === "HIGH" || verdict === "MEDIUM") {
    return true;
  }

  // NEVER drop high-priority alerts (Kerberoasting = 5, local admin = 4, etc.)
  if (socPriority >= MIN_SOC_PRIORITY_TO_KEEP) {
    return true;
  }

  // Only suppress true noise: LOW risk + very rare
  return !(verdict === "LOW" && occurrences <= NOISE_SUPPRESSION_THRESHOLD);
});

// 5. Output
return result.map(i => ({ json: i }));
