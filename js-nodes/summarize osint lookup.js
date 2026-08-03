// === OSINT Summarizer (Compact, No Bloat, No Drops) ===

return items.map(item => {
  const data = item.json;

  // -----------------------------
  // Normalize alert
  // -----------------------------
  const alert = (data.alert && Object.keys(data.alert).length > 1)
    ? data.alert
    : data;

  const lookup = data.lookup_result || data.lookup_results || {};
  const type = data.type || "unknown";
  const value = data.value || null;

  const hasLookup = Object.keys(lookup).length > 0;

  // -----------------------------
  // Helpers
  // -----------------------------
  const safe = (v, def = null) =>
    v === undefined || v === null ? def : v;

  // -----------------------------
  // 🔥 TRIM LOOKUP (CRITICAL)
  // -----------------------------
  function trimLookup() {
    const trimmed = {};

    if (lookup.shodan) {
      trimmed.shodan = {
        isp: lookup.shodan.isp,
        org: lookup.shodan.org,
        ports: (lookup.shodan.ports || []).slice(0, 10)
      };
    }

    if (lookup.abuseipdb) {
      trimmed.abuseipdb = {
        score: lookup.abuseipdb.score,
        country: lookup.abuseipdb.country,
        usage_type: lookup.abuseipdb.usage_type
      };
    }

    if (lookup.virustotal?.raw?.data?.attributes) {
      const attr = lookup.virustotal.raw.data.attributes;

      trimmed.virustotal = {
        reputation: attr.reputation,
        malicious: safe(attr.last_analysis_stats?.malicious, 0),
        suspicious: safe(attr.last_analysis_stats?.suspicious, 0),
        tags: (attr.tags || []).slice(0, 5),
        last_analysis: attr.last_analysis_date
      };
    }

    return trimmed;
  }

  // -----------------------------
  // IP Summary
  // -----------------------------
  function summarizeIP() {
    const shodan = lookup.shodan || {};
    const abuse = lookup.abuseipdb || {};

    let classification = "unknown";

    if ((shodan.isp || "").toLowerCase().includes("cloudflare")) {
      classification = "trusted_cdn";
    } else if ((abuse.score || 0) > 50) {
      classification = "likely_malicious";
    } else if ((abuse.score || 0) > 0) {
      classification = "suspicious";
    }

    return {
      indicator: value,
      type: "ip",
      classification,
      abuse_score: safe(abuse.score, 0),
      isp: safe(shodan.isp),
      country: safe(abuse.country),
      confidence: hasLookup ? 1 : 0
    };
  }

  // -----------------------------
  // Domain Summary
  // -----------------------------
  function summarizeDomain() {
    const vt = lookup.virustotal || {};
    const attr = vt?.raw?.data?.attributes || {};

    const malicious = safe(attr.last_analysis_stats?.malicious, 0);

    let classification = "unknown";

    if (malicious > 5) classification = "malicious";
    else if (malicious > 0) classification = "suspicious";

    return {
      indicator: value,
      type: "domain",
      classification,
      malicious,
      reputation: safe(attr.reputation, 0),
      confidence: vt?.raw?.data ? 1 : 0
    };
  }

  // -----------------------------
  // Hash Summary
  // -----------------------------
  function summarizeHash() {
    const vt = lookup.virustotal || {};
    const attr = vt?.raw?.data?.attributes || {};

    const malicious = safe(attr.last_analysis_stats?.malicious, 0);

    let classification = "clean";
    if (malicious > 10) classification = "malicious";
    else if (malicious > 0) classification = "suspicious";

    return {
      indicator: value,
      type: "hash",
      classification,
      malicious,
      file_type: attr.type_description,
      confidence: vt?.raw?.data ? 1 : 0
    };
  }

  // -----------------------------
  // URL Summary (for Nmap alerts)
  // -----------------------------
  function summarizeURL() {
    const u = (value || "").toLowerCase();

    let classification = "unknown";

    if (u.includes("hnap") || u.includes("sdk")) {
      classification = "scan_probe";
    } else if (u.includes("login") || u.includes("admin")) {
      classification = "sensitive_endpoint";
    }

    return {
      indicator: value,
      type: "url",
      classification,
      confidence: 0.5
    };
  }

  // -----------------------------
  // Dispatcher
  // -----------------------------
  let osint_summary;

  if (!hasLookup) {
    osint_summary = {
      indicator: value,
      type,
      classification: "no_enrichment",
      confidence: 0
    };
  } else if (type === "ip") {
    osint_summary = summarizeIP();
  } else if (type === "domain") {
    osint_summary = summarizeDomain();
  } else if (type === "hash") {
    osint_summary = summarizeHash();
  } else if (type === "url") {
    osint_summary = summarizeURL();
  } else {
    osint_summary = {
      indicator: value,
      type,
      classification: "unsupported",
      confidence: 0
    };
  }

  // -----------------------------
  // FINAL OUTPUT (CLEAN)
  // -----------------------------
  return {
    json: {
      alert_id: alert.alert_id,
      alert,
      type,
      value,

      osint_summary,
      enrichment_confidence: osint_summary.confidence,

      // 🔥 trimmed instead of full raw dump
      lookup_summary: trimLookup()
    }
  };
});
